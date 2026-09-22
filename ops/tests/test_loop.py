"""End-to-end test of the responder loop against mock telemetry + mock model.

This exercises ``respond()`` for real: evidence collection over HTTP, model
invocation over the OpenAI-compatible transport, the policy gate, the bounded
executor (dry-run), and recovery verification. The only fakes are the three
signal stores and the model -- the responder code path is the production one.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from ops import incidents, responder  # noqa: E402


class _Json(BaseHTTPRequestHandler):
    routes = {}

    def do_GET(self) -> None:  # noqa: N802
        payload = self.routes.get(self.path.split("?")[0], {})
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:
        return


@pytest.fixture()
def mock_stack(monkeypatch, tmp_path):
    prom_queries = {
        "/api/v1/query": {
            "data": {
                "result": [
                    {"metric": {"route": "/api/v1/tasks/claim", "release": "bad-1"}, "value": [0, "4.0"]},
                    {"metric": {"route": "/api/v1/tasks/claim", "release": "good-1"}, "value": [0, "0"]},
                ]
            }
        }
    }
    _Json.routes = {
        **prom_queries,
        "/loki/api/v1/query_range": {
            "data": {
                "result": [
                    {
                        "stream": {"severity_text": "ERROR"},
                        "values": [["1", '{"severity_text":"ERROR","body":"Exception in ASGI application"}']],
                    }
                ]
            }
        },
        "/api/search": {"traces": [{"traceID": "abc", "rootTraceName": "POST /api/v1/tasks/claim", "durationMs": 7}]},
    }

    prom = HTTPServer(("127.0.0.1", 0), _Json)
    loki = HTTPServer(("127.0.0.1", 0), _Json)
    tempo = HTTPServer(("127.0.0.1", 0), _Json)
    for server in (prom, loki, tempo):
        threading.Thread(target=server.serve_forever, daemon=True).start()

    from ops.tools.mock_model import Handler as ModelHandler

    model = HTTPServer(("127.0.0.1", 0), ModelHandler)
    threading.Thread(target=model.serve_forever, daemon=True).start()

    monkeypatch.setenv("PROMETHEUS_URL", f"http://127.0.0.1:{prom.server_port}")
    monkeypatch.setenv("LOKI_URL", f"http://127.0.0.1:{loki.server_port}")
    monkeypatch.setenv("TEMPO_URL", f"http://127.0.0.1:{tempo.server_port}")
    monkeypatch.setenv("INCIDENT_STORE", str(tmp_path / "inc.db"))
    monkeypatch.setenv("RESPONDER_PROVIDER", "http")
    monkeypatch.setenv("RESPONDER_API_BASE", f"http://127.0.0.1:{model.server_port}")
    monkeypatch.setenv("RESPONDER_API_KEY", "test")
    monkeypatch.setenv("RESPONDER_MODEL", "mock")

    import importlib

    importlib.reload(incidents)
    importlib.reload(responder)
    yield
    for server in (prom, loki, tempo, model):
        server.shutdown()


def test_full_loop_rolls_back_and_ignores_model_command(mock_stack, monkeypatch, tmp_path):
    monkeypatch.setenv("ESCALATION_DIR", str(tmp_path / "esc"))
    alert = {
        "status": "firing",
        "labels": {
            "alertname": "AgentRelayHighErrorRate",
            "severity": "critical",
            "service": "agent-relay",
            "release": "bad-1",
            "route": "/api/v1/tasks/claim",
        },
        "annotations": {"summary": "5xx", "impact": "users affected"},
    }
    incident = incidents.open_from_alert(alert)

    # The evidence collector must observe a healthy previous release.
    result = responder.respond(incident["id"], dry_run=True)

    assert result["policy"]["outcome"] == "authorized"
    assert result["policy"]["model_command_suggestion"] == "kubectl delete namespace kube-system"
    assert result["policy"]["executed_command"].startswith("kubectl -n agent-relay rollout undo")
    assert "delete" not in result["policy"]["executed_command"]
    # dry_run means the executor reports the command without running it.
    assert result["execution"]["dry_run"] is True
    assert result["execution"]["executed"] is False

    stored = incidents.get(incident["id"])
    assert stored["proposal"]["action"] == "rollback_deployment"
    assert stored["policy"]["outcome"] == "authorized"
    assert stored["evidence"]["summary"]["previous_release"] == "good-1"
    trail = incidents.audit_trail(incident["id"])
    assert any(entry["action"] == "decision" for entry in trail)


def test_loop_escalates_when_previous_release_also_fails(mock_stack, monkeypatch, tmp_path):
    """If the previous release is failing too, a rollback is not authorized."""

    import ops.evidence as evidence_module

    original = evidence_module._summarize

    def summarize(packet, release):
        summary = original(packet, release)
        summary["impacted_routes"].append({"route": "/api/v1/tasks/claim", "release": "good-1"})
        summary["previous_release"] = "good-1"
        return summary

    monkeypatch.setattr(evidence_module, "_summarize", summarize)

    alert = {
        "status": "firing",
        "labels": {"alertname": "AgentRelayHighErrorRate", "severity": "critical", "service": "agent-relay",
                   "release": "bad-1", "route": "/api/v1/tasks/claim"},
        "annotations": {"summary": "5xx", "impact": "users affected"},
    }
    incident = incidents.open_from_alert(alert)
    monkeypatch.setenv("ESCALATION_DIR", str(tmp_path / "esc"))
    result = responder.respond(incident["id"], dry_run=True)
    assert result["policy"]["outcome"] == "escalate"
    assert result["escalation"]["escalated"] is True


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
