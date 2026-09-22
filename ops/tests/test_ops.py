"""Unit tests for the responder side: policy, schema, executor, evidence."""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from ops import evidence, incidents, policy, responder  # noqa: E402


HEALTHY_PACKET = {
    "summary": {
        "impacted_routes": [{"route": "/api/v1/tasks", "release": "bad", "errors_per_second": "5"}],
        "failing_releases": [{"release": "bad", "series": "3"}],
        "previous_release": "good",
    },
    "queries": [{"name": "error_ratio", "query": "q", "result": []}],
}


def test_unknown_action_is_denied():
    decision = policy.decide({"action": "drop_database"}, HEALTHY_PACKET, {})
    assert decision["outcome"] == "denied"
    assert decision["executed_command"] is None


def test_model_command_is_never_executed():
    proposal = {
        "action": "rollback_deployment",
        "rollback_revision": 3,
        "command": "kubectl delete namespace kube-system",
        "rationale": "trust me",
    }
    decision = policy.decide(proposal, HEALTHY_PACKET, {"namespace": "agent-relay", "deployment": "agent-relay"})
    assert decision["outcome"] == "authorized"
    assert decision["model_command_suggestion"] == "kubectl delete namespace kube-system"
    assert decision["executed_command"] == (
        "kubectl -n agent-relay rollout undo deployment/agent-relay --to-revision=3"
    )
    assert "delete" not in decision["executed_command"]


def test_manual_tier_escalates():
    decision = policy.decide({"action": "restart_deployment"}, HEALTHY_PACKET, {})
    assert decision["outcome"] == "escalate"
    assert decision["executed_command"] is None


def test_rollback_requires_healthy_previous_release():
    packet = {"summary": {"impacted_routes": [], "previous_release": None}}
    decision = policy.decide({"action": "rollback_deployment"}, packet, {})
    assert decision["outcome"] == "escalate"


def test_executor_refuses_non_allowlisted_commands():
    assert responder.execute("rm -rf /")["executed"] is False
    assert responder.execute("kubectl delete namespace kube-system")["executed"] is False
    assert responder.execute(None)["executed"] is False


def test_proposal_schema_validation():
    valid = {
        "incident_id": "INC-1",
        "root_cause": "bad image",
        "confidence": 0.9,
        "evidence_refs": ["error_ratio"],
        "action": "rollback_deployment",
        "rationale": "errors started with the deploy",
    }
    assert responder.validate_proposal(valid) == []
    assert responder.validate_proposal({**valid, "confidence": 7})
    assert responder.validate_proposal({**valid, "action": "exfiltrate"})
    assert responder.validate_proposal({**valid, "unexpected": 1})


def test_parse_proposal_extracts_json():
    text = 'Here you go:\n```json\n{"incident_id":"INC-1","action":"observe"}\n```\ntrailing'
    assert responder.parse_proposal(text)["action"] == "observe"


def test_evidence_catalog_is_read_only_and_bounded():
    catalog = evidence.catalog()
    assert catalog, "catalog must not be empty"
    for item in catalog:
        assert item["source"] in {"prometheus", "loki", "tempo"}
        lowered = item["query"].lower()
        assert "delete" not in lowered and "insert" not in lowered and "update" not in lowered


def test_incident_store_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("INCIDENT_STORE", str(tmp_path / "incidents.db"))
    import importlib

    importlib.reload(incidents)
    alert = {
        "status": "firing",
        "labels": {"alertname": "AgentRelayHighErrorRate", "severity": "critical", "service": "agent-relay",
                   "release": "bad", "route": "/api/v1/tasks"},
        "annotations": {"summary": "500s", "impact": "users affected"},
    }
    incident = incidents.open_from_alert(alert)
    assert incident["id"].startswith("INC-")
    again = incidents.open_from_alert(alert)
    assert again["id"] == incident["id"], "repeat alerts must not open duplicates"
    incidents.update(incident["id"], status="resolved")
    assert incidents.get(incident["id"])["status"] == "resolved"
    assert incidents.audit_trail(incident["id"])
    importlib.reload(incidents)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
