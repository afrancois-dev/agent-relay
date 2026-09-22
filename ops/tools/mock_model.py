"""Deterministic mock model for testing the responder loop without a real LLM.

Speaks the OpenAI-compatible chat-completions shape on purpose: it exercises the
exact transport the responder uses in ``RESPONDER_PROVIDER=http`` mode, so the
test is a real integration test of the loop, not a stub of it.

It returns a proposal derived from the prompt: if the evidence mentions a bad
release plus a healthy previous release, it proposes a rollback. It also returns
a deliberately dangerous ``command`` field, so the tests can prove that policy
ignores the model's command suggestion.
"""

from __future__ import annotations

import argparse
import json
import re
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("content-length") or 0)
        body = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        prompt = body.get("messages", [{}])[-1].get("content", "")
        incident, previous, bad = _read_evidence(prompt)
        if previous and bad and previous != bad:
            proposal = {
                "incident_id": incident,
                "root_cause": f"Release {bad} introduced an unhandled error; {previous} is healthy.",
                "confidence": 0.82,
                "evidence_refs": ["error_ratio", "error_logs", "slow_traces"],
                "action": "rollback_deployment",
                "rollback_release": previous,
                "rollback_revision": None,
                "command": "kubectl delete namespace kube-system",
                "rationale": "The error rate rose with the new release and the previous release is clean.",
            }
        else:
            proposal = {
                "incident_id": incident,
                "root_cause": "Not enough evidence to attribute a cause.",
                "confidence": 0.2,
                "evidence_refs": ["error_ratio"],
                "action": "observe",
                "rationale": "No healthy previous release is evidenced; keep observing.",
            }
        content = json.dumps(proposal)
        response = {
            "id": "mock",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
        }
        payload = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        return


def _extract(text: str, pattern: str) -> str | None:
    match = re.search(pattern, text)
    return match.group(1) if match else None


def _read_evidence(prompt: str) -> tuple[str, str | None, str | None]:
    """Pull the incident id and release pair out of the embedded packet JSON."""

    incident = _extract(prompt, r'"incident_id":\s*"([^"]+)"') or "INC-unknown"
    previous = _extract(prompt, r'"previous_release":\s*"([^"]+)"') if '"previous_release": null' not in prompt else None
    summary_match = re.search(r'"summary":\s*\{(.*?)\n\s*\}', prompt, re.DOTALL)
    bad = None
    if summary_match:
        bad = _extract(summary_match.group(1), r'"release":\s*"([^"]+)"')
    return incident, previous, bad


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8098)
    args = parser.parse_args()
    HTTPServer(("0.0.0.0", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
