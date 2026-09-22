"""Incident desk HTTP service.

Small, dependency-free supervisor around the ops package:

* ``POST /alerts``            -- Alertmanager webhook; opens an incident.
* ``GET  /incidents``         -- list incidents (report input).
* ``GET  /incidents/<id>``    -- full incident record (evidence, proposal, policy, execution, verification).
* ``GET  /incidents/<id>/evidence`` -- the bounded evidence packet.
* ``GET  /incidents/<id>/report``   -- Markdown reconstruction of the loop.
* ``POST /incidents/<id>/respond``  -- run the responder loop (policy-gated).
* ``GET  /evidence/catalog``  -- the allowlisted read-only query catalog.
* ``GET  /actions``           -- the action allowlist and autonomy tiers.
* ``GET  /healthz``

The desk never exposes a write endpoint for cluster state other than
``/respond``, which only reaches the bounded executor in :mod:`ops.responder`.
"""

from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

from ops import evidence, incidents, policy, responder


PORT = int(os.getenv("INCIDENT_DESK_PORT", "8099"))


def _render_report(incident: dict) -> str:
    proposal = incident.get("proposal") or {}
    decision = incident.get("policy") or {}
    execution = incident.get("execution") or {}
    verification = incident.get("verification") or {}
    packet = incident.get("evidence") or {}
    lines = [
        f"# Incident {incident['id']}",
        "",
        f"- **Status:** {incident.get('status')}",
        f"- **Opened:** {incident.get('created_at')}",
        f"- **Alert:** {incident.get('alertname')} ({incident.get('severity')})",
        f"- **Release:** `{incident.get('release')}`  Route: `{incident.get('route')}`",
        f"- **Summary:** {incident.get('summary')}",
        f"- **User impact:** {incident.get('impact')}",
        "",
        "## Evidence (read-only, allowlisted)",
        f"- Queries run: {', '.join(q['name'] for q in packet.get('queries', []))}",
        f"- Collection errors: {packet.get('errors') or 'none'}",
        f"- Impacted routes: {json.dumps(packet.get('summary', {}).get('impacted_routes', []))}",
        f"- Deploy history: {json.dumps(packet.get('deploy_history', []), default=str)}",
        "",
        "## Model proposal",
        f"- Model: `{proposal.get('run', {}).get('model')}` (sandbox={proposal.get('run', {}).get('sandbox')})",
        f"- Root cause: {proposal.get('root_cause')}",
        f"- Action proposed: `{proposal.get('action')}`",
        f"- Confidence: {proposal.get('confidence')}",
        f"- Model's suggested command (NOT executed): `{decision.get('model_command_suggestion')}`",
        "",
        "## Policy decision",
        f"- Outcome: **{decision.get('outcome')}** ({decision.get('reason')})",
        f"- Executed command: `{decision.get('executed_command')}`",
        f"- Execution result: {json.dumps(execution, default=str)}",
        "",
        "## Recovery verification",
        f"{json.dumps(verification, default=str)}",
        "",
    ]
    if incident.get("escalation"):
        lines += ["## Escalation packet", json.dumps(incident["escalation"], default=str), ""]
    return "\n".join(lines)


class DeskHandler(BaseHTTPRequestHandler):
    server_version = "IncidentDesk/1.0"

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        json.dump({"logger": "incident-desk", "message": fmt % args}, sys.stdout)
        sys.stdout.write("\n")

    def _send(self, status: int, payload) -> None:
        body = json.dumps(payload, default=str).encode("utf-8") if not isinstance(payload, str) else payload.encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json" if not isinstance(payload, str) else "text/markdown")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        length = int(self.headers.get("content-length") or 0)
        if not length:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if path in {"/", "/healthz"}:
            return self._send(200, {"status": "ok"})
        if path == "/incidents":
            return self._send(200, {"items": incidents.list_incidents()})
        if path == "/evidence/catalog":
            return self._send(200, {"queries": evidence.catalog()})
        if path == "/actions":
            return self._send(200, {"actions": policy.allowed_actions(), "autonomy": policy.AUTONOMY})
        parts = path.strip("/").split("/")
        if len(parts) >= 2 and parts[0] == "incidents":
            incident = incidents.get(parts[1])
            if incident is None:
                return self._send(404, {"error": "not found"})
            if len(parts) == 2:
                return self._send(200, incident)
            if parts[2] == "evidence":
                return self._send(200, incident.get("evidence") or {})
            if parts[2] == "report":
                return self._send(200, _render_report(incident))
            if parts[2] == "audit":
                return self._send(200, {"items": incidents.audit_trail(parts[1])})
        return self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0].rstrip("/")
        if path == "/alerts":
            payload = self._body()
            opened = []
            for alert in payload.get("alerts", []):
                if alert.get("status") not in {None, "firing"}:
                    continue
                opened.append(incidents.open_from_alert(alert))
            return self._send(202, {"incidents": [item["id"] for item in opened]})
        parts = path.strip("/").split("/")
        if len(parts) == 3 and parts[0] == "incidents" and parts[2] == "respond":
            body = self._body()
            result = responder.respond(
                parts[1],
                dry_run=bool(body.get("dry_run")),
                proposal=body.get("proposal"),
            )
            return self._send(200, result)
        if len(parts) == 3 and parts[0] == "incidents" and parts[2] == "record":
            # An out-of-process responder (the in-cluster pod, which can read
            # the Kubernetes API and run the bounded command with its own
            # ServiceAccount) posts its result here for durable storage and
            # reporting. The desk validates the shape before persisting.
            body = self._body()
            allowed = {"evidence", "proposal", "policy", "execution", "verification", "escalation", "status"}
            # A null field means "not provided in this push", not "clear the
            # stored value": the record arrives in stages (evidence, then
            # proposal, then execution, then verification).
            fields = {key: value for key, value in body.items() if key in allowed and value is not None}
            updated = incidents.update(parts[1], **fields)
            if updated is None:
                return self._send(404, {"error": "not found"})
            incidents.note(parts[1], "in-cluster-responder", "record_ingested", sorted(fields))
            return self._send(200, updated)
        return self._send(404, {"error": "not found"})


def main() -> None:
    httpd = HTTPServer(("0.0.0.0", PORT), DeskHandler)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
