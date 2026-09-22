"""Headless first-responder agent.

Flow::

    incident -> evidence packet -> headless coding agent proposal
             -> policy gate -> bounded command (or escalation) -> verify

The agent is run in a read-only sandbox with a structured task and must answer
in a JSON schema. The agent's *proposal* is not trusted to execute anything:
:mod:`ops.policy` maps it onto an allowlisted action and renders the command.
Whatever policy does not authorize is escalated, with the packet attached.

The responder holds no cluster-admin credentials. It can run ``kubectl
rollout undo`` in its own namespace and that is the entire blast radius.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Any

from ops import evidence, incidents, policy


class ModelUnavailable(RuntimeError):
    """No model transport could be reached (no agent binary, no API key)."""


# The JSON contract the headless agent must satisfy. Kept explicit so it can be
# embedded verbatim in the prompt and validated after the fact.
PROPOSAL_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["incident_id", "root_cause", "confidence", "evidence_refs", "action", "rationale"],
    "properties": {
        "incident_id": {"type": "string"},
        "root_cause": {"type": "string"},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "evidence_refs": {"type": "array", "items": {"type": "string"}},
        "action": {
            "type": "string",
            "enum": ["rollback_deployment", "escalate", "observe", "restart_deployment", "scale_deployment"],
        },
        "rollback_release": {"type": ["string", "null"]},
        "rollback_revision": {"type": ["integer", "null"]},
        "command": {"type": ["string", "null"]},
        "rationale": {"type": "string"},
    },
}

TASK_TEMPLATE = """Here is the evidence packet for incident {incident_id}.
Compare it with recent changes, find the most likely
root cause, and propose one action.
You have read-only access. Respond in the JSON schema.

The only actions you may propose are: {allowed_actions}

Evidence packet (JSON):
{packet}

Respond with a single JSON object matching this schema and nothing else:
{schema}
"""

MODEL_DEFAULT = os.getenv("RESPONDER_MODEL", "gpt-5-codex")
TIMEOUT_SECONDS = int(os.getenv("RESPONDER_TIMEOUT", "180"))

# The responder is deliberately provider-agnostic. It prefers the headless
# coding agent on PATH (Codex or Claude Code), and falls back to any
# OpenAI-compatible chat endpoint. The evidence/policy/execution loop does not
# change with the provider -- only the transport that turns a prompt into text.
PROVIDER = os.getenv("RESPONDER_PROVIDER", "auto")
API_BASE = os.getenv("RESPONDER_API_BASE", "https://api.openai.com/v1").rstrip("/")
API_KEY = os.getenv("RESPONDER_API_KEY") or os.getenv("OPENAI_API_KEY")


# --------------------------------------------------------------------------- #
# Model invocation
# --------------------------------------------------------------------------- #


def build_prompt(incident: dict[str, Any], packet: dict[str, Any]) -> str:
    return TASK_TEMPLATE.format(
        incident_id=incident.get("id"),
        allowed_actions=json.dumps([action["name"] for action in policy.allowed_actions()]),
        packet=json.dumps(packet, indent=2, default=str),
        schema=json.dumps(PROPOSAL_SCHEMA, indent=2),
    )


def invoke_via_http(prompt: str) -> tuple[str, dict[str, Any]]:
    """Call an OpenAI-compatible chat endpoint. Same contract, no local agent."""

    if not API_KEY:
        raise RuntimeError("RESPONDER_API_KEY is not set and no headless agent is available")
    import urllib.request

    body = json.dumps(
        {
            "model": MODEL_DEFAULT,
            "messages": [
                {"role": "system", "content": "You are the incident first responder. Answer only with JSON."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        f"{API_BASE}/chat/completions",
        data=body,
        method="POST",
        headers={"content-type": "application/json", "authorization": f"Bearer {API_KEY}"},
    )
    started = time.time()
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        payload = json.loads(response.read().decode("utf-8"))
    content = payload["choices"][0]["message"]["content"]
    metadata = {
        "provider": "openai-compatible",
        "model": MODEL_DEFAULT,
        "base": API_BASE,
        "duration_seconds": round(time.time() - started, 2),
        "raw_output": content,
    }
    return content, metadata


def invoke_agent(prompt: str, workspace: str | None = None) -> tuple[str, dict[str, Any]]:
    """Run the headless coding agent and return raw text plus run metadata."""

    if PROVIDER == "http":
        return invoke_via_http(prompt)
    binary = os.getenv("RESPONDER_BIN", "codex")
    resolved = shutil.which(binary)
    if resolved is None:
        if API_KEY:
            return invoke_via_http(prompt)
        raise ModelUnavailable(f"headless agent '{binary}' is not installed and RESPONDER_API_KEY is unset")
    workspace = workspace or tempfile.mkdtemp(prefix="responder-")
    output_path = os.path.join(workspace, "proposal.json")
    command = [
        resolved,
        "exec",
        "--sandbox",
        "read-only",
        "--skip-git-repo-check",
        "--output-last-message",
        output_path,
        "-m",
        MODEL_DEFAULT,
        prompt,
    ]
    started = time.time()
    # The agent gets a deliberately small environment: HOME so it can read its
    # own credentials, PATH to find itself, and no application secrets. The
    # responder's process env (database URLs, tokens, signing keys) is not
    # inherited, so a prompt-injected agent cannot read it.
    agent_env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", workspace),
        "NO_COLOR": "1",
        "OPENAI_API_KEY": os.environ.get("OPENAI_API_KEY", ""),
    }
    if os.getenv("RESPONDER_BIN_ENV_PASSTHROUGH"):
        for name in os.getenv("RESPONDER_BIN_ENV_PASSTHROUGH", "").split(","):
            if name.strip() and name.strip() in os.environ:
                agent_env[name.strip()] = os.environ[name.strip()]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            cwd=workspace,
            timeout=TIMEOUT_SECONDS,
            env=agent_env,
        )
    except subprocess.TimeoutExpired as exc:
        if API_KEY:
            return invoke_via_http(prompt)
        raise RuntimeError(f"headless agent timed out after {TIMEOUT_SECONDS}s") from exc
    if completed.returncode != 0 and API_KEY and not os.path.exists(output_path):
        # The local agent could not run (missing/invalid credentials, offline).
        # Fall back to the HTTP provider rather than losing the loop.
        return invoke_via_http(prompt)
    metadata = {
        "binary": resolved,
        "model": MODEL_DEFAULT,
        "sandbox": "read-only",
        "exit_code": completed.returncode,
        "duration_seconds": round(time.time() - started, 2),
        "stdout_tail": completed.stdout[-2000:],
        "stderr_tail": completed.stderr[-2000:],
        "output_path": output_path,
    }
    if os.path.exists(output_path):
        with open(output_path, encoding="utf-8") as handle:
            metadata["raw_output"] = handle.read()
    return completed.stdout, metadata


# --------------------------------------------------------------------------- #
# Parsing + validation
# --------------------------------------------------------------------------- #


def parse_proposal(raw: str) -> dict[str, Any]:
    """Extract the first JSON object from the agent's output."""

    stripped = raw.strip()
    if stripped.startswith("```"):
        stripped = stripped.strip("`")
        if stripped.lower().startswith("json"):
            stripped = stripped[4:]
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("no JSON object found in agent output")
    return json.loads(stripped[start : end + 1])


def _check_schema(value: Any, schema: dict[str, Any], path: str = "$") -> list[str]:
    """Minimal structural JSON-schema checker (no external dependency)."""

    errors: list[str] = []
    expected_type = schema.get("type")
    if expected_type == "object":
        if not isinstance(value, dict):
            return [f"{path}: expected object"]
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}.{key}: missing required property")
        if schema.get("additionalProperties") is False:
            for key in value:
                if key not in schema.get("properties", {}):
                    errors.append(f"{path}.{key}: additional property not allowed")
        for key, sub in schema.get("properties", {}).items():
            if key in value:
                errors.extend(_check_schema(value[key], sub, f"{path}.{key}"))
    elif expected_type == "array":
        if not isinstance(value, list):
            return [f"{path}: expected array"]
        for index, item in enumerate(value):
            errors.extend(_check_schema(item, schema.get("items", {}), f"{path}[{index}]"))
    elif expected_type == "string":
        if not isinstance(value, str):
            errors.append(f"{path}: expected string")
        elif "enum" in schema and value not in schema["enum"]:
            errors.append(f"{path}: '{value}' not in {schema['enum']}")
    elif expected_type == "number":
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            errors.append(f"{path}: expected number")
        else:
            if "minimum" in schema and value < schema["minimum"]:
                errors.append(f"{path}: below minimum")
            if "maximum" in schema and value > schema["maximum"]:
                errors.append(f"{path}: above maximum")
    elif expected_type == "integer":
        if not isinstance(value, int) or isinstance(value, bool):
            errors.append(f"{path}: expected integer")
    return errors


def validate_proposal(proposal: Any) -> list[str]:
    return _check_schema(proposal, PROPOSAL_SCHEMA)


# --------------------------------------------------------------------------- #
# Bounded executor
# --------------------------------------------------------------------------- #


ALLOWED_KUBECTL_VERBS = ("rollout undo", "rollout restart", "scale deployment")


def execute(command: str | None, *, dry_run: bool = False) -> dict[str, Any]:
    """Run a policy-rendered command. Refuses anything outside the allowlist."""

    if not command:
        return {"executed": False, "reason": "no command authorized"}
    if not any(verb in command for verb in ALLOWED_KUBECTL_VERBS):
        return {"executed": False, "reason": f"command not in executor allowlist: {command}"}
    if command.strip().split()[0] != "kubectl":
        return {"executed": False, "reason": "only kubectl may be executed"}
    if dry_run:
        return {"executed": False, "dry_run": True, "command": command}
    started = time.time()
    completed = subprocess.run(shlex.split(command), capture_output=True, text=True, timeout=120)
    return {
        "executed": True,
        "command": command,
        "exit_code": completed.returncode,
        "stdout": completed.stdout[-4000:],
        "stderr": completed.stderr[-2000:],
        "duration_seconds": round(time.time() - started, 2),
    }


# --------------------------------------------------------------------------- #
# Verification
# --------------------------------------------------------------------------- #


def verify(incident: dict[str, Any], route: str | None = None, minutes: int = 5, attempts: int = 6) -> dict[str, Any]:
    """Re-collect the user-impact signal until it clears or the budget expires."""

    route = route or incident.get("route")
    release = incident.get("release")
    history: list[dict[str, Any]] = []
    for attempt in range(attempts):
        packet = evidence.collect(incident, minutes=minutes)
        impacted = packet.get("summary", {}).get("impacted_routes", [])
        still_failing = [item for item in impacted if route is None or item.get("route") == route]
        history.append(
            {
                "attempt": attempt + 1,
                "impacted_routes": impacted,
                "error_traces": packet.get("summary", {}).get("error_traces"),
                "error_lines": packet.get("summary", {}).get("error_lines"),
            }
        )
        if not still_failing:
            return {
                "recovered": True,
                "checks": history,
                "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            }
        time.sleep(15)
    # The 5-minute window still contains pre-action errors while the action
    # drains; use a short, post-action window to decide whether NEW traffic is
    # still failing. A flat-zero current rate on the incident's release means
    # the bad version is no longer serving the failure.
    current = _current_rate(release)
    if current is not None and current <= 0:
        return {
            "recovered": True,
            "checks": history,
            "note": "the 5m window still held pre-action errors; the current 1m rate is zero",
            "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        }
    return {"recovered": False, "checks": history, "current_rate": current}


def _current_rate(release: str | None) -> float | None:
    """Current 1-minute 5xx rate for a release (post-action signal)."""

    import urllib.request

    selector = f'{{status=~"5..", release="{release}"}}' if release else '{status=~"5.."}'
    query = f"sum(rate(relay_http_requests_total{selector}[1m]))"
    url = f"{evidence.prometheus_url()}/api/v1/query?query={urllib.parse.quote(query)}"
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
        results = payload.get("data", {}).get("result", [])
        if not results:
            return 0.0
        return float(results[0]["value"][1])
    except Exception:  # noqa: BLE001 - verification must not crash the loop
        return None


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


def escalate(incident_id: str, proposal: dict[str, Any], decision: dict[str, Any], packet: dict[str, Any]) -> dict[str, Any]:
    packet_export = os.getenv("ESCALATION_DIR", "/var/lib/incidents/escalations")
    os.makedirs(packet_export, exist_ok=True)
    path = os.path.join(packet_export, f"{incident_id}.json")
    payload = {
        "incident_id": incident_id,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "reason": decision.get("reason"),
        "proposal": proposal,
        "policy_decision": decision,
        "evidence": packet,
        "allowed_actions": policy.allowed_actions(),
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, default=str)
    return {"escalated": True, "path": path}


def import_from_desk(incident_id: str) -> dict[str, Any]:
    """Fetch an incident from the desk and seed the local store with it.

    The in-cluster responder keeps its own store; the desk is the shared record.
    This pulls the alert payload and metadata so the responder can run against
    an incident opened elsewhere.
    """

    import urllib.request

    desk = os.getenv("INCIDENT_DESK_URL", "http://127.0.0.1:8099").rstrip("/")
    with urllib.request.urlopen(f"{desk}/incidents/{incident_id}", timeout=10) as response:
        incident = json.loads(response.read().decode("utf-8"))
    # Merge, don't clobber: a local store may already hold a proposal that the
    # desk has not been sent yet.
    local = incidents.get(incident_id)
    merged = {**(local or {}), **{k: v for k, v in incident.items() if v is not None}}
    with incidents.connect() as connection:
        connection.execute(
            """INSERT OR REPLACE INTO incidents
               (id, created_at, updated_at, status, alertname, severity, service, release, route,
                summary, impact, labels, annotations, payload, evidence, proposal, policy,
                execution, verification, escalation)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                merged["id"],
                merged.get("created_at"),
                merged.get("updated_at"),
                merged.get("status", "open"),
                merged.get("alertname"),
                merged.get("severity"),
                merged.get("service"),
                merged.get("release"),
                merged.get("route"),
                merged.get("summary"),
                merged.get("impact"),
                json.dumps(merged.get("labels") or {}),
                json.dumps(merged.get("annotations") or {}),
                json.dumps(merged.get("payload") or {}),
                json.dumps(merged.get("evidence")) if merged.get("evidence") is not None else None,
                json.dumps(merged.get("proposal")) if merged.get("proposal") is not None else None,
                json.dumps(merged.get("policy")) if merged.get("policy") is not None else None,
                json.dumps(merged.get("execution")) if merged.get("execution") is not None else None,
                json.dumps(merged.get("verification")) if merged.get("verification") is not None else None,
                json.dumps(merged.get("escalation")) if merged.get("escalation") is not None else None,
            ),
        )
    return incidents.get(incident_id) or incident


def emit_to_desk(incident_id: str, result: dict[str, Any]) -> None:
    """POST the responder's result to the desk (used by the in-cluster pod)."""

    import urllib.request

    desk = os.getenv("INCIDENT_DESK_URL", "http://127.0.0.1:8099").rstrip("/")
    # Send the whole persisted record, merged over the in-flight result, so no
    # stage is lost regardless of when the emit happens.
    stored = incidents.get(incident_id) or {}
    merged = {**stored, **result}
    payload = {
        key: merged[key]
        for key in ("evidence", "proposal", "policy", "execution", "verification", "escalation", "status")
        if merged.get(key) is not None
    }
    request = urllib.request.Request(
        f"{desk}/incidents/{incident_id}/record",
        data=json.dumps(payload, default=str).encode("utf-8"),
        method="POST",
        headers={"content-type": "application/json"},
    )
    try:
        urllib.request.urlopen(request, timeout=10)
    except Exception:  # noqa: BLE001 - storage is best-effort; the local record remains authoritative
        pass


def respond(
    incident_id: str,
    *,
    dry_run: bool = False,
    invoke: bool = True,
    proposal: dict[str, Any] | None = None,
    emit: bool = False,
) -> dict[str, Any]:
    """Run the loop for one incident and persist every step to the store."""

    incident = incidents.get(incident_id)
    if incident is None:
        incident = import_from_desk(incident_id)
    if incident is None:
        raise SystemExit(f"incident {incident_id} not found")

    incidents.update(incident_id, status="investigating")
    incidents.note(incident_id, "responder", "evidence_collection_started", {"read_only": True})

    packet = evidence.collect(incident)
    incidents.update(incident_id, evidence=packet)
    incidents.note(incident_id, "responder", "evidence_collected", {"queries": [q["name"] for q in packet["queries"]]})

    run_metadata: dict[str, Any] = {"invoked": False}
    if proposal is None:
        if not invoke:
            raise SystemExit("no proposal supplied and invoke=False")
        prompt = build_prompt(incident, packet)
        try:
            raw_output, agent_run = invoke_agent(prompt)
            run_metadata = {"invoked": True, **agent_run}
            proposal = parse_proposal(agent_run.get("raw_output") or raw_output)
        except ModelUnavailable as exc:
            proposal = {
                "incident_id": incident_id,
                "root_cause": "The responder could not reach a model.",
                "confidence": 0.0,
                "evidence_refs": [],
                "action": "escalate",
                "rationale": f"Model transport unavailable ({exc}); escalating the evidence packet to a human.",
            }
            run_metadata = {"invoked": False, "model_unavailable": str(exc)}
        except (ValueError, json.JSONDecodeError) as exc:
            proposal = {
                "incident_id": incident_id,
                "root_cause": f"agent output was not valid JSON: {exc}",
                "confidence": 0.0,
                "evidence_refs": [],
                "action": "escalate",
                "rationale": "The responder could not parse a proposal; escalating to a human.",
            }
            run_metadata = {"invoked": True, "parse_error": str(exc)}

    schema_errors = validate_proposal(proposal)
    if schema_errors:
        incidents.note(incident_id, "responder", "proposal_schema_invalid", {"errors": schema_errors})
        proposal = {
            "incident_id": incident_id,
            "root_cause": proposal.get("root_cause", "invalid proposal"),
            "confidence": 0.0,
            "evidence_refs": [],
            "action": "escalate",
            "rationale": f"proposal failed schema validation: {schema_errors}",
        }
    proposal_record = {**proposal, "run": run_metadata, "schema_errors": schema_errors}
    incidents.update(incident_id, proposal=proposal_record)
    incidents.note(incident_id, "responder", "proposal_received", {"action": proposal.get("action")})

    context = {
        "namespace": os.getenv("K8S_NAMESPACE", "agent-relay"),
        "deployment": os.getenv("K8S_DEPLOYMENT", "agent-relay"),
        "previous_revision": _previous_revision_from_evidence(packet),
        "replicas": 2,
    }
    decision = policy.decide(proposal, packet, context)
    incidents.update(incident_id, policy=decision)
    incidents.note(incident_id, "policy", "decision", decision)

    result: dict[str, Any] = {
        "incident_id": incident_id,
        "proposal": proposal_record,
        "policy": decision,
    }

    if decision["outcome"] == "authorized" and decision.get("executed_command"):
        execution = execute(decision["executed_command"], dry_run=dry_run)
        incidents.update(incident_id, execution=execution)
        incidents.note(incident_id, "executor", "command", execution)
        result["execution"] = execution
        if execution.get("executed") and not dry_run:
            verification = verify(incident)
            incidents.update(incident_id, verification=verification, status="resolved" if verification["recovered"] else "verifying")
            incidents.note(incident_id, "verifier", "recovery_check", {"recovered": verification["recovered"]})
            result["verification"] = verification
        elif dry_run:
            result["verification"] = {"dry_run": True}
    else:
        if decision["outcome"] == "authorized":
            # observe: authorized by design but no command to run.
            incidents.update(incident_id, status="observing")
            result["execution"] = {"executed": False, "reason": "observe: no bounded command required"}
            result["evidence"] = packet
            result["status"] = (incidents.get(incident_id) or {}).get("status")
            if emit:
                emit_to_desk(incident_id, result)
            return result
        escalation = escalate(incident_id, proposal, decision, packet)
        incidents.update(incident_id, escalation=escalation, status="escalated")
        incidents.note(incident_id, "responder", "escalated", escalation)
        result["escalation"] = escalation

    # Carry the full record so an out-of-process caller can persist it.
    result["evidence"] = packet
    final = incidents.get(incident_id) or {}
    result["status"] = final.get("status")
    if emit:
        emit_to_desk(incident_id, result)
    return result


def _previous_revision_from_evidence(packet: dict[str, Any]) -> int | None:
    """Map the previous healthy release to a concrete ReplicaSet revision.

    A rollback must name the revision to undo to; ``--to-revision=0`` ("the one
    before now") is not a bounded response because it depends on whatever else
    rolled out in between. The evidence packet carries the ReplicaSet list with
    each revision's release label, so the target is chosen from data, not
    guessed.
    """

    summary = packet.get("summary", {})
    # Evidence already derived the exact previous revision from the ReplicaSet
    # history; use it rather than re-deriving it from Prometheus label order.
    if summary.get("previous_revision") is not None:
        return int(summary["previous_revision"])
    previous_release = summary.get("previous_release")
    deploys = packet.get("deploy_history", [])
    revisions: list[tuple[int, str | None]] = []
    for item in deploys:
        if item.get("kind") != "replicaset":
            continue
        try:
            revisions.append((int(item.get("revision")), item.get("release")))
        except (TypeError, ValueError):
            continue
    if not revisions:
        return None
    revisions.sort()
    if previous_release:
        candidates = [rev for rev, release in revisions if release == previous_release]
        if candidates:
            return candidates[-1]
    return revisions[0][0] if len(revisions) == 1 else revisions[-2][0]


def _cli() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Headless incident responder")
    parser.add_argument("incident_id")
    parser.add_argument("--dry-run", action="store_true", help="decide but do not execute")
    parser.add_argument("--proposal", help="path to a proposal JSON (skips the model)")
    parser.add_argument("--emit", action="store_true", help="POST the record back to the incident desk")
    args = parser.parse_args()
    proposal = None
    if args.proposal:
        with open(args.proposal, encoding="utf-8") as handle:
            proposal = json.load(handle)
    print(
        json.dumps(
            respond(args.incident_id, dry_run=args.dry_run, proposal=proposal, emit=args.emit),
            indent=2,
            default=str,
        )
    )


if __name__ == "__main__":
    _cli()
