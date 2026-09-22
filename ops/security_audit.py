"""Security audit: deterministic scan, model review, human validation.

Three stages, in this order:

1. **Deterministic scan** -- Semgrep runs a pinned ruleset over the application
   and the responder. Deterministic means the same commit yields the same
   findings with no model in the loop.
2. **Model review** -- the headless agent reviews the same diff for the classes
   of issue a rule engine misses (authorization logic, trust boundaries). Model
   output is untrusted input; it is stored as a proposal, never as a verdict.
3. **Validation** -- every finding is marked ``confirmed``, ``false_positive``,
   or ``needs_human`` by a person. Only confirmed findings go into the report's
   risk section.

The responder's own capabilities and credentials are inventoried here too, so
the report can answer "what can the agent do, and with whose credentials?".
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO = Path(os.getenv("AUDIT_REPO", Path(__file__).resolve().parent.parent))
# The deterministic scan pairs a pinned upstream ruleset with the project rules
# that encode the responder's own invariants.
SEMGREP_CONFIG = os.getenv("SEMGREP_CONFIG", "p/owasp-top-ten")
PROJECT_CONFIG = "observability/security/semgrep.yml"
FINDINGS_DIR = Path(os.getenv("AUDIT_DIR", REPO / "ops" / "audit"))
APP_TARGETS = ["main.py", "database.py", "storage.py", "schemas.py", "worker.py", "telemetry.py", "ops"]

# Validated by reading each code path (not by trusting the rule). Recorded here
# so the report distinguishes real risk from scanner noise, and so a future
# scan can diff against these decisions.
VALIDATION: dict[str, dict[str, str]] = {
    "ops/responder.py:dangerous-subprocess-use-tainted-env-args": {
        "verdict": "false_positive",
        "note": (
            "The flagged env is an explicit allowlist (PATH, HOME, OPENAI_API_KEY, "
            "NO_COLOR); application secrets are not inherited. The command list is "
            "built from constants plus RESPONDER_MODEL, not from model output."
        ),
    },
    "ops/security_audit.py:dangerous-subprocess-use-tainted-env-args": {
        "verdict": "false_positive",
        "note": "`targets` is the constant APP_TARGETS list; SEMGREP_CONFIG is operator-set, not request data.",
    },
    "worker.py:python-logger-credential-disclosure": {
        "verdict": "false_positive",
        "note": "The log line prints the agent_id, which is a public identifier; the token is never logged.",
    },
}


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def deterministic_scan(targets: list[str] | None = None) -> dict[str, Any]:
    """Run Semgrep. Returns structured findings; never raises if Semgrep is absent."""

    binary = shutil.which("semgrep")
    result: dict[str, Any] = {
        "tool": "semgrep",
        "config": SEMGREP_CONFIG,
        "available": binary is not None,
        "at": now(),
        "findings": [],
    }
    if binary is None:
        result["error"] = "semgrep is not installed (pipx install semgrep / pip install semgrep)"
        return result

    targets = targets or APP_TARGETS
    command = [
        binary,
        "scan",
        "--config",
        SEMGREP_CONFIG,
        "--config",
        PROJECT_CONFIG,
        "--json",
        "--quiet",
        "--metrics",
        "off",
        *targets,
    ]
    completed = subprocess.run(command, capture_output=True, text=True, cwd=REPO, timeout=900)
    result["exit_code"] = completed.returncode
    try:
        payload = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError:
        result["error"] = "semgrep did not return JSON"
        result["stderr_tail"] = completed.stderr[-2000:]
        return result
    for finding in payload.get("results", []):
        check_id = finding.get("check_id") or ""
        path = os.path.relpath(finding.get("path", ""), REPO)
        key = f"{path}:{check_id.split('.')[-1]}"
        human = VALIDATION.get(key, {})
        result["findings"].append(
            {
                "check_id": check_id,
                "path": path,
                "line": (finding.get("start") or {}).get("line"),
                "message": (finding.get("extra") or {}).get("message"),
                "severity": (finding.get("extra") or {}).get("severity"),
                "validation": human.get("verdict", "needs_human"),
                "validation_note": human.get("note"),
            }
        )
    return result


def responder_capabilities() -> dict[str, Any]:
    """Inventory what the responder can do and which credentials it holds."""

    manifests = REPO / "k8s" / "ops-responder.yaml"
    return {
        "identity": {
            "service_account": "incident-responder",
            "namespace": "agent-relay",
            "token_mounted": True,
            "audience": "kubernetes.default.svc",
        },
        "kubernetes_rbac": {
            "read": [
                "get/list pods,deployments,replicasets,events in namespace agent-relay",
                "get configmaps in namespace agent-relay",
            ],
            "write": [
                "patch deployments/agent-relay (rollout undo/restart) in namespace agent-relay",
                "patch deployments/agent-relay/scale",
            ],
            "explicitly_absent": [
                "secrets (all verbs)",
                "pods/exec",
                "cluster-scoped resources",
                "other namespaces",
                "rbac.authorization.k8s.io",
                "persistentvolumes",
            ],
        },
        "observability_credentials": {
            "prometheus": "read-only HTTP GET (no auth) to /api/v1/query",
            "loki": "read-only HTTP GET to /query_range",
            "tempo": "read-only HTTP GET to /api/search",
            "grafana": "viewer (datasource proxy only)",
        },
        "database_credentials": "none: the ops image does not connect to PostgreSQL",
        "application_secrets": "none: no RELAY_ENROLLMENT_SECRET, no agent tokens",
        "model_credentials": {
            "provider": os.getenv("RESPONDER_PROVIDER", "openai-codex"),
            "scope": "a model API key only; it grants no infrastructure access",
            "sandbox": "codex exec --sandbox read-only",
        },
        "bounded_actions": [
            "kubectl rollout undo deployment/agent-relay (auto, only with a healthy previous release)",
            "kubectl rollout restart deployment/agent-relay (manual tier: escalated, not executed)",
            "kubectl scale deployment/agent-relay (manual tier: escalated, not executed)",
        ],
        "manifest": str(manifests.relative_to(REPO)) if manifests.exists() else "k8s/ops-responder.yaml",
    }


def model_review(diff: str | None = None, invoke: bool = False) -> dict[str, Any]:
    """Ask the headless agent for an advisory review. Advisory only."""

    review: dict[str, Any] = {
        "at": now(),
        "stage": "model_review",
        "advisory_only": True,
        "invoked": False,
        "findings": [],
    }
    if not invoke:
        review["note"] = "model review skipped (invoke=False); run with --invoke to call the headless agent"
        return review
    from ops import responder

    prompt = (
        "Review this repository for security issues a deterministic scanner would miss. "
        "Focus on authorization boundaries, credential handling, and the responder's "
        "trust boundary. Return JSON: {\"findings\":[{\"title\",\"path\",\"severity\",\"detail\"}]}.\n\n"
        + (diff or _git_diff())
    )
    _, run = responder.invoke_agent(prompt)
    review["invoked"] = True
    review["run"] = {k: v for k, v in run.items() if k != "raw_output"}
    try:
        parsed = responder.parse_proposal(run.get("raw_output") or "")
        review["findings"] = parsed.get("findings", []) if isinstance(parsed, dict) else []
    except Exception as exc:  # noqa: BLE001
        review["parse_error"] = str(exc)
    return review


def _git_diff() -> str:
    completed = subprocess.run(
        ["git", "diff", "--stat", "HEAD"],
        capture_output=True,
        text=True,
        cwd=REPO,
    )
    return completed.stdout or "(no diff)"


def run(invoke_model: bool = False) -> dict[str, Any]:
    FINDINGS_DIR.mkdir(parents=True, exist_ok=True)
    report = {
        "at": now(),
        "commit": _git_rev(),
        "deterministic": deterministic_scan(),
        "model_review": model_review(invoke=invoke_model),
        "responder_capabilities": responder_capabilities(),
        "validation": {
            "instructions": (
                "For each deterministic finding set validation to confirmed|false_positive|needs_human "
                "with a note. Confirm by reading the code path, not by trusting the rule or the model."
            ),
            "validated_by": None,
            "validated_at": None,
        },
    }
    (FINDINGS_DIR / "findings.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    (FINDINGS_DIR / "capabilities.json").write_text(
        json.dumps(report["responder_capabilities"], indent=2), encoding="utf-8"
    )
    return report


def _git_rev() -> str:
    completed = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, cwd=REPO)
    return completed.stdout.strip() or "unknown"


def _cli() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Agent Relay security audit")
    parser.add_argument("--invoke", action="store_true", help="also run the model review")
    args = parser.parse_args()
    print(json.dumps(run(invoke_model=args.invoke), indent=2, default=str))


if __name__ == "__main__":
    _cli()
