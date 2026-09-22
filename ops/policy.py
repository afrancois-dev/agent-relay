"""Autonomy policy: the code outside the model that enforces permission.

The model supplies a *proposal*. This module decides whether that proposal maps
to a command the operator has pre-authorized. Three rules:

1. A proposed action must exist in :data:`ACTIONS`; unknown actions are denied.
2. The action's ``predicate`` must hold for this incident (e.g. a rollback only
   when telemetry shows the previous release is healthy).
3. The command is **rendered by policy from the allowlist entry only** -- the
   model's free-text ``command`` is never executed. It is recorded so the report
   can show what the model suggested versus what policy ran.

The responder carries no production admin credentials; the executor runs a
single ``kubectl`` verb from this allowlist, authenticated by the responder's
own namespace-scoped ServiceAccount.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable


# Actions the operator has pre-authorized the responder to take. Everything not
# in this table is denied, including actions that look reasonable.
AUTONOMY = {
    "rollback_deployment": "auto",
    "escalate": "auto",
    "observe": "auto",
    "restart_deployment": "manual",
    "scale_deployment": "manual",
}


@dataclass(frozen=True)
class Authorized:
    name: str
    tier: str
    description: str
    template: str = ""
    predicate: Callable[[dict[str, Any], dict[str, Any]], bool] = field(default=lambda *_: True)
    denial: str = "the preconditions for this action are not met"


def _previous_release_healthy(packet: dict[str, Any], proposal: dict[str, Any]) -> bool:
    summary = packet.get("summary", {})
    previous = proposal.get("rollback_release") or summary.get("previous_release")
    if not previous:
        return False
    # The previous release must be absent from the failing set for every
    # impacted route in this incident.
    impacted = {item.get("route") for item in summary.get("impacted_routes", [])}
    if not impacted:
        return False
    failing_routes_by_release = {
        (item.get("route"), item.get("release"))
        for item in summary.get("impacted_routes", [])
    }
    return all((route, previous) not in failing_routes_by_release for route in impacted)


def _has_release_evidence(packet: dict[str, Any], proposal: dict[str, Any]) -> bool:
    summary = packet.get("summary", {})
    return bool(summary.get("previous_release") or proposal.get("rollback_release"))


def _always(*_: Any) -> bool:
    return True


ACTIONS: dict[str, Authorized] = {
    "rollback_deployment": Authorized(
        name="rollback_deployment",
        tier="auto",
        description="Roll the deployment back to the last healthy release (bounded, reversible).",
        template="kubectl -n {namespace} rollout undo deployment/{deployment} --to-revision={revision}",
        predicate=_previous_release_healthy,
        denial="no healthy previous release is evidenced for the impacted routes",
    ),
    "observe": Authorized(
        name="observe",
        tier="auto",
        description="Take no action; keep observing. Used when evidence is inconclusive or impact is not yet proven.",
        template="",
        predicate=_always,
    ),
    "restart_deployment": Authorized(
        name="restart_deployment",
        tier="manual",
        description="Rolling restart. Requires human approval because a restart can mask a real fault.",
        template="kubectl -n {namespace} rollout restart deployment/{deployment}",
        predicate=_always,
    ),
    "scale_deployment": Authorized(
        name="scale_deployment",
        tier="manual",
        description="Change replica count. Requires human approval; changes capacity and cost.",
        template="kubectl -n {namespace} scale deployment/{deployment} --replicas={replicas}",
        predicate=_always,
    ),
}


def decide(proposal: dict[str, Any], packet: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Map a model proposal to an allowlisted, bounded command or a denial."""

    context = context or {}
    requested = (proposal.get("action") or "").strip()
    decision: dict[str, Any] = {
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "requested_action": requested,
        "model_rationale": proposal.get("rationale"),
        "model_confidence": proposal.get("confidence"),
        "model_command_suggestion": proposal.get("command"),
        "action_tier": AUTONOMY.get(requested, "unknown"),
    }

    if requested not in ACTIONS:
        decision.update(
            allowed=False,
            outcome="denied",
            reason=f"'{requested}' is not in the action allowlist",
            executed_command=None,
        )
        return decision

    action = ACTIONS[requested]
    if not action.predicate(packet, proposal):
        decision.update(
            allowed=False,
            outcome="escalate",
            reason=action.denial,
            executed_command=None,
        )
        return decision

    if action.tier == "manual":
        decision.update(
            allowed=False,
            outcome="escalate",
            reason=f"'{requested}' requires human approval (tier=manual)",
            executed_command=None,
        )
        return decision

    if not _has_release_evidence(packet, proposal) and requested == "rollback_deployment":
        revision = proposal.get("rollback_revision") or context.get("previous_revision")
        if revision is None:
            decision.update(
                allowed=False,
                outcome="escalate",
                reason="rollback needs a concrete target revision from evidence",
                executed_command=None,
            )
            return decision

    revision = proposal.get("rollback_revision") or context.get("previous_revision") or "0"
    replicas = proposal.get("replicas") or context.get("replicas") or 2
    command = action.template.format(
        namespace=context.get("namespace", "agent-relay"),
        deployment=context.get("deployment", "agent-relay"),
        revision=revision,
        replicas=replicas,
    ).strip() or None

    decision.update(
        allowed=True,
        outcome="authorized",
        reason=f"'{requested}' matches an allowlisted action at tier '{action.tier}'",
        executed_command=command,
    )
    return decision


def allowed_actions() -> list[dict[str, str]]:
    return [
        {"name": action.name, "tier": action.tier, "description": action.description}
        for action in ACTIONS.values()
    ]


__all__ = ["ACTIONS", "AUTONOMY", "allowed_actions", "decide"]
