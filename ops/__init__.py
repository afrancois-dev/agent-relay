"""Operations plane for Agent Relay.

Nothing in this package is imported by the API image. It is the *responder*
side of the loop: it receives alerts, collects evidence read-only, asks a
headless coding agent for a proposal, and enforces policy before any action.

The trust boundary is deliberate: the responder never holds cluster admin
credentials and never executes a command the policy layer did not select from a
fixed allowlist.
"""

__all__ = ["evidence", "incidents", "policy", "responder", "security_audit", "desk"]
