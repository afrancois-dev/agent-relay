# Runbook: Agent Relay server errors

Referenced by the alert annotations. It is deliberately short: an on-call
engineer should be able to start investigating from the alert payload alone.

## Symptoms

- `AgentRelayHighErrorRate` (critical): a route is returning 5xx for >20% of
  requests over 1 minute.
- `AgentRelayErrorBurst` (warning): a route is emitting >0.2 5xx/s over 5
  minutes even if total traffic is too low for a ratio.
- `AgentRelayTaskFailures` (warning): tasks fail faster than they complete.

## First five minutes

1. **Open the dashboard** named in the alert (`Agent Relay — RED, logs,
   traces`). It is pre-filtered by the `release` label in the alert.
2. **Identify the release.** The alert carries `release` and `route`. Compare
   that release with recent rollouts in the deploy history panel.
3. **Confirm the previous release is healthy.** If the previous release has no
   5xx on the same route, the change is isolated and a rollback is bounded.
4. **Read one error trace.** Jump from the log line's `trace_id` to Tempo and
   read the exception; the span attributes name the failing handler.

## Bounded response

```bash
# Roll back to the immediately previous revision (policy-rendered command).
kubectl -n agent-relay rollout undo deployment/agent-relay --to-revision=<rev>
```

The responder derives `<rev>` from the ReplicaSet history in the evidence
packet; do not guess it. A restart or scale is a *manual* action and needs a
human decision.

## Do not

- Roll back without evidence that the previous release is healthy.
- Restart to "see if it clears": it hides the fault and resets the evidence
  window.
- Read or export application secrets while investigating.
