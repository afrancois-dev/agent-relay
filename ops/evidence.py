"""Bounded, repeatable evidence collection.

The responder must be *evidence first*: before any model is involved, collect a
packet from read-only, allowlisted queries. Two properties matter:

* **Read-only** -- every query is an HTTP GET against Prometheus, Loki, Tempo,
  or the Grafana alert list. No writes, no database admin credentials.
* **Allowlisted** -- only the queries in :data:`CATALOG` can run. The catalog is
  code, not model output, so a prompt-injected model cannot widen it.

The packet is normalized and size-bounded so it is safe to hand to a model and
small enough to store in the incident row.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any


def _url(name: str, default: str) -> str:
    # Resolved at call time so tests and the in-cluster pod can point the
    # collector at different backends without re-importing the module.
    return os.getenv(name, default).rstrip("/")


def prometheus_url() -> str:
    return _url("PROMETHEUS_URL", "http://localhost:9090")


def loki_url() -> str:
    return _url("LOKI_URL", "http://localhost:3100")


def tempo_url() -> str:
    return _url("TEMPO_URL", "http://localhost:3200")


PROMETHEUS_URL = prometheus_url()
LOKI_URL = loki_url()
TEMPO_URL = tempo_url()
K8S_API = os.getenv("K8S_API", "https://kubernetes.default.svc").rstrip("/")
K8S_TOKEN_PATH = os.getenv("K8S_TOKEN_PATH", "/var/run/secrets/kubernetes.io/serviceaccount/token")
K8S_CA_PATH = os.getenv("K8S_CA_PATH", "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
NAMESPACE = os.getenv("K8S_NAMESPACE", "agent-relay")
DEPLOYMENT = os.getenv("K8S_DEPLOYMENT", "agent-relay")

MAX_LOGS = 40
MAX_TRACES = 10
MAX_DEPLOYS = 25
HTTP_TIMEOUT = 10


@dataclass(frozen=True)
class ReadOnlyQuery:
    """One allowlisted read-only lookup."""

    name: str
    description: str
    source: str
    query: str
    window_minutes: int = 15


CATALOG: dict[str, ReadOnlyQuery] = {
    "error_ratio": ReadOnlyQuery(
        "error_ratio",
        "5xx share per route and release (the symptom users feel).",
        "prometheus",
        'sum by (route, release) (rate(relay_http_requests_total{status=~"5.."}[5m]))',
        window_minutes=15,
    ),
    "request_rate": ReadOnlyQuery(
        "request_rate",
        "Total request rate per route and status.",
        "prometheus",
        "sum by (route, status, release) (rate(relay_http_requests_total[5m]))",
    ),
    "error_logs": ReadOnlyQuery(
        "error_logs",
        "Recent error/exception log lines for the service.",
        "loki",
        '{service_name="agent-relay"} | severity_text=~"ERROR|WARN"',
    ),
    "recent_deploys": ReadOnlyQuery(
        "recent_deploys",
        "Recent releases seen in telemetry with their first/last sample.",
        "prometheus",
        "count by (release) (relay_http_requests_total)",
        window_minutes=1440,
    ),
    "task_lifecycle": ReadOnlyQuery(
        "task_lifecycle",
        "Task create/claim/complete/fail rates (business impact).",
        "prometheus",
        "sum by (event, release) (rate(relay_task_events_total[5m]))",
    ),
    "alert_state": ReadOnlyQuery(
        "alert_state",
        "Currently firing alerts and their labels.",
        "prometheus",
        "ALERTS{alertstate='firing'}",
    ),
    "slow_traces": ReadOnlyQuery(
        "slow_traces",
        "Recent failing/slow traces (via Tempo search).",
        "tempo",
        "GET /api/search",
    ),
}


class EvidenceError(RuntimeError):
    pass


def _http_get(url: str, params: dict[str, Any] | None = None, headers: dict[str, str] | None = None) -> Any:
    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"
    request = urllib.request.Request(url, method="GET", headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise EvidenceError(f"GET {url} -> HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        raise EvidenceError(f"GET {url} failed: {exc}") from exc


def _promql(expression: str, minutes: int = 15, limit: int = 50) -> list[dict[str, Any]]:
    payload = _http_get(f"{prometheus_url()}/api/v1/query", {"query": expression})
    results = payload.get("data", {}).get("result", [])
    sample = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    return [
        {
            "metric": item.get("metric", {}),
            "value": item.get("value", [None, None])[1],
            "window_start": sample.isoformat(timespec="seconds"),
        }
        for item in results[:limit]
    ]


def _loki(expression: str, minutes: int = 15, limit: int = MAX_LOGS) -> list[dict[str, Any]]:
    end = time.time()
    start = end - minutes * 60
    payload = _http_get(
        f"{loki_url()}/loki/api/v1/query_range",
        {"query": expression, "start": f"{start:.0f}", "end": f"{end:.0f}", "limit": limit, "direction": "backward"},
    )
    entries: list[dict[str, Any]] = []
    for stream in payload.get("data", {}).get("result", []):
        labels = stream.get("stream", {})
        for value in stream.get("values", [])[:limit]:
            timestamp, line = value[0], value[1]
            parsed: Any = line
            try:
                parsed = json.loads(line)
            except (json.JSONDecodeError, TypeError):
                pass
            entries.append({"labels": labels, "timestamp": timestamp, "line": parsed})
    entries.sort(key=lambda item: item["timestamp"], reverse=True)
    return entries[:limit]


def _tempo(minutes: int = 15, limit: int = MAX_TRACES) -> list[dict[str, Any]]:
    end = int(time.time())
    start = end - minutes * 60
    payload = _http_get(
        f"{tempo_url()}/api/search",
        {"q": '{resource.service.name="agent-relay" && status=error}', "start": start, "end": end, "limit": limit},
    )
    traces = payload.get("traces", []) or []
    return [
        {
            "trace_id": trace.get("traceID"),
            "root_service": trace.get("rootServiceName"),
            "root_span": trace.get("rootTraceName"),
            "start": trace.get("startTimeUnixNano"),
            "duration_ms": trace.get("durationMs"),
        }
        for trace in traces[:limit]
    ]


def _k8s_get(path: str) -> Any:
    headers = {"Accept": "application/json"}
    token = None
    try:
        with open(K8S_TOKEN_PATH, encoding="utf-8") as handle:
            token = handle.read().strip()
    except OSError:
        token = None
    if token:
        headers["Authorization"] = f"Bearer {token}"
    import ssl

    context = None
    if os.path.exists(K8S_CA_PATH):
        context = ssl.create_default_context(cafile=K8S_CA_PATH)
    request = urllib.request.Request(f"{K8S_API}{path}", method="GET", headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT, context=context) as response:
            return json.loads(response.read().decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - evidence collection degrades, never crashes the responder
        raise EvidenceError(f"k8s GET {path} failed: {exc}") from exc


def _k8s_deploys() -> list[dict[str, Any]]:
    """Read-only deployment and rollout history (no secrets, no pod exec)."""

    deploys: list[dict[str, Any]] = []
    try:
        deployment = _k8s_get(f"/apis/apps/v1/namespaces/{NAMESPACE}/deployments/{DEPLOYMENT}")
        for container in deployment["spec"]["template"]["spec"]["containers"]:
            for env in container.get("env", []):
                if env.get("name") in {"RELAY_RELEASE", "GIT_SHA"}:
                    value = env.get("value") or env.get("valueFrom", {}).get("secretKeyRef", {}).get("name")
                    deploys.append({"kind": "env", "name": env["name"], "value": value})
            deploys.append({"kind": "image", "container": container["name"], "value": container["image"]})
    except (EvidenceError, KeyError, TypeError):
        pass
    try:
        replicasets = _k8s_get(f"/apis/apps/v1/namespaces/{NAMESPACE}/replicasets")
        for item in replicasets.get("items", [])[:MAX_DEPLOYS]:
            if not item.get("metadata", {}).get("name", "").startswith(DEPLOYMENT):
                continue
            containers = item["spec"]["template"]["spec"]["containers"]
            images = [container["image"] for container in containers]
            release = None
            for container in containers:
                for env in container.get("env", []):
                    if env.get("name") == "RELAY_RELEASE":
                        release = env.get("value") or (
                            env.get("valueFrom", {}).get("secretKeyRef", {}).get("name")
                        )
            # Release identity comes from the image tag when the template has no
            # RELAY_RELEASE env: the baked-in label means the tag IS the release.
            # This keeps the previous-release lookup correct for immutable tags.
            if release is None and images:
                tag = images[0].rsplit(":", 1)[-1]
                if tag and tag not in {"latest", "local"}:
                    release = tag
            deploys.append(
                {
                    "kind": "replicaset",
                    "name": item["metadata"]["name"],
                    "images": images,
                    "release": release,
                    "revision": item["metadata"]["annotations"].get("deployment.kubernetes.io/revision"),
                    "created_at": item["metadata"].get("creationTimestamp"),
                }
            )
    except (EvidenceError, KeyError, TypeError):
        pass
    return deploys


def collect(incident: dict[str, Any] | None = None, minutes: int = 15) -> dict[str, Any]:
    """Collect the standard evidence packet. Never raises; records what failed."""

    incident = incident or {}
    release = incident.get("release")
    started = time.time()
    packet: dict[str, Any] = {
        "incident_id": incident.get("id"),
        "collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "window_minutes": minutes,
        "focus": {
            "release": release,
            "route": incident.get("route"),
            "alertname": incident.get("alertname"),
            "severity": incident.get("severity"),
        },
        "queries": [],
        "errors": [],
    }

    def record(name: str, query: str, result: Any) -> None:
        packet["queries"].append({"name": name, "query": query, "result": result})

    def capture(name: str, description: str, query: str, source: str, minutes_: int = minutes) -> None:
        try:
            if source == "prometheus":
                result = _promql(query, minutes_)
            elif source == "loki":
                result = _loki(query, minutes_)
            else:
                result = _tempo(minutes_)
            record(name, query, result)
        except EvidenceError as exc:
            packet["errors"].append({"name": name, "description": description, "error": str(exc)})

    for name, item in CATALOG.items():
        if name == "slow_traces":
            capture(name, item.description, item.query, "tempo", max(minutes, 30))
        else:
            capture(name, item.description, item.query, item.source, max(minutes, item.window_minutes))

    packet["deploy_history"] = _k8s_deploys()

    # Highlight the differential: which release is failing and what changed.
    packet["summary"] = _summarize(packet, release)
    packet["raw_error_ratio"] = {item["name"]: item["result"] for item in packet["queries"]}.get("error_ratio", [])
    packet["attach"] = {
        "grafana_dashboard": "/d/agent-relay-red",
        "grafana_explore": f"/explore?left=[\"now-{minutes}m\",\"now\",\"Prometheus\",{{\"expr\":\"{CATALOG['error_ratio'].query}\"}}]",
        "release": release,
    }
    packet["collection_seconds"] = round(time.time() - started, 3)
    return packet


def _summarize(packet: dict[str, Any], release: str | None) -> dict[str, Any]:
    summary: dict[str, Any] = {"impacted_routes": [], "failing_releases": [], "error_lines": 0, "error_traces": 0}
    by_name = {item["name"]: item for item in packet["queries"]}
    errors = by_name.get("error_ratio", {}).get("result", []) or []
    for item in errors:
        metric = item.get("metric", {})
        if metric.get("release") == release or release is None:
            try:
                rate = float(item.get("value"))
            except (TypeError, ValueError):
                rate = 0.0
            if rate <= 0:
                # A zero-rate series is not an impacted route; keeping it would
                # make verification unable to ever report recovery.
                continue
            summary["impacted_routes"].append(
                {"route": metric.get("route"), "release": metric.get("release"), "errors_per_second": item.get("value")}
            )
    # Failing releases come from the error ratio, not from "all releases seen".
    # A release is failing only if it has a positive 5xx rate.
    failing: dict[str, str] = {}
    for item in by_name.get("error_ratio", {}).get("result", []) or []:
        metric = item.get("metric", {})
        item_release = metric.get("release")
        try:
            rate = float(item.get("value"))
        except (TypeError, ValueError):
            rate = 0.0
        if item_release and rate > 0:
            failing[item_release] = item.get("value")
    seen_releases = [
        item.get("metric", {}).get("release")
        for item in (by_name.get("recent_deploys", {}).get("result", []) or [])
        if item.get("metric", {}).get("release")
    ]
    for name, value in failing.items():
        summary["failing_releases"].append({"release": name, "errors_per_second": value})
    # The previous release is the most recent other release that is NOT failing.
    summary["healthy_releases"] = [name for name in seen_releases if name not in failing]
    summary["error_lines"] = len(by_name.get("error_logs", {}).get("result", []) or [])
    summary["error_traces"] = len(by_name.get("slow_traces", {}).get("result", []) or [])
    summary["previous_release"], summary["previous_revision"] = _revision_neighbour(
        packet.get("deploy_history", []), release, failing
    )
    if summary["previous_release"] is None:
        summary["previous_release"] = _pick_previous(summary, release)
    return summary


def _revision_neighbour(
    deploy_history: list[dict[str, Any]], release: str | None, failing: dict[str, str]
) -> tuple[str | None, int | None]:
    """The release immediately before the incident's, from ReplicaSet revisions.

    Revision order is ground truth for "what was deployed before this one".
    Prometheus label order is not: a rollback can leave several old release
    labels with live series. Prefer the highest-revision ReplicaSet whose
    release differs from the incident's and is not itself failing.
    """

    revisions: list[tuple[int, str | None]] = []
    for item in deploy_history:
        if item.get("kind") != "replicaset":
            continue
        try:
            revisions.append((int(item.get("revision")), item.get("release")))
        except (TypeError, ValueError):
            continue
    revisions.sort()
    # Find the highest revision matching the incident release (the bad one),
    # then walk backwards to the nearest non-failing different release.
    index = None
    for position in range(len(revisions) - 1, -1, -1):
        if revisions[position][1] == release:
            index = position
            break
    search = revisions[:index] if index is not None else revisions
    for revision, name in reversed(search):
        if name and name != release and name not in failing:
            return name, revision
    return None, None


def _previous_release(releases: list[dict[str, Any]], current: str | None) -> str | None:
    others = [item["release"] for item in releases if item.get("release") and item.get("release") != current]
    return others[0] if others else None


def _pick_previous(summary: dict[str, Any], release: str | None) -> str | None:
    healthy = [name for name in summary.get("healthy_releases", []) if name != release]
    if healthy:
        return healthy[0]
    failing = [item["release"] for item in summary.get("failing_releases", []) if item.get("release") != release]
    return failing[0] if failing else None


def catalog() -> list[dict[str, str]]:
    return [
        {"name": item.name, "description": item.description, "source": item.source, "query": item.query}
        for item in CATALOG.values()
    ]


__all__ = ["CATALOG", "EvidenceError", "collect", "catalog"]
