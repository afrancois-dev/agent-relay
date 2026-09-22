"""Incident store.

An incident is opened from an Alertmanager webhook and grown by the responder
with the evidence packet, the model proposal, the policy decision, the command
that was actually executed, and the recovery verification. Everything a report
reader needs lives in this one row so an incident ID reconstructs the loop.
"""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Generator


STORE_PATH = os.getenv("INCIDENT_STORE", "/var/lib/incidents/incidents.db")
SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    id            TEXT PRIMARY KEY,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    status        TEXT NOT NULL,
    alertname     TEXT,
    severity      TEXT,
    service       TEXT,
    release       TEXT,
    route         TEXT,
    summary       TEXT,
    impact        TEXT,
    labels        TEXT NOT NULL,
    annotations   TEXT NOT NULL,
    payload       TEXT NOT NULL,
    evidence      TEXT,
    proposal      TEXT,
    policy        TEXT,
    execution     TEXT,
    verification  TEXT,
    escalation    TEXT
);
CREATE TABLE IF NOT EXISTS audit (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    at          TEXT NOT NULL,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    detail      TEXT
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@contextmanager
def connect() -> Generator[sqlite3.Connection, None, None]:
    os.makedirs(os.path.dirname(STORE_PATH), exist_ok=True)
    connection = sqlite3.connect(STORE_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    try:
        connection.executescript(SCHEMA)
        yield connection
        connection.commit()
    finally:
        connection.close()


def audit(connection: sqlite3.Connection, incident_id: str, actor: str, action: str, detail: Any = None) -> None:
    connection.execute(
        "INSERT INTO audit (incident_id, at, actor, action, detail) VALUES (?,?,?,?,?)",
        (incident_id, _now(), actor, action, json.dumps(detail, default=str) if detail is not None else None),
    )


def _dumps(value: Any) -> str | None:
    return None if value is None else json.dumps(value, default=str, sort_keys=True)


def _loads(value: str | None) -> Any:
    if not value:
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def row_to_incident(row: sqlite3.Row) -> dict[str, Any]:
    incident = dict(row)
    for key in ("labels", "annotations", "payload", "evidence", "proposal", "policy", "execution",
                "verification", "escalation"):
        if key in incident:
            incident[key] = _loads(incident[key])
    return incident


def open_from_alert(alert: dict[str, Any], incident_id: str | None = None, debounce_seconds: int = 120) -> dict[str, Any]:
    """Create an incident from one Alertmanager alert (or return the open one).

    Repeat alerts for the same (alertname, release, route) within
    ``debounce_seconds`` join the existing incident instead of opening a new
    one, so a flapping alert does not fragment the evidence trail.
    """

    labels = alert.get("labels", {}) or {}
    annotations = alert.get("annotations", {}) or {}
    incident_id = incident_id or f"INC-{uuid.uuid4().hex[:12]}"
    with connect() as connection:
        existing = connection.execute(
            "SELECT * FROM incidents WHERE alertname=? AND release=? AND route=? "
            "ORDER BY created_at DESC LIMIT 1",
            (labels.get("alertname"), labels.get("release"), labels.get("route")),
        ).fetchone()
        if existing is not None:
            opened_at = datetime.fromisoformat(existing["created_at"].replace("Z", "+00:00"))
            age = (datetime.now(timezone.utc) - opened_at).total_seconds()
            if age <= debounce_seconds or existing["status"] != "resolved":
                audit(connection, existing["id"], "alertmanager", "alert_repeat", labels)
                return row_to_incident(existing)

        now = _now()
        connection.execute(
            """INSERT INTO incidents
               (id, created_at, updated_at, status, alertname, severity, service, release, route,
                summary, impact, labels, annotations, payload)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                incident_id,
                now,
                now,
                "open",
                labels.get("alertname"),
                labels.get("severity"),
                labels.get("service"),
                labels.get("release"),
                labels.get("route"),
                annotations.get("summary"),
                annotations.get("impact"),
                _dumps(labels),
                _dumps(annotations),
                _dumps(alert),
            ),
        )
        audit(connection, incident_id, "alertmanager", "incident_opened", {"alertname": labels.get("alertname")})
        row = connection.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        return row_to_incident(row)


def update(incident_id: str, **fields: Any) -> dict[str, Any] | None:
    if not fields:
        return get(incident_id)
    fields["updated_at"] = _now()
    columns = ", ".join(f"{key}=?" for key in fields)
    values = [_dumps(value) if key in {
        "labels", "annotations", "payload", "evidence", "proposal", "policy", "execution",
        "verification", "escalation",
    } else value for key, value in fields.items()]
    with connect() as connection:
        connection.execute(f"UPDATE incidents SET {columns} WHERE id=?", (*values, incident_id))
        row = connection.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        return row_to_incident(row) if row else None


def note(incident_id: str, actor: str, action: str, detail: Any = None) -> None:
    with connect() as connection:
        audit(connection, incident_id, actor, action, detail)


def get(incident_id: str) -> dict[str, Any] | None:
    with connect() as connection:
        row = connection.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        return row_to_incident(row) if row else None


def list_incidents(limit: int = 50) -> list[dict[str, Any]]:
    with connect() as connection:
        rows = connection.execute(
            "SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [row_to_incident(row) for row in rows]


def audit_trail(incident_id: str) -> list[dict[str, Any]]:
    with connect() as connection:
        rows = connection.execute(
            "SELECT * FROM audit WHERE incident_id=? ORDER BY at, id", (incident_id,)
        ).fetchall()
        return [dict(row) for row in rows]


__all__ = [
    "audit_trail",
    "connect",
    "get",
    "list_incidents",
    "note",
    "open_from_alert",
    "row_to_incident",
    "update",
]
