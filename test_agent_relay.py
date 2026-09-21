"""Protocol tests for the SQLite starter.

These tests intentionally exercise storage calls from multiple threads: that
is the closest local equivalent to several worker processes racing to claim an
inbox.  The production guarantee comes from SQLite's BEGIN IMMEDIATE boundary,
not from a Python lock.
"""

from __future__ import annotations

import os

# Default to a scratch DB so `pytest` never resets the dev server's
# `./agent-relay.db`. Respect an explicit RELAY_DATABASE_URL/DATABASE_URL
# (e.g. CI pointing at PostgreSQL), but otherwise isolate tests.
os.environ.setdefault("RELAY_DATABASE_URL", "sqlite:////tmp/agent-relay-test.db")

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

import main
from database import Attempt, Base, Task, as_db_time, db_session, engine, utcnow
from storage import claim_one


@pytest.fixture(autouse=True)
def empty_database():
    # Resets whatever DB RELAY_DATABASE_URL points at. Defaults to the
    # scratch /tmp file above; never run against a DB with data you need.
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield
    Base.metadata.drop_all(engine)


def register(client: TestClient, name: str) -> tuple[dict, dict[str, str]]:
    response = client.post("/api/v1/agents", json={"name": name})
    assert response.status_code == 201
    data = response.json()
    return data, {"Authorization": f"Bearer {data['token']}"}


def test_protocol_idempotency_terminal_retry_and_auth_boundary():
    with TestClient(main.app) as client:
        sender, sender_headers = register(client, "sender")
        recipient, recipient_headers = register(client, "uppercase")
        sent = client.post(
            "/api/v1/tasks",
            headers={**sender_headers, "Idempotency-Key": "demo-1"},
            json={"to": recipient["agent_id"], "input": "hello relay"},
        )
        assert sent.status_code == 201
        duplicate = client.post(
            "/api/v1/tasks",
            headers={**sender_headers, "Idempotency-Key": "demo-1"},
            json={"to": recipient["agent_id"], "input": "hello relay"},
        )
        assert duplicate.status_code == 201
        assert duplicate.json() == sent.json()
        conflict = client.post(
            "/api/v1/tasks",
            headers={**sender_headers, "Idempotency-Key": "demo-1"},
            json={"to": recipient["agent_id"], "input": "different"},
        )
        assert conflict.status_code == 409

        task_id = sent.json()["task_id"]
        claim = client.post(
            "/api/v1/tasks/claim",
            headers=recipient_headers,
            json={"worker_id": "worker-a", "wait_seconds": 0},
        )
        assert claim.status_code == 200
        claim_data = claim.json()
        assert "claim_token" in claim_data
        complete = client.post(
            f"/api/v1/tasks/{task_id}/complete",
            headers=recipient_headers,
            json={"claim_token": claim_data["claim_token"], "output": "HELLO RELAY"},
        )
        assert complete.status_code == 200
        retry = client.post(
            f"/api/v1/tasks/{task_id}/complete",
            headers=recipient_headers,
            json={"claim_token": claim_data["claim_token"], "output": "HELLO RELAY"},
        )
        assert retry.status_code == 200
        assert client.get(f"/api/v1/tasks/{task_id}", headers=recipient_headers).status_code == 200
        forbidden = client.get(f"/api/v1/tasks/{task_id}", headers={"Authorization": f"Bearer {sender['token']}"})
        assert forbidden.status_code == 200  # sender is an authorized participant
        no_credentials = client.get("/api/v1/agents")
        assert no_credentials.status_code == 401
        attempts = client.get(f"/api/v1/tasks/{task_id}/attempts", headers=sender_headers).json()
        assert attempts["items"][0]["outcome"] == "completed"
        assert "claim_token" not in attempts["items"][0]


def test_acceptance_scenario_exchange_task_and_result():
    """SPEC acceptance scenario 1: two agents exchange a task and its result.

    Drives the real HTTP API and the real database (not the storage layer
    directly), then confirms both participants observe the terminal state the
    dashboard reads through ``GET /tasks``.
    """

    with TestClient(main.app) as client:
        sender, sender_headers = register(client, "alice-reviewer")
        recipient, recipient_headers = register(client, "bob-worker")

        sent = client.post(
            "/api/v1/tasks",
            headers={**sender_headers, "Idempotency-Key": "scenario-1"},
            json={"to": recipient["agent_id"], "input": "review this python function"},
        )
        assert sent.status_code == 201
        task_id = sent.json()["task_id"]
        assert sent.json()["status"] == "queued"

        queued = client.get(f"/api/v1/tasks/{task_id}", headers=sender_headers).json()
        assert queued["status"] == "queued"
        assert queued["from"] == sender["agent_id"]
        assert queued["to"] == recipient["agent_id"]
        assert queued["output"] is None and queued["finished_at"] is None

        claim = client.post(
            "/api/v1/tasks/claim",
            headers=recipient_headers,
            json={"worker_id": "bob-laptop-1", "wait_seconds": 0},
        )
        assert claim.status_code == 200
        claim_data = claim.json()
        assert claim_data["task_id"] == task_id
        assert claim_data["from"] == sender["agent_id"]
        assert claim_data["input"] == "review this python function"
        assert claim_data["attempt"] == 1
        assert claim_data["claim_token"]
        assert claim_data["lease_expires_at"]

        # The recipient executes locally (the starter's engine is input.upper()).
        complete = client.post(
            f"/api/v1/tasks/{task_id}/complete",
            headers=recipient_headers,
            json={"claim_token": claim_data["claim_token"], "output": claim_data["input"].upper()},
        )
        assert complete.status_code == 200

        # The sender reads the result through the same endpoint the dashboard uses.
        result = client.get(f"/api/v1/tasks/{task_id}", headers=sender_headers).json()
        assert result["status"] == "completed"
        assert result["output"] == "REVIEW THIS PYTHON FUNCTION"
        assert result["error"] is None
        assert result["attempt_count"] == 1
        assert result["finished_at"] is not None

        # Both participants see it in their dashboard task lists.
        sent_list = client.get("/api/v1/tasks?direction=sent", headers=sender_headers).json()
        received_list = client.get("/api/v1/tasks?direction=received", headers=recipient_headers).json()
        assert [t["task_id"] for t in sent_list["items"]] == [task_id]
        assert [t["task_id"] for t in received_list["items"]] == [task_id]
        assert sent_list["items"][0]["status"] == "completed"

        attempts = client.get(f"/api/v1/tasks/{task_id}/attempts", headers=sender_headers).json()
        assert [(a["attempt"], a["outcome"], a["worker_id"]) for a in attempts["items"]] == [
            (1, "completed", "bob-laptop-1")
        ]
        assert "claim_token" not in attempts["items"][0]


def test_sqlite_atomic_claims_distribute_without_overlap():
    with TestClient(main.app) as client:
        _sender, sender_headers = register(client, "sender")
        recipient, _recipient_headers = register(client, "recipient")
        for index in range(16):
            response = client.post(
                "/api/v1/tasks",
                headers=sender_headers,
                json={"to": recipient["agent_id"], "input": f"task-{index}"},
            )
            assert response.status_code == 201
        with ThreadPoolExecutor(max_workers=16) as pool:
            claims = list(pool.map(lambda index: claim_one(recipient["agent_id"], f"worker-{index}"), range(16)))
        claims = [claim for claim in claims if claim is not None]
        assert len(claims) == 16
        assert len({claim["task_id"] for claim in claims}) == 16
        with db_session() as db:
            processing = list(db.query(Task).filter(Task.status == "processing"))
            assert len(processing) == 16
            assert all(task.attempt_count == 1 for task in processing)


def test_expiry_requeues_and_old_token_is_stale_before_recovery():
    with TestClient(main.app) as client:
        _sender, sender_headers = register(client, "sender")
        recipient, recipient_headers = register(client, "recipient")
        task = client.post(
            "/api/v1/tasks",
            headers=sender_headers,
            json={"to": recipient["agent_id"], "input": "recover me"},
        ).json()
        task_id = task["task_id"]
        first = client.post(
            "/api/v1/tasks/claim", headers=recipient_headers, json={"worker_id": "dead", "wait_seconds": 0}
        ).json()
        with db_session() as db:
            attempt = db.query(Attempt).filter(Attempt.task_id == task_id).one()
            attempt.lease_expires_at = as_db_time(utcnow() - timedelta(seconds=1))
        stale = client.post(
            f"/api/v1/tasks/{task_id}/complete",
            headers=recipient_headers,
            json={"claim_token": first["claim_token"], "output": "TOO LATE"},
        )
        assert stale.status_code == 409
        assert stale.json()["error"]["code"] == "stale_claim"
        assert main.recover_expired() == 1
        second = client.post(
            "/api/v1/tasks/claim", headers=recipient_headers, json={"worker_id": "replacement", "wait_seconds": 0}
        )
        assert second.status_code == 200
        assert second.json()["attempt"] == 2
        assert second.json()["claim_token"] != first["claim_token"]


def test_dashboard_is_asset_and_invalid_input_is_documented_error():
    with TestClient(main.app) as client:
        page = client.get("/")
        assert page.status_code == 200
        assert "sessionStorage" in page.text
        missing_name = client.post("/api/v1/agents", json={})
        assert missing_name.status_code == 400
        assert missing_name.json()["error"]["code"] == "invalid_input"
