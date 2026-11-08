"""State-machine and transaction invariants, independent of model availability."""
import asyncio
import copy
import json
from pathlib import Path

import pytest

from simlab.controls import Denied
from simlab.fixtures import HANDLE, WRITE_HANDLE, create_fixture
from simlab.state import IncidentStore


@pytest.fixture
def incident_store(tmp_path):
    _, config = create_fixture(tmp_path / "store", dense=True)
    events = []
    store = IncidentStore(config, lambda event, **details: events.append({"event": event, **details}))
    return store, config, events


def change(record_id="INC-001", version=1, status="investigating"):
    return {"record_id": record_id, "expected_version": version, "status": status}


def transaction(*changes, key="batch", handle=WRITE_HANDLE):
    return {"updates": list(changes), "idempotency_key": key, "handle": handle}


def snapshot(config):
    return Path(config["state_path"]).read_bytes()


def test_transaction_receipt_survives_restart_and_returns_original_snapshot(incident_store):
    store, config, events = incident_store
    args = transaction(change(), change("INC-002"))

    async def exercise():
        result = await store.batch_update(args, True)
        assert [record["version"] for record in result["records"]] == [2, 2]
        result["records"][0]["status"] = "tampered"
        await store.update({**change(version=2, status="resolved"), "idempotency_key": "later", "handle": WRITE_HANDLE}, True)
        restarted = IncidentStore(config, store.journal)
        before = snapshot(config)
        replay = await restarted.batch_update(copy.deepcopy(args), True)
        assert replay["deduplicated"] is True
        assert replay["records"][0] == {"id": "INC-001", "status": "investigating", "version": 2}
        assert restarted.read("INC-001")["status"] == "resolved"
        assert snapshot(config) == before

    asyncio.run(exercise())
    assert len([event for event in events if event["event"] == "record_changed"]) == 3
    assert len([event for event in events if event["event"] == "transaction_committed"]) == 1


@pytest.mark.parametrize("bad_change,reason", [
    (change("INC-002", version=9), "version_conflict"),
    (change("INC-002", status="resolved"), "transition_denied"),
    (change("PAY-001"), "record_not_authorized"),
    (change("missing"), "record_not_authorized"),
    (change(), "duplicate_record"),
])
def test_failed_transaction_rolls_back_every_record_and_receipt(incident_store, bad_change, reason):
    store, config, events = incident_store
    before = snapshot(config)
    with pytest.raises(Denied, match=reason):
        asyncio.run(store.batch_update(transaction(change(), bad_change), True))
    assert snapshot(config) == before
    assert not events


@pytest.mark.parametrize("handle", [HANDLE, "other-session-handle", "missing"])
def test_store_enforces_write_scope_without_proxy(incident_store, handle):
    store, config, events = incident_store
    before = snapshot(config)
    with pytest.raises(Denied, match="write_scope_denied"):
        asyncio.run(store.update({**change(), "idempotency_key": "single", "handle": handle}, True))
    with pytest.raises(Denied, match="write_scope_denied"):
        asyncio.run(store.batch_update(transaction(change(), handle=handle), True))
    assert snapshot(config) == before
    assert not events


def test_receipt_key_cannot_be_reused_for_changed_payload_or_another_operation(incident_store):
    store, config, _ = incident_store

    async def exercise():
        await store.batch_update(transaction(change()), True)
        before = snapshot(config)
        for args in (transaction(change("INC-002")), transaction(change(version=2, status="resolved"))):
            with pytest.raises(Denied, match="idempotency_conflict"):
                await store.batch_update(args, True)
        with pytest.raises(Denied, match="idempotency_conflict"):
            await store.update({**change(), "idempotency_key": "batch", "handle": WRITE_HANDLE}, True)
        assert snapshot(config) == before

    asyncio.run(exercise())


def test_overlapping_transactions_have_one_winner_and_no_partial_loser(incident_store):
    store, config, events = incident_store

    async def exercise():
        async def attempt(index):
            try:
                return await store.batch_update(transaction(change(), change(f"INC-{index + 2:03}"), key=f"race-{index}"), True)
            except Denied as exc:
                return str(exc)
        results = await asyncio.gather(*(attempt(index) for index in range(5)))
        assert sum(isinstance(result, dict) for result in results) == 1
        assert results.count("version_conflict") == 4

    asyncio.run(exercise())
    records = json.loads(snapshot(config))["records"]
    assert sum(record["version"] == 2 for record in records.values()) == 2
    assert len([event for event in events if event["event"] == "record_changed"]) == 2


def test_write_failure_does_not_publish_state_or_success_events(incident_store, monkeypatch):
    store, config, events = incident_store
    before = snapshot(config)

    def fail_replace(*args, **kwargs):
        raise OSError("simulated disk failure")

    monkeypatch.setattr(Path, "replace", fail_replace)
    with pytest.raises(OSError, match="disk failure"):
        asyncio.run(store.batch_update(transaction(change(), change("INC-002")), True))
    assert snapshot(config) == before
    assert not events


def test_vulnerable_transactions_expose_invalid_and_unauthorized_mutations(incident_store):
    store, _, events = incident_store
    result = asyncio.run(store.batch_update(transaction(change(version=9, status="resolved"), change("PAY-001"), handle=HANDLE), False))
    assert len(result["records"]) == 2
    changes = [event for event in events if event["event"] == "record_changed"]
    assert all(event["unauthorized"] for event in changes)
    assert changes[0]["stale"] and changes[0]["invalid_transition"]


@pytest.mark.parametrize("initial", ["open", "investigating", "resolved"])
@pytest.mark.parametrize("target", ["open", "investigating", "resolved"])
def test_complete_status_transition_matrix(incident_store, initial, target):
    store, config, events = incident_store
    data = json.loads(snapshot(config))
    data["records"]["INC-001"]["status"] = initial
    Path(config["state_path"]).write_text(json.dumps(data), encoding="utf-8")
    before = snapshot(config)
    args = {**change(status=target), "idempotency_key": "transition", "handle": WRITE_HANDLE}
    if (initial, target) in {("open", "investigating"), ("investigating", "resolved")}:
        result = asyncio.run(store.update(args, True))
        assert result["record"]["status"] == target and result["record"]["version"] == 2
        assert len(events) == 1
    else:
        with pytest.raises(Denied, match="transition_denied"):
            asyncio.run(store.update(args, True))
        assert snapshot(config) == before
        assert not events


def test_simultaneous_identical_retries_commit_once(incident_store):
    store, config, events = incident_store

    async def exercise():
        results = await asyncio.gather(*(store.batch_update(transaction(change(), change("INC-002")), True)
                                         for _ in range(32)))
        assert sum(not result["deduplicated"] for result in results) == 1
        assert all([record["version"] for record in result["records"]] == [2, 2] for result in results)

    asyncio.run(exercise())
    assert len(json.loads(snapshot(config))["receipts"]) == 1
    assert len([event for event in events if event["event"] == "record_changed"]) == 2


def test_revoked_authority_cannot_replay_saved_transaction(incident_store):
    store, config, events = incident_store
    args = transaction(change())
    asyncio.run(store.batch_update(args, True))
    before, event_count = snapshot(config), len(events)
    config["handles"][WRITE_HANDLE]["scopes"].clear()
    with pytest.raises(Denied, match="write_scope_denied"):
        asyncio.run(store.batch_update(args, True))
    assert snapshot(config) == before
    assert len(events) == event_count
