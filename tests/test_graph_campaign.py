import asyncio
import copy
import json
import random
from pathlib import Path

import pytest

from simlab.campaign import campaign_matrix, read_manifest
from simlab.graph_campaign import generate_graph_manifest, validate_graph_manifest
from simlab.graph_campaign import GraphOracle, verify_race
from simlab.fixtures import WRITE_HANDLE, create_fixture
from simlab.state import IncidentStore
from simlab.controls import Denied
from mcp import types


def test_graph_manifest_generation_is_deterministic_and_contains_composed_stress():
    manifest = generate_graph_manifest(11, 60, nodes=32, width=4, parallel_calls=16)
    assert manifest == generate_graph_manifest(11, 60, nodes=32, width=4, parallel_calls=16)
    assert len(manifest["graph"]) == 32 and len(manifest["actions"]) == 60
    assert {action["label"] for action in manifest["actions"]} >= {
        "lost_ack_retry", "blocked_tip", "receipt_payload_conflict", "dependency_wave", "completed_analysis", "replayed_race"}
    assert len(next(action for action in manifest["actions"] if action["kind"] == "race")["requests"]) == 16


@pytest.mark.parametrize("problem", ["cycle", "outside_edge", "unknown_tool", "outside_record", "race_duplicate_records", "race_duplicate_keys"])
def test_graph_manifest_rejects_unsafe_or_ambiguous_actions(tmp_path, problem):
    manifest = copy.deepcopy(generate_graph_manifest(7, 40, nodes=16, width=4))
    if problem == "cycle":
        manifest["graph"]["GR-000"] = ["GR-015"]
    elif problem == "outside_edge":
        manifest["graph"]["GR-015"] = ["PAY-001"]
    elif problem == "unknown_tool":
        manifest["actions"][0]["tool"] = "execute_command"
    elif problem == "outside_record":
        manifest["actions"][0]["arguments"]["record_id"] = "../../outside"
    else:
        race = next(action for action in manifest["actions"] if action["kind"] == "race")
        if problem == "race_duplicate_records":
            race["requests"][1]["updates"][1]["record_id"] = race["requests"][1]["updates"][0]["record_id"]
        else:
            race["requests"][1]["idempotency_key"] = race["requests"][0]["idempotency_key"]
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError):
        read_manifest(path)


@pytest.mark.parametrize("mode", ["vulnerable", "hardened"])
@pytest.mark.parametrize("transport", ["stdio", "sse"])
def test_graph_campaign_checks_state_receipts_notifications_and_legal_races(tmp_path, mode, transport):
    rows = asyncio.run(campaign_matrix(tmp_path / "graph-campaign", mode, transport, seed=11, steps=40,
                                       graph_nodes=16, graph_width=4, parallel_calls=8))
    failures = [row for row in rows if not row["passed"]]
    assert not failures, failures
    assert len(rows) == 40
    assert all(row["state_matches_oracle"] and row["resource_notifications_match"] and row["catalog_notifications_match"] for row in rows)
    race = next(row for row in rows if row["action"]["label"] == "overlapping_root_resolutions")
    assert race["expected"]["accepted"] == (1 if mode == "hardened" else 8)
    retry = next(row for row in rows if row["action"]["label"] == "lost_ack_retry")
    if mode == "hardened":
        assert retry["responses"][0]["structuredContent"]["deduplicated"] is True
        assert retry["notifications"] == []


@pytest.mark.parametrize("nodes,width,parallel", [(32, 4, 16), (64, 8, 24), (128, 4, 32)])
def test_hardened_graph_stress_at_larger_sizes(tmp_path, nodes, width, parallel):
    rows = asyncio.run(campaign_matrix(tmp_path / "stress", "hardened", "stdio", seed=7, steps=80,
                                       graph_nodes=nodes, graph_width=width, parallel_calls=parallel))
    assert not [row for row in rows if not row["passed"]]
    completed = next(row for row in rows if row["action"]["label"] == "completed_analysis")
    assert completed["responses"][0]["structuredContent"]["unresolved"] == []
    assert max(row["receipt_count"] for row in rows) >= (nodes + 15) // 16


def test_dependency_graph_campaign_can_replay_saved_manifest(tmp_path):
    original = asyncio.run(campaign_matrix(tmp_path / "original", "hardened", "stdio", seed=11, steps=40,
                                           graph_nodes=16, graph_width=4, parallel_calls=8))
    repeated = asyncio.run(campaign_matrix(tmp_path / "replay", "hardened", "stdio",
                                           manifest_path=tmp_path / "original" / "campaign.json"))
    assert [row["action"] for row in original] == [row["action"] for row in repeated]
    assert all(row["passed"] for row in repeated)
    # Race winners may differ, but every result must match a legal serialization.
    assert [row["receipt_count"] for row in original] == [row["receipt_count"] for row in repeated]


@pytest.mark.parametrize("mode,transport,nodes,width,parallel", [
    ("hardened", "stdio", 128, 8, 32), ("vulnerable", "sse", 32, 4, 16),
    ("hardened", "streamable-http", 64, 8, 24), ("vulnerable", "streamable-http", 64, 8, 24)])
def test_mixed_write_sets_and_root_churn_campaign(tmp_path, mode, transport, nodes, width, parallel):
    rows = asyncio.run(campaign_matrix(tmp_path / "mixed", mode, transport, seed=19, steps=100,
        graph_nodes=nodes, graph_width=width, parallel_calls=parallel, race_topology="mixed", root_churn=True))
    assert not [row["case"] for row in rows if not row["passed"]]
    race = next(row for row in rows if row["action"]["kind"] == "race")
    sets = [set(item["record_id"] for item in request["updates"]) for request in race["action"]["requests"]]
    assert any(a.isdisjoint(b) for a in sets for b in sets)
    assert any(a & b and a != b for a in sets for b in sets)
    assert race["expected"]["serialization_verified"]
    assert {row["action"]["notify"] for row in rows if row["action"]["kind"] == "guided_drift"} == {True, False}
    assert all(row["root_change_verified"] for row in rows if row["action"]["kind"] == "roots_change")


@pytest.mark.parametrize("hardened", [True, False])
@pytest.mark.parametrize("seed", range(8))
def test_race_oracle_matches_real_store_for_arbitrary_overlaps_and_replays(tmp_path, hardened, seed):
    graph = {f"GR-{index:03}": [] for index in range(8)}
    _, config = create_fixture(tmp_path, dense=True, dependency_graph=graph)
    config["faults"] = {}
    state = json.loads(Path(config["state_path"]).read_text())
    for key in graph:
        state["records"][key].update(status="investigating", version=2)
    Path(config["state_path"]).write_text(json.dumps(state))
    oracle, store, rng = GraphOracle(config, hardened), IncidentStore(config, lambda *a, **kw: None), random.Random(seed)
    requests = [{"updates": [{"record_id": key, "expected_version": 2, "status": "resolved"}
                 for key in rng.sample(list(graph), rng.randint(1, 6))],
                 "handle": WRITE_HANDLE if index % 5 else "synthetic-read-handle", "idempotency_key": f"race-{index}"}
                for index in range(24)]
    async def run():
        for _ in range(2):
            results = [None] * len(requests)
            order = list(range(len(requests)))
            rng.shuffle(order)
            for index in order:
                try:
                    value = await store.batch_update(requests[index], hardened)
                    results[index] = types.CallToolResult(content=[], structuredContent=value)
                except Denied:
                    results[index] = types.CallToolResult(content=[], isError=True)
            published = json.loads(Path(config["state_path"]).read_text())
            valid, serialization, _ = verify_race(oracle, requests, results, published["receipts"])
            assert valid and sorted(serialization) == list(range(len(requests)))
            assert published == {"records": oracle.records, "receipts": oracle.receipts}
    asyncio.run(run())


@pytest.mark.parametrize("child_first", [True, False])
def test_race_oracle_orders_disjoint_dependency_commits_and_early_rejections(tmp_path, child_first):
    graph = {"GR-000": [], "GR-001": ["GR-000"], "GR-002": [], "GR-003": []}
    _, config = create_fixture(tmp_path, dense=True, dependency_graph=graph)
    config["faults"] = {}
    state = json.loads(Path(config["state_path"]).read_text())
    for key in graph:
        state["records"][key].update(status="investigating", version=2)
    Path(config["state_path"]).write_text(json.dumps(state))
    oracle, store = GraphOracle(config, True), IncidentStore(config, lambda *a, **kw: None)
    # Request array deliberately puts the dependent before its prerequisite.
    requests = [{"updates": [{"record_id": key, "expected_version": 2, "status": "resolved"}],
                 "handle": WRITE_HANDLE, "idempotency_key": key} for key in ("GR-001", "GR-000")]
    async def run():
        results = [None, None]
        for index in ([0, 1] if child_first else [1, 0]):
            try:
                value = await store.batch_update(requests[index], True)
                results[index] = types.CallToolResult(content=[], structuredContent=value)
            except Denied:
                results[index] = types.CallToolResult(content=[], isError=True)
        published = json.loads(Path(config["state_path"]).read_text())
        valid, order, _ = verify_race(oracle, requests, results, published["receipts"])
        assert valid and order == ([0, 1] if child_first else [1, 0])
        assert published == {"records": oracle.records, "receipts": oracle.receipts}
    asyncio.run(run())


@pytest.mark.parametrize("corruption", ["partial_batch", "duplicate_version", "cross_record_cycle"])
def test_race_oracle_rejects_inconsistent_atomic_commit_witnesses(tmp_path, corruption):
    graph = {f"GR-{index:03}": [] for index in range(4)}
    _, config = create_fixture(tmp_path, dense=True, dependency_graph=graph)
    oracle = GraphOracle(config, False)
    requests = [{"updates": [{"record_id": key, "expected_version": 1, "status": "investigating"}
                             for key in ("GR-000", "GR-001")],
                 "handle": WRITE_HANDLE, "idempotency_key": f"commit-{index}"} for index in range(2)]
    records = [[{"id": key, "status": "investigating", "version": index + 2}
                for key in ("GR-000", "GR-001")] for index in range(2)]
    if corruption == "partial_batch":
        records[0].pop()
    elif corruption == "duplicate_version":
        records[1][0]["version"] = 2
    else:
        records[0][1]["version"], records[1][1]["version"] = 3, 2
    results = [types.CallToolResult(content=[], structuredContent={"records": items, "deduplicated": False}) for items in records]
    valid, _, _ = verify_race(oracle, requests, results, {})
    assert not valid


def test_race_oracle_consumes_transient_fault_before_a_disjoint_commit(tmp_path):
    graph = {f"GR-{index:03}": [] for index in range(4)}
    _, config = create_fixture(tmp_path, dense=True, dependency_graph=graph)
    config["faults"] = {"batch_update_records": 1}
    oracle = GraphOracle(config, True)
    requests = [{"updates": [{"record_id": f"GR-{index:03}", "expected_version": 1, "status": "investigating"}],
                 "handle": WRITE_HANDLE, "idempotency_key": f"fault-{index}"} for index in range(2)]
    async def run():
        store = IncidentStore(config, lambda *a, **kw: None)
        value = await store.batch_update(requests[1], True)
        results = [types.CallToolResult(content=[], isError=True), types.CallToolResult(content=[], structuredContent=value)]
        published = json.loads(Path(config["state_path"]).read_text())
        valid, order, _ = verify_race(oracle, requests, results, published["receipts"])
        assert valid and order == [0, 1]
        assert oracle.faults == {"batch_update_records": 0}
        assert published == {"records": oracle.records, "receipts": oracle.receipts}
    asyncio.run(run())
