import asyncio
import copy
import json
import random
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from simlab.client import connect
from simlab.controls import Denied
from simlab.fixtures import WRITE_HANDLE, create_fixture
from simlab.graph_operations import GraphOperations
from simlab.state import IncidentStore
from simlab.dependency_graph import generate_graph
from simlab.graph_campaign import generate_graph_manifest, graph_campaign_matrix, GraphOracle


DIAMOND = {"GR-000": [], "GR-001": ["GR-000"], "GR-002": ["GR-000"],
           "GR-003": ["GR-001", "GR-002"]}


def operations(tmp_path, graph=DIAMOND):
    path, config = create_fixture(tmp_path, dense=True, dependency_graph=graph)
    store = IncidentStore(config, lambda *a, **kw: None)
    return path, config, store, GraphOperations(store, config, True)


def test_failure_cascade_deduplicates_diamond_and_uses_shortest_explanation(tmp_path):
    _, config, _, graph = operations(tmp_path)
    before = Path(config["state_path"]).read_bytes()
    result = graph.failure_cascade({"failed_records": ["GR-002", "GR-000"]})
    assert result["failed_records"] == ["GR-000", "GR-002"]
    assert result["waves"] == [["GR-000", "GR-002"], ["GR-001", "GR-003"]]
    assert result["paths"]["GR-003"] == ["GR-002", "GR-003"]
    assert result["impacted_records"] == sorted(DIAMOND)
    assert Path(config["state_path"]).read_bytes() == before


@pytest.mark.parametrize("budget", [1, 2, 3, 16])
def test_recovery_waves_execute_with_real_versions_and_prerequisites(tmp_path, budget):
    _, config, store, graph = operations(tmp_path)
    plan = graph.plan_recovery({"record_id": "GR-003", "max_parallel": budget})
    assert plan["total_updates"] == 8
    assert all(0 < len(wave) <= budget for wave in plan["waves"])
    async def run():
        for index, wave in enumerate(plan["waves"]):
            # Distinct calls in each wave must be safe in any completion order.
            await asyncio.gather(*(store.update({**update, "handle": WRITE_HANDLE,
                "idempotency_key": f"{index}-{update['record_id']}"}, True) for update in reversed(wave)))
    asyncio.run(run())
    assert all(store.read(key)["status"] == "resolved" for key in DIAMOND)
    assert graph.plan_recovery({"record_id": "GR-003", "max_parallel": budget})["waves"] == []


def test_recovery_preview_is_invalidated_by_intervening_writer(tmp_path):
    _, _, store, graph = operations(tmp_path)
    first = graph.plan_recovery({"record_id": "GR-003", "max_parallel": 2})["waves"][0][0]
    asyncio.run(store.update({**first, "handle": WRITE_HANDLE, "idempotency_key": "competitor"}, True))
    with pytest.raises(Denied, match="version_conflict"):
        asyncio.run(store.update({**first, "handle": WRITE_HANDLE, "idempotency_key": "stale-plan"}, True))


@pytest.mark.parametrize("tool,args", [("failure_cascade", {"failed_records": ["PAY-001"]}),
    ("plan_recovery", {"record_id": "PAY-001", "max_parallel": 1}),
    ("failure_cascade", {"failed_records": ["GR-000", "GR-000"]}),
    ("plan_recovery", {"record_id": "GR-003", "max_parallel": 0})])
def test_graph_operations_enforce_authority_and_bounded_inputs(tmp_path, tool, args):
    _, _, _, graph = operations(tmp_path)
    with pytest.raises(Denied):
        getattr(graph, tool)(args)


@pytest.mark.parametrize("problem", ["protected", "missing", "cycle"])
@pytest.mark.parametrize("method,args", [("failure_cascade", {"failed_records": ["GR-000"]}),
                                        ("plan_recovery", {"record_id": "GR-003", "max_parallel": 2})])
def test_graph_previews_reject_invalid_or_protected_prerequisite_closures(tmp_path, problem, method, args):
    _, config, _, graph = operations(tmp_path)
    config["dependencies"]["GR-000"] = [{"protected": "PAY-001", "missing": "ABS-999", "cycle": "GR-003"}[problem]]
    with pytest.raises(Denied):
        getattr(graph, method)(args)


@pytest.mark.parametrize("transport", ["stdio", "sse", "streamable-http"])
@pytest.mark.parametrize("mode", ["hardened", "vulnerable"])
def test_new_graph_tools_are_discoverable_structured_and_read_only(tmp_path, transport, mode):
    config_path, config, _, _ = operations(tmp_path)
    before = Path(config["state_path"]).read_bytes()
    async def run():
        prefix = "sim_" if mode == "hardened" else ""
        async with connect(config_path, mode, tmp_path / "wire.jsonl", transport) as session:
            tools = {tool.name: tool for tool in (await session.list_tools()).tools}
            for name, args in [("simulate_dependency_outage", {"failed_records": ["GR-000"]}),
                               ("plan_recovery", {"record_id": "GR-003", "max_parallel": 2})]:
                tool = tools[prefix + name]
                assert tool.annotations.readOnlyHint and tool.annotations.idempotentHint
                result = await session.call_tool(prefix + name, args)
                assert not result.isError
                Draft202012Validator(tool.outputSchema).validate(result.structuredContent)
            denied = await session.call_tool(prefix + "simulate_dependency_outage", {"failed_records": ["PAY-001"]})
            assert bool(denied.isError) == (mode == "hardened")
            await session.send_ping()
    asyncio.run(run())
    assert Path(config["state_path"]).read_bytes() == before


@pytest.mark.parametrize("seed", range(6))
@pytest.mark.parametrize("budget", [1, 5, 16])
def test_dense_randomized_plans_execute_and_outages_match_transitive_reachability(tmp_path, seed, budget):
    graph = generate_graph(seed, 128, 8)
    _, config, store, operations_graph = operations(tmp_path, graph)
    rng = random.Random(seed)
    state = json.loads(Path(config["state_path"]).read_text())
    for key in graph:
        state["records"][key].update(status=rng.choice(["open", "investigating"]), version=rng.randint(1, 9))
    Path(config["state_path"]).write_text(json.dumps(state))
    before = Path(config["state_path"]).read_bytes()
    failures = rng.sample(sorted(graph), 16)
    outage = operations_graph.failure_cascade({"failed_records": failures})
    affected = set(failures)
    while True:
        expanded = affected | {key for key, parents in graph.items() if affected.intersection(parents)}
        if expanded == affected:
            break
        affected = expanded
    assert set(outage["impacted_records"]) == affected
    for key, path in outage["paths"].items():
        assert path[0] in failures and path[-1] == key
        assert all(parent in graph[child] for parent, child in zip(path, path[1:]))
    args = {"record_id": "GR-127", "max_parallel": budget}
    plan = operations_graph.plan_recovery(args)
    reference = GraphOracle(config, True)
    assert plan == reference.call("plan_recovery", args)["value"]
    assert Path(config["state_path"]).read_bytes() == before
    async def execute():
        for index, wave in enumerate(plan["waves"]):
            shuffled = copy.deepcopy(wave)
            rng.shuffle(shuffled)
            await asyncio.gather(*(store.update({**update, "handle": WRITE_HANDLE,
                "idempotency_key": f"recovery-{index}-{update['record_id']}"}, True) for update in shuffled))
    asyncio.run(execute())
    assert all(store.read(record["id"])["status"] == "resolved" for record in plan["snapshot"])


@pytest.mark.parametrize("mode,transport", [("hardened", "stdio"), ("vulnerable", "sse"),
                                           ("hardened", "streamable-http"), ("vulnerable", "streamable-http")])
def test_outage_campaigns_replay_and_resume_with_full_oracle(tmp_path, mode, transport):
    manifest = generate_graph_manifest(23, 70, nodes=32, width=8, parallel_calls=24,
        race_topology="mixed", root_churn=True, outage_stress=True)
    assert manifest == generate_graph_manifest(23, 70, nodes=32, width=8, parallel_calls=24,
        race_topology="mixed", root_churn=True, outage_stress=True)
    stop = next(index + 1 for index, action in enumerate(manifest["actions"]) if action["label"] == "mid_graph_outage")
    source = tmp_path / "source"
    partial = asyncio.run(graph_campaign_matrix(source, mode, transport, manifest, stop_after=stop))
    assert all(row["passed"] for row in partial)
    rows = asyncio.run(graph_campaign_matrix(tmp_path / "continued", mode, transport, manifest,
        resume_checkpoint=source / "checkpoint.json"))
    assert len(rows) == 70 and all(row["passed"] for row in rows)
    assert {row["action"]["label"] for row in rows} >= {"root_outage", "mid_graph_outage", "initial_recovery_plan",
        "constrained_recovery_plan", "protected_outage_probe", "completed_recovery_plan"}
