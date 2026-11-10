import asyncio
import json
import random
from pathlib import Path

import pytest

from simlab.controls import Denied
from simlab.fixtures import WRITE_HANDLE
from simlab.client import connect
from simlab.dependency_graph import generate_graph
from simlab.graph_campaign import GraphOracle, generate_graph_manifest, graph_campaign_matrix
from jsonschema import Draft202012Validator
from test_outage_recovery import DIAMOND, operations


def timeline_args(workers=2):
    return {"record_id": "GR-003", "max_parallel": workers, "durations": [
        {"record_id": "GR-000", "investigate_ms": 3, "resolve_ms": 7},
        {"record_id": "GR-001", "investigate_ms": 2, "resolve_ms": 13},
        {"record_id": "GR-002", "investigate_ms": 5, "resolve_ms": 4},
        {"record_id": "GR-003", "investigate_ms": 1, "resolve_ms": 6}]}


@pytest.mark.parametrize("workers", [1, 2, 3, 16])
def test_timed_schedule_respects_workers_dependencies_and_real_versions(tmp_path, workers):
    _, config, store, graph = operations(tmp_path)
    before = Path(config["state_path"]).read_bytes()
    result = graph.recovery_timeline(timeline_args(workers))
    assert result["total_work_ms"] == 41
    assert result["critical_path_ms"] == 29
    assert result["makespan_ms"] >= max(29, result["worker_lower_bound_ms"])
    assert result["makespan_ms"] == (41 if workers == 1 else result["makespan_ms"])
    assert Path(config["state_path"]).read_bytes() == before
    events = result["events"]
    assert len(events) == 8
    for event in events:
        assert 0 <= event["worker"] < workers and event["end_ms"] > event["start_ms"]
        peers = [other for other in events if other["worker"] == event["worker"] and other is not event]
        assert all(other["end_ms"] <= event["start_ms"] or event["end_ms"] <= other["start_ms"] for other in peers)
        if event["status"] == "resolved":
            parents = DIAMOND[event["record_id"]]
            assert all(next(item["end_ms"] for item in events if item["record_id"] == key and item["status"] == "resolved")
                       <= event["start_ms"] for key in parents)
    async def execute():
        for index, event in enumerate(sorted(events, key=lambda item: (item["end_ms"], item["start_ms"], item["record_id"]))):
            await store.update({key: event[key] for key in ("record_id", "expected_version", "status")} |
                               {"handle": WRITE_HANDLE, "idempotency_key": f"timeline-{index}"}, True)
    asyncio.run(execute())
    assert all(store.read(key)["status"] == "resolved" for key in DIAMOND)
    empty = graph.recovery_timeline(timeline_args(workers))
    assert empty["events"] == [] and empty["makespan_ms"] == empty["critical_path_ms"] == 0


def test_bottleneck_ranking_counts_shared_descendants_once_and_tracks_work(tmp_path):
    _, _, store, graph = operations(tmp_path)
    result = graph.rank_bottlenecks({"record_id": "GR-003", "limit": 3})
    assert [row["record_id"] for row in result["ranking"]] == ["GR-000", "GR-001", "GR-002"]
    assert result["ranking"][0] == {"record_id": "GR-000", "impacted_count": 4,
        "direct_dependents": 2, "unresolved_dependents": 3, "downstream_depth": 2}
    asyncio.run(store.update({"record_id": "GR-000", "status": "investigating", "expected_version": 1,
                             "handle": WRITE_HANDLE, "idempotency_key": "changed"}, True))
    assert graph.rank_bottlenecks({"record_id": "GR-003", "limit": 1})["snapshot"][0]["version"] == 2


def test_simultaneous_completions_release_join_only_after_both_parents(tmp_path):
    _, _, _, graph = operations(tmp_path)
    result = graph.recovery_timeline({"record_id": "GR-003", "max_parallel": 16, "durations": []})
    assert result["makespan_ms"] == result["critical_path_ms"] == 4
    assert next(event for event in result["events"] if event["record_id"] == "GR-003" and event["status"] == "resolved")["start_ms"] == 3


def test_competing_writer_invalidates_timeline_update(tmp_path):
    _, _, store, graph = operations(tmp_path)
    event = graph.recovery_timeline(timeline_args())["events"][0]
    update = {key: event[key] for key in ("record_id", "status", "expected_version")} | {"handle": WRITE_HANDLE}
    asyncio.run(store.update({**update, "idempotency_key": "competitor"}, True))
    with pytest.raises(Denied, match="version_conflict"):
        asyncio.run(store.update({**update, "idempotency_key": "stale-timeline"}, True))


@pytest.mark.parametrize("problem", ["protected", "missing", "cycle"])
@pytest.mark.parametrize("method", ["recovery_timeline", "rank_bottlenecks"])
def test_timed_analysis_rejects_invalid_or_protected_prerequisites(tmp_path, method, problem):
    _, config, _, graph = operations(tmp_path)
    config["dependencies"]["GR-000"] = [{"protected": "PAY-001", "missing": "ABS-999", "cycle": "GR-003"}[problem]]
    with pytest.raises(Denied):
        getattr(graph, method)(timeline_args() if method == "recovery_timeline" else {"record_id": "GR-003", "limit": 3})


@pytest.mark.parametrize("problem", ["duplicate", "outside_closure", "protected", "zero", "workers"])
def test_timeline_rejects_invalid_duration_overrides(tmp_path, problem):
    _, _, _, graph = operations(tmp_path)
    args = timeline_args()
    if problem == "duplicate":
        args["durations"].append(dict(args["durations"][0]))
    elif problem in ("outside_closure", "protected"):
        args["durations"][0]["record_id"] = "INC-001" if problem == "outside_closure" else "PAY-001"
    elif problem == "zero":
        args["durations"][0]["resolve_ms"] = 0
    else:
        args["max_parallel"] = 17
    with pytest.raises(Denied):
        graph.recovery_timeline(args)


@pytest.mark.parametrize("nodes,workers", [(8, 1), (32, 3), (128, 16)])
@pytest.mark.parametrize("seed", [7, 23, 41])
def test_weighted_schedules_and_rankings_match_independent_reference(tmp_path, nodes, workers, seed):
    graph_data = generate_graph(seed, nodes, 4)
    _, config, store, graph = operations(tmp_path, graph_data)
    state = json.loads(Path(config["state_path"]).read_text())
    rng = random.Random(seed)
    for key in graph_data:
        state["records"][key].update(status=rng.choice(["open", "investigating", "resolved"]), version=rng.randint(1, 9))
    Path(config["state_path"]).write_text(json.dumps(state))
    reference = GraphOracle(config, True)
    target = sorted(graph_data)[-1]
    selected = sorted(reference.closure(target))
    args = {"record_id": target, "max_parallel": workers, "durations": [
        {"record_id": key, "investigate_ms": rng.randint(1, 1000), "resolve_ms": rng.randint(1, 1000)} for key in selected]}
    before = Path(config["state_path"]).read_bytes()
    timeline = graph.recovery_timeline(args)
    assert timeline == reference.call("simulate_recovery_timeline", args)["value"]
    assert timeline["makespan_ms"] >= max(timeline["critical_path_ms"], timeline["worker_lower_bound_ms"])
    rank_args = {"record_id": target, "limit": 20}
    assert graph.rank_bottlenecks(rank_args) == reference.call("rank_dependency_bottlenecks", rank_args)["value"]
    assert Path(config["state_path"]).read_bytes() == before
    async def execute():
        for index, event in enumerate(sorted(timeline["events"], key=lambda row: (row["end_ms"], row["start_ms"], row["record_id"]))):
            await store.update({key: event[key] for key in ("record_id", "status", "expected_version")} |
                               {"handle": WRITE_HANDLE, "idempotency_key": f"weighted-{index}"}, True)
    asyncio.run(execute())
    assert all(store.read(key)["status"] == "resolved" for key in selected)


@pytest.mark.parametrize("transport", ["stdio", "sse", "streamable-http"])
@pytest.mark.parametrize("mode", ["hardened", "vulnerable"])
def test_timed_tools_live_discovery_contracts_and_rejection_recovery(tmp_path, mode, transport):
    config_path, config, _, _ = operations(tmp_path)
    before = Path(config["state_path"]).read_bytes()
    async def run():
        prefix = "sim_" if mode == "hardened" else ""
        async with connect(config_path, mode, tmp_path / "wire.jsonl", transport) as session:
            tools = {tool.name: tool for tool in (await session.list_tools()).tools}
            for name, args in [("simulate_recovery_timeline", timeline_args()),
                               ("rank_dependency_bottlenecks", {"record_id": "GR-003", "limit": 4})]:
                tool = tools[prefix + name]
                assert tool.annotations.readOnlyHint and tool.annotations.idempotentHint
                result = await session.call_tool(prefix + name, args)
                assert not result.isError
                Draft202012Validator(tool.outputSchema).validate(result.structuredContent)
                protected = {**args, "record_id": "PAY-001"}
                if "durations" in protected:
                    protected["durations"] = []
                assert bool((await session.call_tool(prefix + name, protected)).isError) == (mode == "hardened")
            bad = await session.call_tool(prefix + "simulate_recovery_timeline", {**timeline_args(), "max_parallel": 0})
            assert bad.isError
            await session.send_ping()
    asyncio.run(run())
    assert Path(config["state_path"]).read_bytes() == before


@pytest.mark.parametrize("mode,transport", [("hardened", "stdio"), ("vulnerable", "sse"), ("hardened", "streamable-http")])
def test_timed_campaign_replay_and_checkpoint_reconstruction(tmp_path, mode, transport):
    manifest = generate_graph_manifest(41, 80, nodes=16, width=4, parallel_calls=8, race_topology="mixed",
        root_churn=True, outage_stress=True, timeline_stress=True)
    stop = next(index + 1 for index, action in enumerate(manifest["actions"]) if action["label"] == "contended_recovery_timeline")
    source = tmp_path / "source"
    partial = asyncio.run(graph_campaign_matrix(source, mode, transport, manifest, stop_after=stop))
    assert all(row["passed"] for row in partial)
    rows = asyncio.run(graph_campaign_matrix(tmp_path / "continued", mode, transport, manifest, resume_checkpoint=source / "checkpoint.json"))
    assert len(rows) == 80 and all(row["passed"] for row in rows)


@pytest.mark.parametrize("mode", ["hardened", "vulnerable"])
def test_large_timeline_response_survives_stdio_buffer_boundary(tmp_path, mode):
    config_path, _, _, _ = operations(tmp_path, generate_graph(41, 128, 8))
    async def run():
        prefix = "sim_" if mode == "hardened" else ""
        async with connect(config_path, mode, tmp_path / "wire.jsonl", "stdio") as session:
            result = await session.call_tool(prefix + "simulate_recovery_timeline", {
                "record_id": "GR-127", "max_parallel": 16, "durations": []})
            assert not result.isError
            assert len(json.dumps(result.model_dump()).encode("utf-8")) > 65536
            assert len(result.structuredContent["events"]) == 242
            assert (await session.call_tool(prefix + "calculate", {"expression": "6*7"})).structuredContent == {"result": 42}
    asyncio.run(run())
