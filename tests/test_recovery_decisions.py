import asyncio
import copy
import json
import random
import hashlib
from pathlib import Path

import pytest

from simlab.controls import Denied
from simlab.recovery_decisions import compare, deadlines
from simlab.resilience import simulate
from simlab.recovery_decisions import strategy_scenario
from simlab.client import connect
from simlab.dependency_graph import generate_graph
from simlab.graph_campaign import generate_graph_manifest, graph_campaign_matrix, GraphOracle, check_strategy_action
from simlab.checkpoint import canonical
from mcp import types
from jsonschema import Draft202012Validator
from test_outage_recovery import DIAMOND, operations
from test_resilience import scenario


def comparison_args():
    base = scenario()
    base["faults"] = [{"record_id": "GR-000", "status": "investigating", "failed_attempts": 1}]
    return {"scenario": base, "deadline_ms": 100, "strategies": [
        {"label": "fragile", "max_parallel": 1, "max_attempts": 1, "retry_backoff_ms": 0},
        {"label": "resilient", "max_parallel": 3, "max_attempts": 3, "retry_backoff_ms": 1}]}


def test_comparison_uses_one_snapshot_and_never_prefers_fast_failed_recovery(tmp_path):
    _, config, _, _ = operations(tmp_path)
    records = json.loads(Path(config["state_path"]).read_text())["records"]
    args = comparison_args()
    original = copy.deepcopy(args)
    result = compare(args, DIAMOND, records)
    assert result["best_strategy"] == "resilient"
    assert result["strategies"][0]["completed"] is False
    assert result["strategies"][0]["deadline_met"] is False
    assert result["strategies"][1]["completed"] and result["strategies"][1]["deadline_met"]
    assert args == original
    reordered = compare({**args, "strategies": list(reversed(args["strategies"]))}, DIAMOND, records)
    assert reordered["best_strategy"] == result["best_strategy"]


def test_deadlines_distinguish_met_late_exhausted_and_blocked(tmp_path):
    _, config, _, _ = operations(tmp_path)
    records = json.loads(Path(config["state_path"]).read_text())["records"]
    args = scenario()
    trace = simulate(args, DIAMOND, records)
    targets = [{"record_id": "GR-000", "deadline_ms": 100}, {"record_id": "GR-003", "deadline_ms": 0}]
    scored = deadlines(trace, targets)
    assert [row["outcome"] for row in scored["targets"]] == ["met", "late"]
    assert scored["met_count"] == scored["late_count"] == 1 and scored["unfinished_count"] == 0
    finish = next(row["end_ms"] for row in trace["attempts"] if row["record_id"] == "GR-003" and row["status"] == "resolved")
    exact = deadlines(trace, [{"record_id": "GR-003", "deadline_ms": finish}])
    assert exact["all_met"] and exact["targets"][0]["lateness_ms"] == 0
    args.update(max_attempts=1, faults=[{"record_id": "GR-000", "status": "investigating", "failed_attempts": 1}])
    trace = simulate(args, DIAMOND, records)
    scored = deadlines(trace, targets)
    assert scored["unfinished_count"] == 2
    assert [row["cause"] for row in scored["targets"]] == ["attempts_exhausted", "dependency_blocked"]
    assert all(row["completion_ms"] is None and row["lateness_ms"] is None for row in scored["targets"])


def test_deadline_tool_requires_current_legal_evidence(tmp_path):
    _, config, store, graph = operations(tmp_path)
    args = scenario()
    trace = graph.recovery_resilience(args)
    request = {"scenario": args, "trace": trace, "deadlines": [{"record_id": "GR-003", "deadline_ms": 100}]}
    assert graph.evaluate_deadlines(request)["all_met"]
    forged = copy.deepcopy(request)
    forged["trace"]["completed"] = False
    with pytest.raises(Denied, match="recovery_trace_invalid"):
        graph.evaluate_deadlines(forged)
    first = next(row for row in trace["attempts"] if row["outcome"] == "succeeded")
    from simlab.fixtures import WRITE_HANDLE
    asyncio.run(store.update({key: first[key] for key in ("record_id", "status", "expected_version")} |
                             {"handle": WRITE_HANDLE, "idempotency_key": "competing-writer"}, True))
    with pytest.raises(Denied, match="recovery_trace_invalid"):
        graph.evaluate_deadlines(request)


def test_comparison_ties_empty_work_and_all_failed_candidates(tmp_path):
    _, config, _, _ = operations(tmp_path)
    records = json.loads(Path(config["state_path"]).read_text())["records"]
    args = comparison_args()
    args["strategies"] = [{"label": label, "max_parallel": 1, "max_attempts": 1, "retry_backoff_ms": 0} for label in ("z", "a")]
    assert compare(args, DIAMOND, records)["best_strategy"] is None
    for key in DIAMOND:
        records[key]["status"] = "resolved"
    args["deadline_ms"] = 0
    result = compare(args, DIAMOND, records)
    assert result["best_strategy"] == "a"
    assert all(row["deadline_met"] and row["elapsed_ms"] == 0 for row in result["strategies"])


@pytest.mark.parametrize("problem", ["labels", "worker", "too_many", "duplicate_deadlines", "outside_deadline", "negative_deadline"])
def test_decision_tools_reject_ambiguous_or_out_of_scope_inputs(tmp_path, problem):
    _, _, _, graph = operations(tmp_path)
    args = comparison_args()
    if problem == "labels":
        args["strategies"][1]["label"] = args["strategies"][0]["label"]
    elif problem == "worker":
        args["scenario"]["worker_outages"] = [{"worker": 1, "start_ms": 0, "end_ms": 2}]
    elif problem == "too_many":
        args["strategies"] *= 5
    else:
        trace = graph.recovery_resilience(args["scenario"])
        targets = [{"record_id": "GR-003", "deadline_ms": 100}]
        if problem == "duplicate_deadlines":
            targets *= 2
        elif problem == "outside_deadline":
            targets[0]["record_id"] = "INC-001"
        else:
            targets[0]["deadline_ms"] = -1
        with pytest.raises(Denied):
            graph.evaluate_deadlines({"scenario": args["scenario"], "trace": trace, "deadlines": targets})
        return
    with pytest.raises(Denied):
        graph.compare_strategies(args)


@pytest.mark.parametrize("nodes", [8, 32, 128])
@pytest.mark.parametrize("seed", [7, 23, 41])
def test_strategy_metrics_and_deadlines_match_independent_witnesses(tmp_path, nodes, seed):
    data = generate_graph(seed, nodes, 4)
    _, config, _, graph = operations(tmp_path, data)
    rng = random.Random(seed)
    args = comparison_args()
    args["scenario"].update(record_id=sorted(data)[-1], faults=[{"record_id": "GR-000", "status": "resolved", "failed_attempts": 2}],
        durations=[{"record_id": "GR-000", "investigate_ms": rng.randint(1, 20), "resolve_ms": rng.randint(1, 20)}])
    action = {"kind": "strategy", "arguments": args, "deadlines": [{"record_id": "GR-000", "deadline_ms": 10},
        {"record_id": args["scenario"]["record_id"], "deadline_ms": 1000}], "tamper": False}
    before = Path(config["state_path"]).read_bytes()
    compared = graph.compare_strategies(args)
    variants = [strategy_scenario(args["scenario"], row) for row in args["strategies"]]
    witnesses = [graph.recovery_resilience(variant) for variant in variants]
    evaluated = [graph.evaluate_deadlines({"scenario": variant, "trace": trace, "deadlines": action["deadlines"]})
                 for variant, trace in zip(variants, witnesses)]
    responses = [types.CallToolResult(content=[], structuredContent=value) for value in [compared, *witnesses, *evaluated]]
    oracle = GraphOracle(config, True)
    assert check_strategy_action(oracle, action, responses)
    forged = copy.deepcopy(responses)
    forged[0].structuredContent["best_strategy"] = "fragile"
    assert not check_strategy_action(oracle, action, forged)
    assert Path(config["state_path"]).read_bytes() == before


@pytest.mark.parametrize("mode", ["hardened", "vulnerable"])
@pytest.mark.parametrize("transport", ["stdio", "sse", "streamable-http"])
def test_decision_tools_live_discovery_contracts_and_authority(tmp_path, mode, transport):
    config_path, config, _, _ = operations(tmp_path)
    before = Path(config["state_path"]).read_bytes()
    async def run():
        prefix = "sim_" if mode == "hardened" else ""
        async with connect(config_path, mode, tmp_path / "wire.jsonl", transport) as session:
            tools = {tool.name: tool for tool in (await session.list_tools()).tools}
            args = comparison_args()
            compared = await session.call_tool(prefix + "compare_recovery_strategies", args)
            assert not compared.isError and compared.structuredContent["best_strategy"] == "resilient"
            trace = await session.call_tool(prefix + "simulate_recovery_resilience", args["scenario"])
            evaluated = await session.call_tool(prefix + "evaluate_recovery_deadlines", {"scenario": args["scenario"],
                "trace": trace.structuredContent, "deadlines": [{"record_id": "GR-003", "deadline_ms": 1000}]})
            assert not evaluated.isError and evaluated.structuredContent["all_met"]
            for name, result in [("compare_recovery_strategies", compared), ("evaluate_recovery_deadlines", evaluated)]:
                assert tools[prefix + name].annotations.readOnlyHint
                Draft202012Validator(tools[prefix + name].outputSchema).validate(result.structuredContent)
            protected = copy.deepcopy(args)
            protected["scenario"].update(record_id="PAY-001", faults=[])
            assert bool((await session.call_tool(prefix + "compare_recovery_strategies", protected)).isError) == (mode == "hardened")
            protected_trace = await session.call_tool(prefix + "simulate_recovery_resilience", protected["scenario"])
            protected_score = await session.call_tool(prefix + "evaluate_recovery_deadlines", {"scenario": protected["scenario"],
                "trace": protected_trace.structuredContent or {}, "deadlines": [{"record_id": "PAY-001", "deadline_ms": 100}]})
            assert bool(protected_score.isError) == (mode == "hardened")
            invalid = await session.call_tool(prefix + "evaluate_recovery_deadlines", {"scenario": args["scenario"],
                "trace": {}, "deadlines": [{"record_id": "GR-003", "deadline_ms": 1000}]})
            assert invalid.isError
            await session.send_ping()
    asyncio.run(run())
    assert Path(config["state_path"]).read_bytes() == before


@pytest.mark.parametrize("mode,transport", [("hardened", "stdio"), ("vulnerable", "sse"), ("hardened", "streamable-http")])
def test_decision_campaigns_resume_witnessed_policy_and_deadline_actions(tmp_path, mode, transport):
    manifest = generate_graph_manifest(23, 80, nodes=16, width=4, parallel_calls=8, strategy_stress=True, resilience_stress=True)
    source = tmp_path / "source"
    rows = asyncio.run(graph_campaign_matrix(source, mode, transport, manifest, stop_after=4))
    assert all(row["passed"] for row in rows)
    continued = asyncio.run(graph_campaign_matrix(tmp_path / "continued", mode, transport, manifest, resume_checkpoint=source / "checkpoint.json"))
    assert len(continued) == 80 and all(row["passed"] for row in continued)
    assert {row["action"]["tamper"] for row in continued if row["action"]["kind"] == "strategy"} == {True, False}


@pytest.mark.parametrize("field", ["winner", "deadline"])
def test_rehashed_checkpoint_cannot_forge_recovery_decisions(tmp_path, field):
    manifest = generate_graph_manifest(23, 60, nodes=8, width=2, parallel_calls=4, strategy_stress=True)
    source = tmp_path / "source"
    rows = asyncio.run(graph_campaign_matrix(source, "hardened", "stdio", manifest, stop_after=3))
    assert all(row["passed"] for row in rows)
    path = source / "checkpoint.json"
    envelope = json.loads(path.read_text())
    responses = envelope["payload"]["rows"][-1]["responses"]
    if field == "winner":
        responses[0]["structuredContent"]["best_strategy"] = "fragile"
    else:
        responses[3]["structuredContent"]["all_met"] = True
    envelope["sha256"] = hashlib.sha256(canonical(envelope["payload"])).hexdigest()
    path.write_text(json.dumps(envelope))
    with pytest.raises(ValueError, match="recovery decisions fail reference witnesses"):
        asyncio.run(graph_campaign_matrix(tmp_path / "rejected", "hardened", "stdio", manifest, resume_checkpoint=path))
