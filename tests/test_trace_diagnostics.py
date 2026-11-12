import copy
import json
import asyncio
import hashlib
import random
from pathlib import Path

import pytest

from simlab.trace_diagnostics import utilization
from test_outage_recovery import DIAMOND, operations
from test_resilience import scenario
from simlab.resilience import simulate
from simlab.client import connect
from simlab.controls import Denied
from simlab.dependency_graph import generate_graph
from simlab.graph_campaign import generate_graph_manifest, graph_campaign_matrix, GraphOracle, check_utilization_action
from simlab.checkpoint import canonical
from mcp import types
from jsonschema import Draft202012Validator


def test_worker_capacity_accounting_and_retry_wait_are_separate(tmp_path):
    _, config, _, _ = operations(tmp_path)
    records = json.loads(Path(config["state_path"]).read_text())["records"]
    args = scenario()
    trace = simulate(args, DIAMOND, records)
    result = utilization(args, trace)
    assert result["elapsed_ms"] == 5
    assert result["totals"] == {"capacity_ms": 10, "available_ms": 10, "busy_ms": 8, "productive_ms": 8,
        "failed_attempt_ms": 0, "outage_ms": 0, "idle_ms": 2, "utilization_basis_points": 8000}
    args["faults"] = [{"record_id": "GR-000", "status": "investigating", "failed_attempts": 1}]
    trace = simulate(args, DIAMOND, records)
    result = utilization(args, trace)
    assert result["totals"]["busy_ms"] == 9 and result["totals"]["failed_attempt_ms"] == 1
    assert result["retry_wait"] == {"required_backoff_ms": 2, "additional_wait_ms": 0}


def test_overlapping_outages_are_unioned_and_clipped_to_trace_horizon(tmp_path):
    _, config, _, _ = operations(tmp_path)
    records = json.loads(Path(config["state_path"]).read_text())["records"]
    args = scenario()
    args["worker_outages"] = [{"worker": 0, "start_ms": 0, "end_ms": 2}, {"worker": 0, "start_ms": 1, "end_ms": 4},
        {"worker": 1, "start_ms": 2, "end_ms": 3}, {"worker": 1, "start_ms": 15, "end_ms": 20}]
    trace = simulate(args, DIAMOND, records)
    result = utilization(args, trace)
    assert result["elapsed_ms"] == 7
    assert result["totals"]["outage_ms"] == 5 and result["totals"]["idle_ms"] == 1
    assert result["totals"]["utilization_basis_points"] == 8888


def test_diagnostics_reject_stale_or_forged_trace_and_preserve_state(tmp_path):
    _, config, _, graph = operations(tmp_path)
    args = scenario()
    trace = graph.recovery_resilience(args)
    before = Path(config["state_path"]).read_bytes()
    assert graph.recovery_utilization({"scenario": args, "trace": trace})["totals"]["productive_ms"] == 8
    forged = copy.deepcopy(trace)
    forged["attempts"][0]["expected_version"] += 1
    with pytest.raises(Denied, match="recovery_trace_invalid"):
        graph.recovery_utilization({"scenario": args, "trace": forged})
    assert Path(config["state_path"]).read_bytes() == before
    path = Path(config["state_path"])
    state = json.loads(before)
    state["records"]["GR-000"]["version"] += 1
    path.write_text(json.dumps(state))
    updated = path.read_bytes()
    with pytest.raises(Denied, match="recovery_trace_invalid"):
        graph.recovery_utilization({"scenario": args, "trace": trace})
    assert path.read_bytes() == updated


def test_empty_capacity_is_not_reported_as_zero_percent_utilization(tmp_path):
    _, config, _, graph = operations(tmp_path)
    path = Path(config["state_path"])
    state = json.loads(path.read_text())
    for key in DIAMOND:
        state["records"][key]["status"] = "resolved"
    path.write_text(json.dumps(state))
    args = scenario()
    trace = graph.recovery_resilience(args)
    result = graph.recovery_utilization({"scenario": args, "trace": trace})
    assert result["elapsed_ms"] == 0 and result["totals"]["capacity_ms"] == 0
    assert result["totals"]["utilization_basis_points"] is None
    assert all(row["utilization_basis_points"] is None for row in result["workers"])


def test_legal_queue_delays_are_separate_from_required_backoff(tmp_path):
    _, _, _, graph = operations(tmp_path)
    args = scenario()
    args["faults"] = [{"record_id": "GR-000", "status": "investigating", "failed_attempts": 1}]
    trace = graph.recovery_resilience(args)
    for event in trace["attempts"]:
        if event["start_ms"] >= 3:
            event["start_ms"] += 2
            event["end_ms"] += 2
    trace["elapsed_ms"] += 2
    result = graph.recovery_utilization({"scenario": args, "trace": trace})
    assert result["retry_wait"] == {"required_backoff_ms": 2, "additional_wait_ms": 2}


@pytest.mark.parametrize("nodes", [8, 32, 128])
@pytest.mark.parametrize("seed", [7, 23, 41])
def test_capacity_accounting_matches_independent_interval_sweep(tmp_path, nodes, seed):
    data = generate_graph(seed, nodes, 4)
    _, config, _, graph = operations(tmp_path, data)
    rng = random.Random(seed)
    root = sorted(data)[-1]
    args = {**scenario(), "record_id": root, "max_parallel": 3,
        "durations": [{"record_id": "GR-000", "investigate_ms": rng.randint(1, 10), "resolve_ms": rng.randint(1, 10)}],
        "faults": [{"record_id": "GR-000", "status": "investigating", "failed_attempts": 2}],
        "worker_outages": [{"worker": 0, "start_ms": 0, "end_ms": 2}, {"worker": 0, "start_ms": 1, "end_ms": 5},
                           {"worker": 1, "start_ms": 6, "end_ms": 8}]}
    before = Path(config["state_path"]).read_bytes()
    trace = graph.recovery_resilience(args)
    value = graph.recovery_utilization({"scenario": args, "trace": trace})
    oracle = GraphOracle(config, True)
    simulated = types.CallToolResult(content=[], structuredContent=trace)
    analyzed = types.CallToolResult(content=[], structuredContent=value)
    assert check_utilization_action(oracle, {"arguments": args}, simulated, analyzed)
    for row in [*value["workers"], value["totals"]]:
        assert row["capacity_ms"] == row["busy_ms"] + row["outage_ms"] + row["idle_ms"]
        assert row["busy_ms"] == row["productive_ms"] + row["failed_attempt_ms"]
    forged = copy.deepcopy(analyzed)
    forged.structuredContent["totals"]["outage_ms"] += 1
    assert not check_utilization_action(oracle, {"arguments": args}, simulated, forged)
    assert Path(config["state_path"]).read_bytes() == before


@pytest.mark.parametrize("mode", ["hardened", "vulnerable"])
@pytest.mark.parametrize("transport", ["stdio", "sse", "streamable-http"])
def test_utilization_live_contract_authority_and_rejection_recovery(tmp_path, mode, transport):
    config_path, config, _, _ = operations(tmp_path)
    before = Path(config["state_path"]).read_bytes()
    async def run():
        prefix, args = "sim_" if mode == "hardened" else "", scenario()
        async with connect(config_path, mode, tmp_path / "wire.jsonl", transport) as session:
            tool = next(tool for tool in (await session.list_tools()).tools if tool.name == prefix + "analyze_recovery_utilization")
            assert tool.annotations.readOnlyHint and tool.annotations.idempotentHint
            trace = (await session.call_tool(prefix + "simulate_recovery_resilience", args)).structuredContent
            result = await session.call_tool(prefix + "analyze_recovery_utilization", {"scenario": args, "trace": trace})
            assert not result.isError and result.structuredContent["totals"]["busy_ms"] == 8
            Draft202012Validator(tool.outputSchema).validate(result.structuredContent)
            forged = copy.deepcopy(trace);forged["completed"] = False
            assert (await session.call_tool(prefix + "analyze_recovery_utilization", {"scenario": args, "trace": forged})).isError
            protected = {**args, "record_id": "PAY-001"}
            outside = await session.call_tool(prefix + "simulate_recovery_resilience", protected)
            result = await session.call_tool(prefix + "analyze_recovery_utilization", {"scenario": protected, "trace": outside.structuredContent or {}})
            assert bool(result.isError) == (mode == "hardened")
            await session.send_ping()
    asyncio.run(run())
    assert Path(config["state_path"]).read_bytes() == before


@pytest.mark.parametrize("mode,transport", [("hardened", "stdio"), ("vulnerable", "sse"), ("hardened", "streamable-http")])
def test_utilization_campaigns_resume_rechecked_capacity_evidence(tmp_path, mode, transport):
    manifest = generate_graph_manifest(7, 40, nodes=8, width=2, utilization_stress=True)
    source = tmp_path / "source"
    partial = asyncio.run(graph_campaign_matrix(source, mode, transport, manifest, stop_after=3))
    assert all(row["passed"] for row in partial)
    rows = asyncio.run(graph_campaign_matrix(tmp_path / "continued", mode, transport, manifest, resume_checkpoint=source / "checkpoint.json"))
    assert len(rows) == 40 and all(row["passed"] for row in rows)


@pytest.mark.parametrize("field", ["capacity", "retry"])
def test_rehashed_checkpoint_cannot_forge_capacity_or_retry_metrics(tmp_path, field):
    manifest = generate_graph_manifest(7, 40, nodes=8, width=2, utilization_stress=True)
    source = tmp_path / "source"
    rows = asyncio.run(graph_campaign_matrix(source, "hardened", "stdio", manifest, stop_after=3))
    assert all(row["passed"] for row in rows)
    path = source / "checkpoint.json"
    envelope = json.loads(path.read_text())
    value = envelope["payload"]["rows"][-1]["responses"][1]["structuredContent"]
    if field == "capacity":
        value["totals"]["outage_ms"] += 1
    else:
        value["retry_wait"]["additional_wait_ms"] += 1
    envelope["sha256"] = hashlib.sha256(canonical(envelope["payload"])).hexdigest()
    path.write_text(json.dumps(envelope))
    with pytest.raises(ValueError, match="utilization fails interval sweep"):
        asyncio.run(graph_campaign_matrix(tmp_path / "rejected", "hardened", "stdio", manifest, resume_checkpoint=path))
