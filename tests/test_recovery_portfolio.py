import asyncio
import copy
import hashlib
import json
import random
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from mcp import types

from simlab.checkpoint import canonical
from simlab.client import connect
from simlab.controls import Denied, Firewall
from simlab.dependency_graph import generate_graph
from simlab.fixtures import CATALOG_HANDLE
from simlab.graph_campaign import (GraphOracle, check_portfolio_action, generate_graph_manifest,
                                  graph_campaign_matrix, validate_graph_manifest)
from simlab.portfolio_oracle import witnesses
from simlab.recovery_portfolio import PORTFOLIO_OUTPUT, TRACE_COMPARISON_OUTPUT
from simlab.resilience import closure
from test_outage_recovery import operations
from test_resilience import scenario


def arguments():
    base = scenario()
    base["faults"] = [{"record_id": "GR-000", "status": "investigating", "failed_attempts": 1}]
    return {"scenarios": [{"label": "fault", "scenario": base}, {"label": "clean", "scenario": scenario()}],
        "strategies": [{"label": "fragile", "max_parallel": 1, "max_attempts": 1, "retry_backoff_ms": 0},
                       {"label": "resilient", "max_parallel": 2, "max_attempts": 3, "retry_backoff_ms": 2}],
        "deadline_ms": 100, "max_worker_busy_ms": 100}


def pair(graph, left=None, right=None):
    left, right = left or scenario(), right or scenario()
    return {"baseline": {"scenario": left, "trace": graph.recovery_resilience(left)},
            "candidate": {"scenario": right, "trace": graph.recovery_resilience(right)}, "deadline_ms": 100}


def test_portfolio_requires_feasibility_in_every_scenario_and_preserves_inputs(tmp_path):
    _, config, _, graph = operations(tmp_path)
    args = arguments()
    original = copy.deepcopy(args)
    before = Path(config["state_path"]).read_bytes()
    result = graph.recovery_portfolio(args)
    Draft202012Validator(PORTFOLIO_OUTPUT).validate(result)
    assert result["robust_strategy"] == "resilient"
    # A failing policy can remain on the frontier because it spends less work;
    # feasibility in every scenario is a separate requirement for recommendation.
    assert result["pareto_strategies"] == ["fragile", "resilient"]
    fragile = result["strategies"][0]
    assert fragile["completed_count"] == fragile["eligible_count"] == 1
    assert fragile["worst_elapsed_ms"] is None
    assert args == original and Path(config["state_path"]).read_bytes() == before
    args["scenarios"].reverse();args["strategies"].reverse()
    assert graph.recovery_portfolio(args) == result
    for sample in args["scenarios"]:
        sample["scenario"]["faults"] = []
    assert graph.recovery_portfolio(args)["pareto_strategies"] == ["resilient"]


@pytest.mark.parametrize("constraint", ["deadline_ms", "max_worker_busy_ms"])
def test_portfolio_never_recommends_a_policy_outside_deadline_or_budget(tmp_path, constraint):
    _, _, _, graph = operations(tmp_path)
    args = arguments();args[constraint] = 0
    result = graph.recovery_portfolio(args)
    assert result["robust_strategy"] is None
    assert not any(row["eligible"] for row in result["cells"])
    assert any(row["completed"] for row in result["cells"])


def test_portfolio_empty_work_ties_and_full_64_cell_bound(tmp_path):
    _, config, _, graph = operations(tmp_path)
    path = Path(config["state_path"])
    data = json.loads(path.read_text())
    for key in graph.config["dependencies"]:
        data["records"][key]["status"] = "resolved"
    path.write_text(json.dumps(data))
    args = arguments()
    args["scenarios"] = [{"label": f"s{i}", "scenario": scenario()} for i in range(8)]
    args["strategies"] = [{"label": f"p{i}", "max_parallel": i+1, "max_attempts": 1, "retry_backoff_ms": 0} for i in range(8)]
    args["deadline_ms"] = args["max_worker_busy_ms"] = 0
    result = graph.recovery_portfolio(args)
    assert len(result["cells"]) == 64 and result["robust_strategy"] == "p0"
    assert result["pareto_strategies"] == [f"p{i}" for i in range(8)]
    assert all(row["eligible"] and row["elapsed_ms"] == 0 for row in result["cells"])


def test_whole_valued_json_numbers_have_identical_analysis_results(tmp_path):
    _, _, _, graph = operations(tmp_path)
    def whole_floats(value):
        if isinstance(value, dict): return {key: whole_floats(item) for key, item in value.items()}
        if isinstance(value, list): return [whole_floats(item) for item in value]
        return float(value) if type(value) is int else value
    args = arguments()
    assert graph.recovery_portfolio(whole_floats(args)) == graph.recovery_portfolio(args)
    request = pair(graph)
    assert graph.compare_recovery_traces(whole_floats(request)) == graph.compare_recovery_traces(request)


def test_nested_analysis_cannot_expose_a_hidden_prerequisite(tmp_path):
    _, config, _, graph = operations(tmp_path)
    request = pair(graph)
    config["allowed_records"].remove("GR-000")
    with pytest.raises(Denied): graph.recovery_portfolio(arguments())
    with pytest.raises(Denied): graph.compare_recovery_traces(request)


@pytest.mark.parametrize("problem", ["scenario_labels", "policy_labels", "targets", "outage_worker", "outage_interval", "override", "too_many"])
def test_portfolio_rejects_ambiguous_invalid_or_unbounded_inputs(tmp_path, problem):
    _, _, _, graph = operations(tmp_path)
    args = arguments()
    if problem == "scenario_labels": args["scenarios"][1]["label"] = args["scenarios"][0]["label"]
    elif problem == "policy_labels": args["strategies"][1]["label"] = args["strategies"][0]["label"]
    elif problem == "targets": args["scenarios"][1]["scenario"]["record_id"] = "GR-000"
    elif problem == "outage_worker": args["scenarios"][0]["scenario"]["worker_outages"] = [{"worker": 1, "start_ms": 0, "end_ms": 1}]
    elif problem == "outage_interval": args["scenarios"][0]["scenario"]["worker_outages"] = [{"worker": 0, "start_ms": 5, "end_ms": 1}]
    elif problem == "override": args["scenarios"][0]["scenario"]["durations"] = [{"record_id": "PAY-001", "investigate_ms": 2, "resolve_ms": 2}]
    else: args["scenarios"] *= 5
    with pytest.raises(Denied): graph.recovery_portfolio(args)


@pytest.mark.parametrize("direction", ["recovered", "lost", "unfinished"])
def test_trace_comparison_distinguishes_recovered_lost_and_unfinished_work(tmp_path, direction):
    _, _, _, graph = operations(tmp_path)
    bad = scenario();bad["max_attempts"] = 1
    bad["faults"] = [{"record_id": "GR-000", "status": "investigating", "failed_attempts": 1}]
    left = scenario() if direction == "lost" else bad
    right = scenario() if direction == "recovered" else bad
    result = graph.compare_recovery_traces(pair(graph, left, right))
    Draft202012Validator(TRACE_COMPARISON_OUTPUT).validate(result)
    assert result["counts"][direction] == 4
    assert result["delta"]["elapsed_ms"] is None
    assert all(row["delta_ms"] is None for row in result["targets"])


def test_trace_comparison_reports_signed_deltas_without_modifying_evidence(tmp_path):
    _, _, _, graph = operations(tmp_path)
    slow = scenario();slow["durations"] = [{"record_id": "GR-000", "investigate_ms": 3, "resolve_ms": 4}]
    args = pair(graph, scenario(), slow);original = copy.deepcopy(args)
    result = graph.compare_recovery_traces(args)
    assert result["counts"]["regressed"] == 4
    assert result["delta"]["elapsed_ms"] == 4
    assert result["delta"]["worker_busy_ms"] == 5
    assert result["targets"][0]["delta_ms"] == 5 and args == original
    reverse = graph.compare_recovery_traces(pair(graph, slow, scenario()))
    assert reverse["counts"]["improved"] == 4 and reverse["delta"]["elapsed_ms"] == -4


@pytest.mark.parametrize("side", ["baseline", "candidate"])
def test_trace_comparison_rejects_forged_and_stale_evidence_on_either_side(tmp_path, side):
    _, config, _, graph = operations(tmp_path)
    args = pair(graph)
    forged = copy.deepcopy(args);forged[side]["trace"]["completed"] = False
    with pytest.raises(Denied, match="recovery_trace_invalid"): graph.compare_recovery_traces(forged)
    path = Path(config["state_path"]);data = json.loads(path.read_text())
    data["records"]["GR-000"]["version"] += 1;path.write_text(json.dumps(data))
    # Refresh the other side, leaving only this side stale.
    other = "candidate" if side == "baseline" else "baseline"
    args[other]["trace"] = graph.recovery_resilience(args[other]["scenario"])
    before = path.read_bytes()
    with pytest.raises(Denied, match="recovery_trace_invalid"): graph.compare_recovery_traces(args)
    assert path.read_bytes() == before


def test_trace_comparison_handles_already_resolved_incidents_and_different_targets(tmp_path):
    _, config, _, graph = operations(tmp_path)
    path = Path(config["state_path"]);data = json.loads(path.read_text())
    data["records"]["GR-000"]["status"] = "resolved";path.write_text(json.dumps(data))
    result = graph.compare_recovery_traces(pair(graph))
    assert result["targets"][0]["baseline_completion_ms"] == 0
    assert result["counts"]["unchanged"] == 4
    args = pair(graph);args["candidate"]["scenario"]["record_id"] = "GR-000"
    with pytest.raises(Denied, match="trace_targets_differ"): graph.compare_recovery_traces(args)


@pytest.mark.parametrize("nodes,seed", [(8, 7), (32, 11), (128, 23)])
def test_generated_portfolios_match_separately_audited_witnesses_and_reject_corruption(tmp_path, nodes, seed):
    manifest = generate_graph_manifest(seed, 150, nodes=nodes, width=4, portfolio_stress=True)
    action = next(row for row in manifest["actions"] if row["kind"] == "portfolio")
    _, config, _, graph = operations(tmp_path, manifest["graph"])
    rng = random.Random(seed)
    action["arguments"]["deadline_ms"] = rng.randint(nodes, nodes*5)
    action["arguments"]["max_worker_busy_ms"] = rng.randint(nodes, nodes*4)
    variants = witnesses(action["arguments"])
    traces = [graph.recovery_resilience(variant) for variant in variants]
    result = graph.recovery_portfolio(action["arguments"])
    comparison = graph.compare_recovery_traces({"baseline": {"scenario": variants[0], "trace": traces[0]},
        "candidate": {"scenario": variants[1], "trace": traces[1]}, "deadline_ms": action["arguments"]["deadline_ms"]})
    responses = [types.CallToolResult(content=[], structuredContent=value) for value in [result, comparison, *traces]]
    assert check_portfolio_action(GraphOracle(config, True), action, responses)
    forged = copy.deepcopy(responses);forged[0].structuredContent["cells"][0]["worker_busy_ms"] += 1
    assert not check_portfolio_action(GraphOracle(config, True), action, forged)
    forged = copy.deepcopy(responses);forged[1].structuredContent["targets"][0]["change"] = "invented"
    assert not check_portfolio_action(GraphOracle(config, True), action, forged)
    forged = copy.deepcopy(responses);forged[1].structuredContent["counts"]["lost"] = False
    assert not check_portfolio_action(GraphOracle(config, True), action, forged)


def test_full_64_cell_matrix_on_dense_128_node_graph_with_correlated_disruptions(tmp_path):
    dependency_graph = generate_graph(31, 128, 8)
    _, config, _, graph = operations(tmp_path, dependency_graph)
    target = sorted(dependency_graph)[-1]
    selected = closure(target, dependency_graph)
    samples = []
    for index in range(8):
        base = {**scenario(), "record_id": target,
            "durations": [{"record_id": key, "investigate_ms": 1+(position+index)%7, "resolve_ms": 2+(position*index)%9}
                          for position, key in enumerate(selected[::5])],
            "faults": [{"record_id": key, "status": phase, "failed_attempts": index%4}
                       for key, phase in [(selected[0], "investigating"), (selected[1], "resolved"), (target, "resolved")]],
            "worker_outages": [{"worker": 0, "start_ms": index, "end_ms": index+4},
                               {"worker": 0, "start_ms": index+2, "end_ms": index+7}]}
        samples.append({"label": f"scenario{index}", "scenario": base})
    args = {"scenarios": samples, "strategies": [{"label": f"policy{index}", "max_parallel": index+1,
            "max_attempts": index%4+1, "retry_backoff_ms": index} for index in range(8)],
        "deadline_ms": 1000000, "max_worker_busy_ms": 1000000}
    before = Path(config["state_path"]).read_bytes()
    result = graph.recovery_portfolio(args)
    variants = witnesses(args)
    traces = [graph.recovery_resilience(variant) for variant in variants]
    compared = graph.compare_recovery_traces({"baseline": {"scenario": variants[0], "trace": traces[0]},
        "candidate": {"scenario": variants[1], "trace": traces[1]}, "deadline_ms": args["deadline_ms"]})
    responses = [types.CallToolResult(content=[], structuredContent=value) for value in [result, compared, *traces]]
    assert len(result["cells"]) == 64 and len({(row["scenario"], row["strategy"]) for row in result["cells"]}) == 64
    assert result["robust_strategy"] in ("policy3", "policy7")
    assert any(not row["completed"] for row in result["cells"]) and any(row["eligible"] for row in result["cells"])
    assert check_portfolio_action(GraphOracle(config, True), {"arguments": args}, responses)
    assert Path(config["state_path"]).read_bytes() == before


@pytest.mark.parametrize("mode", ["vulnerable", "hardened"])
@pytest.mark.parametrize("transport", ["stdio", "sse", "streamable-http"])
def test_portfolio_and_trace_tools_live_discovery_contract_scope_and_connection_recovery(tmp_path, mode, transport):
    config_path, config, _, _ = operations(tmp_path)
    before = Path(config["state_path"]).read_bytes()
    async def run():
        prefix = "sim_" if mode == "hardened" else ""
        async with connect(config_path, mode, tmp_path / "wire.jsonl", transport) as session:
            tools = {tool.name: tool for tool in (await session.list_tools()).tools}
            for name in ("evaluate_recovery_portfolio", "compare_recovery_traces"):
                assert tools[prefix+name].annotations.readOnlyHint and tools[prefix+name].annotations.idempotentHint
            result = await session.call_tool(prefix+"evaluate_recovery_portfolio", arguments())
            assert not result.isError and result.structuredContent["robust_strategy"] == "resilient"
            Draft202012Validator(tools[prefix+"evaluate_recovery_portfolio"].outputSchema).validate(result.structuredContent)
            trace = (await session.call_tool(prefix+"simulate_recovery_resilience", scenario())).structuredContent
            request = {"baseline": {"scenario": scenario(), "trace": trace}, "candidate": {"scenario": scenario(), "trace": trace}, "deadline_ms": 0}
            result = await session.call_tool(prefix+"compare_recovery_traces", request)
            assert not result.isError and result.structuredContent["counts"]["unchanged"] == 4
            Draft202012Validator(tools[prefix+"compare_recovery_traces"].outputSchema).validate(result.structuredContent)
            forged = copy.deepcopy(request);forged["candidate"]["trace"]["completed"] = False
            assert (await session.call_tool(prefix+"compare_recovery_traces", forged)).isError
            protected = arguments()
            for sample in protected["scenarios"]:
                sample["scenario"]["record_id"] = "PAY-001";sample["scenario"]["faults"] = []
            denied = await session.call_tool(prefix+"evaluate_recovery_portfolio", protected)
            assert bool(denied.isError) == (mode == "hardened")
            await session.call_tool(prefix+"set_catalog_profile", {"profile": "compact", "handle": CATALOG_HANDLE})
            compact = {tool.name for tool in (await session.list_tools()).tools}
            assert {prefix+"evaluate_recovery_portfolio", prefix+"compare_recovery_traces"} <= compact
            assert not (await session.call_tool(prefix+"compare_recovery_traces", request)).isError
            await session.send_ping()
    asyncio.run(run())
    assert Path(config["state_path"]).read_bytes() == before


@pytest.mark.parametrize("slot", [0, 1])
def test_firewall_checks_every_nested_portfolio_scenario_and_trace_side(tmp_path, slot):
    _, config, _, _ = operations(tmp_path)
    args = arguments();args["scenarios"][slot]["scenario"]["record_id"] = "PAY-001"
    with pytest.raises(Denied, match="record_not_authorized"):
        Firewall(config).check("sim_evaluate_recovery_portfolio", args)
    args = {"baseline": {"scenario": scenario(), "trace": {}}, "candidate": {"scenario": scenario(), "trace": {}}, "deadline_ms": 100}
    args[("baseline", "candidate")[slot]]["scenario"]["record_id"] = "PAY-001"
    with pytest.raises(Denied, match="record_not_authorized"):
        Firewall(config).check("sim_compare_recovery_traces", args)


@pytest.mark.parametrize("problem", ["labels", "target", "override", "outage", "bound"])
def test_portfolio_manifest_rejects_invalid_nested_inputs_before_execution(problem):
    manifest = generate_graph_manifest(7, 40, nodes=8, width=2, portfolio_stress=True)
    args = next(action["arguments"] for action in manifest["actions"] if action["kind"] == "portfolio")
    if problem == "labels": args["strategies"][1]["label"] = args["strategies"][0]["label"]
    elif problem == "target": args["scenarios"][0]["scenario"]["record_id"] = "PAY-001"
    elif problem == "override": args["scenarios"][0]["scenario"]["durations"][0]["record_id"] = "PAY-001"
    elif problem == "outage": args["scenarios"][0]["scenario"]["worker_outages"][0]["worker"] = 15
    else: args["strategies"] *= 4
    with pytest.raises(ValueError): validate_graph_manifest(manifest)


@pytest.mark.parametrize("mode,transport", [("hardened", "stdio"), ("vulnerable", "sse"), ("hardened", "streamable-http")])
def test_portfolio_campaigns_resume_and_recheck_saved_witnesses(tmp_path, mode, transport):
    manifest = generate_graph_manifest(7, 40, nodes=8, width=2, portfolio_stress=True)
    assert manifest == generate_graph_manifest(7, 40, nodes=8, width=2, portfolio_stress=True)
    source = tmp_path / "source"
    rows = asyncio.run(graph_campaign_matrix(source, mode, transport, manifest, stop_after=3))
    assert len(rows) == 3 and all(row["passed"] for row in rows)
    rows = asyncio.run(graph_campaign_matrix(tmp_path / "continued", mode, transport, manifest, resume_checkpoint=source / "checkpoint.json"))
    assert len(rows) == 40 and all(row["passed"] for row in rows)


@pytest.mark.parametrize("field", ["winner", "frontier", "comparison", "trace", "boolean"])
def test_rehashed_checkpoint_cannot_forge_portfolio_or_regression_evidence(tmp_path, field):
    manifest = generate_graph_manifest(7, 40, nodes=8, width=2, portfolio_stress=True)
    source = tmp_path / "source"
    asyncio.run(graph_campaign_matrix(source, "hardened", "stdio", manifest, stop_after=3))
    path = source / "checkpoint.json";envelope = json.loads(path.read_text())
    responses = envelope["payload"]["rows"][-1]["responses"]
    if field == "winner": responses[0]["structuredContent"]["robust_strategy"] = "invented"
    elif field == "frontier": responses[0]["structuredContent"]["pareto_strategies"] = []
    elif field == "comparison": responses[1]["structuredContent"]["counts"]["lost"] += 1
    elif field == "boolean": responses[1]["structuredContent"]["counts"]["lost"] = False
    else: responses[2]["structuredContent"]["attempts"][0]["expected_version"] += 1
    envelope["sha256"] = hashlib.sha256(canonical(envelope["payload"])).hexdigest();path.write_text(json.dumps(envelope))
    with pytest.raises(ValueError, match="portfolio fails independent witnesses"):
        asyncio.run(graph_campaign_matrix(tmp_path / "rejected", "hardened", "stdio", manifest, resume_checkpoint=path))
