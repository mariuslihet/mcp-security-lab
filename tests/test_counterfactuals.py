import copy
import json
import asyncio
import hashlib
from pathlib import Path

from simlab.counterfactuals import mitigation_search, duration_sensitivity
from simlab.controls import Denied
from simlab.client import connect
from simlab.dependency_graph import generate_graph
from simlab.graph_campaign import generate_graph_manifest, graph_campaign_matrix, GraphOracle, check_counterfactual_action
from simlab.counterfactual_oracle import witnesses
from simlab.checkpoint import canonical
from mcp import types
from jsonschema import Draft202012Validator
import pytest
from test_outage_recovery import DIAMOND, operations
from test_resilience import scenario


def mitigation_args():
    base = scenario()
    base.update(max_attempts=1, faults=[{"record_id": key, "status": "investigating", "failed_attempts": 1}
                                     for key in ("GR-000", "GR-001")])
    return {"scenario": base, "deadline_ms": 1000, "candidates": [{"kind": "fault", "index": 0}, {"kind": "fault", "index": 1}],
            "max_removals": 2, "max_evaluations": 4}


def test_search_finds_joint_mitigation_and_reports_incomplete_search(tmp_path):
    _, config, _, _ = operations(tmp_path)
    records = json.loads(Path(config["state_path"]).read_text())["records"]
    args = mitigation_args()
    before = copy.deepcopy(args)
    result = mitigation_search(args, DIAMOND, records)
    assert result["search_complete"] and result["total_trials"] == result["evaluated_trials"] == 4
    assert result["best_trial"] == 3
    assert not any(row["deadline_met"] for row in result["trials"][:3])
    assert result["trials"][3]["removed"] == [{"kind": "fault", "index": 0}, {"kind": "fault", "index": 1}]
    truncated = mitigation_search({**args, "max_evaluations": 2}, DIAMOND, records)
    assert not truncated["search_complete"] and truncated["best_trial"] is None
    assert args == before


def test_search_prefers_no_changes_when_deadline_already_met(tmp_path):
    _, config, _, _ = operations(tmp_path)
    records = json.loads(Path(config["state_path"]).read_text())["records"]
    args = mitigation_args()
    args["scenario"]["max_attempts"] = 3
    result = mitigation_search(args, DIAMOND, records)
    assert result["best_trial"] == 0 and result["trials"][0]["removed"] == []


def test_sensitivity_reports_each_scale_without_probability_claims(tmp_path):
    _, config, _, _ = operations(tmp_path)
    records = json.loads(Path(config["state_path"]).read_text())["records"]
    args = {"scenario": scenario(), "deadline_ms": 5, "duration_percent": [200, 50, 100]}
    result = duration_sensitivity(args, DIAMOND, records)
    assert [row["duration_percent"] for row in result["samples"]] == [50, 100, 200]
    assert result["samples"][0]["deadline_met"] and not result["samples"][-1]["deadline_met"]
    assert not result["robust_across_samples"]
    assert result["worst_completed_elapsed_ms"] == max(row["elapsed_ms"] for row in result["samples"])


def test_sensitivity_all_failed_samples_have_no_completed_time(tmp_path):
    _, _, _, graph = operations(tmp_path)
    result = graph.recovery_sensitivity({"scenario": mitigation_args()["scenario"], "deadline_ms": 1000,
                                         "duration_percent": [100, 200]})
    assert result["worst_completed_elapsed_ms"] is None and not result["robust_across_samples"]
    assert not any(row["completed"] for row in result["samples"])


def test_whole_valued_json_numbers_are_accepted_without_mutating_arguments(tmp_path):
    config_path, _, _, graph = operations(tmp_path)
    def floating(value):
        if isinstance(value, dict):
            return {key: floating(item) for key, item in value.items()}
        if isinstance(value, list):
            return [floating(item) for item in value]
        return float(value) if type(value) is int else value
    args = floating(mitigation_args())
    encoded_before = json.dumps(args)
    assert graph.search_mitigations(args) == graph.search_mitigations(mitigation_args())
    assert json.dumps(args) == encoded_before
    sensitivity = {"scenario": scenario(), "deadline_ms": 1000, "duration_percent": [100, 150]}
    assert graph.recovery_sensitivity(floating(sensitivity)) == graph.recovery_sensitivity(sensitivity)
    async def roundtrip():
        async with connect(config_path, "hardened", tmp_path / "numeric-wire.jsonl", "stdio") as session:
            searched = await session.call_tool("sim_search_recovery_mitigations", json.loads(json.dumps(args)))
            assert not searched.isError and searched.structuredContent == graph.search_mitigations(mitigation_args())
            scaled = await session.call_tool("sim_analyze_recovery_sensitivity", floating(sensitivity))
            assert not scaled.isError and scaled.structuredContent == graph.recovery_sensitivity(sensitivity)
    asyncio.run(roundtrip())


def test_longer_work_can_avoid_an_outage_boundary_and_recover(tmp_path):
    _, config, _, graph = operations(tmp_path)
    base = scenario()
    base.update(max_parallel=1, max_attempts=1, durations=[{"record_id": "GR-000", "investigate_ms": 2, "resolve_ms": 2}],
                worker_outages=[{"worker": 0, "start_ms": 3, "end_ms": 4}])
    result = graph.recovery_sensitivity({"scenario": base, "deadline_ms": 1000, "duration_percent": [100, 150]})
    assert [row["completed"] for row in result["samples"]] == [False, True]
    assert not result["robust_across_samples"]


def test_joint_outage_and_fault_removal_use_original_array_indices(tmp_path):
    _, _, _, graph = operations(tmp_path)
    args = mitigation_args()
    args["scenario"].update(faults=[{"record_id": "GR-000", "status": "investigating", "failed_attempts": 1}],
        durations=[{"record_id": "GR-000", "investigate_ms": 5, "resolve_ms": 1}],
        worker_outages=[{"worker": 0, "start_ms": 1, "end_ms": 6}], max_parallel=1)
    args["candidates"] = [{"kind": "outage", "index": 0}, {"kind": "fault", "index": 0}]
    result = graph.search_mitigations(args)
    assert result["best_trial"] == 3
    reordered = graph.search_mitigations({**args, "candidates": list(reversed(args["candidates"]))})
    assert result == reordered


def test_maximum_candidate_set_has_37_bounded_trials_and_can_have_no_solution(tmp_path):
    _, _, _, graph = operations(tmp_path)
    args = mitigation_args()
    args["scenario"]["faults"] = [{"record_id": key, "status": phase, "failed_attempts": 1}
        for key in DIAMOND for phase in ("investigating", "resolved")]
    args.update(candidates=[{"kind": "fault", "index": index} for index in range(8)], max_evaluations=40)
    result = graph.search_mitigations(args)
    assert result["total_trials"] == result["evaluated_trials"] == 37 and result["search_complete"]
    assert result["best_trial"] is None


@pytest.mark.parametrize("problem", ["duplicate", "index", "budget", "removals", "scales", "overflow", "scope"])
def test_counterfactual_profiles_are_bounded_and_scoped(tmp_path, problem):
    _, _, _, graph = operations(tmp_path)
    args = mitigation_args()
    if problem == "duplicate":
        args["candidates"] *= 2
    elif problem == "index":
        args["candidates"][0]["index"] = 10
    elif problem == "budget":
        args["max_evaluations"] = 0
    elif problem == "removals":
        args["max_removals"] = 3
    elif problem == "scope":
        args["scenario"]["faults"][0]["record_id"] = "INC-001"
    else:
        spec = {"scenario": scenario(), "deadline_ms": 1000, "duration_percent": [100, 100] if problem == "scales" else [100, 200]}
        if problem == "overflow":
            spec["scenario"]["durations"] = [{"record_id": "GR-000", "investigate_ms": 1000, "resolve_ms": 1}]
        with pytest.raises(Denied):
            graph.recovery_sensitivity(spec)
        return
    with pytest.raises(Denied):
        graph.search_mitigations(args)


@pytest.mark.parametrize("nodes", [8, 32, 128])
@pytest.mark.parametrize("seed", [7, 23, 41])
def test_randomized_counterfactual_metrics_match_independent_audited_witnesses(tmp_path, nodes, seed):
    data = generate_graph(seed, nodes, 4)
    _, config, _, graph = operations(tmp_path, data)
    manifest = generate_graph_manifest(seed, max(80, nodes), nodes=nodes, width=4, analysis_stress=True)
    action = next(row for row in manifest["actions"] if row["kind"] == "counterfactual")
    before = Path(config["state_path"]).read_bytes()
    searched = graph.search_mitigations(action["mitigation"])
    scaled = graph.recovery_sensitivity(action["sensitivity"])
    scenarios, _, _, _ = witnesses(action, data)
    traces = [graph.recovery_resilience(spec) for spec in scenarios]
    returned = [types.CallToolResult(content=[], structuredContent=value) for value in [searched, scaled, *traces]]
    oracle = GraphOracle(config, True)
    assert check_counterfactual_action(oracle, action, returned)
    forged = copy.deepcopy(returned)
    forged[0].structuredContent["best_trial"] = 0
    assert not check_counterfactual_action(oracle, action, forged)
    forged = copy.deepcopy(returned)
    forged[1].structuredContent["robust_across_samples"] = not forged[1].structuredContent["robust_across_samples"]
    assert not check_counterfactual_action(oracle, action, forged)
    assert Path(config["state_path"]).read_bytes() == before


@pytest.mark.parametrize("mode", ["hardened", "vulnerable"])
@pytest.mark.parametrize("transport", ["stdio", "sse", "streamable-http"])
def test_counterfactual_tools_live_contracts_and_authority(tmp_path, mode, transport):
    config_path, config, _, _ = operations(tmp_path)
    before = Path(config["state_path"]).read_bytes()
    async def run():
        prefix = "sim_" if mode == "hardened" else ""
        async with connect(config_path, mode, tmp_path / "wire.jsonl", transport) as session:
            tools = {tool.name: tool for tool in (await session.list_tools()).tools}
            search = await session.call_tool(prefix + "search_recovery_mitigations", mitigation_args())
            assert not search.isError and search.structuredContent["best_trial"] == 3
            sensitivity_args = {"scenario": scenario(), "deadline_ms": 1000, "duration_percent": [100, 200]}
            sensitivity = await session.call_tool(prefix + "analyze_recovery_sensitivity", sensitivity_args)
            assert not sensitivity.isError and sensitivity.structuredContent["robust_across_samples"]
            for name, response in [("search_recovery_mitigations", search), ("analyze_recovery_sensitivity", sensitivity)]:
                assert tools[prefix + name].annotations.readOnlyHint
                Draft202012Validator(tools[prefix + name].outputSchema).validate(response.structuredContent)
            truncated = await session.call_tool(prefix + "search_recovery_mitigations", {**mitigation_args(), "max_evaluations": 1})
            assert not truncated.isError and truncated.structuredContent["best_trial"] is None
            assert not truncated.structuredContent["search_complete"]
            for name, args in [("search_recovery_mitigations", mitigation_args()), ("analyze_recovery_sensitivity", sensitivity_args)]:
                protected = copy.deepcopy(args)
                protected["scenario"].update(record_id="PAY-001", faults=[])
                if "candidates" in protected:
                    protected["scenario"]["faults"] = [{"record_id": "PAY-001", "status": "investigating", "failed_attempts": 1}]
                    protected["candidates"] = [{"kind": "fault", "index": 0}]
                assert bool((await session.call_tool(prefix + name, protected)).isError) == (mode == "hardened")
            await session.send_ping()
    asyncio.run(run())
    assert Path(config["state_path"]).read_bytes() == before


@pytest.mark.parametrize("mode,transport", [("hardened", "stdio"), ("vulnerable", "sse"), ("hardened", "streamable-http")])
def test_counterfactual_campaigns_resume_search_and_sensitivity_evidence(tmp_path, mode, transport):
    manifest = generate_graph_manifest(7, 80, nodes=16, width=4, analysis_stress=True, strategy_stress=True, resilience_stress=True)
    source = tmp_path / "source"
    rows = asyncio.run(graph_campaign_matrix(source, mode, transport, manifest, stop_after=4))
    assert all(row["passed"] for row in rows)
    continued = asyncio.run(graph_campaign_matrix(tmp_path / "continued", mode, transport, manifest, resume_checkpoint=source / "checkpoint.json"))
    assert len(continued) == 80 and all(row["passed"] for row in continued)


@pytest.mark.parametrize("field", ["winner", "robustness"])
def test_rehashed_checkpoints_cannot_forge_counterfactual_claims(tmp_path, field):
    manifest = generate_graph_manifest(7, 60, nodes=8, width=2, analysis_stress=True)
    source = tmp_path / "source"
    rows = asyncio.run(graph_campaign_matrix(source, "hardened", "stdio", manifest, stop_after=3))
    assert all(row["passed"] for row in rows)
    path = source / "checkpoint.json"
    envelope = json.loads(path.read_text())
    responses = envelope["payload"]["rows"][-1]["responses"]
    if field == "winner":
        responses[0]["structuredContent"]["best_trial"] = 0
    else:
        value = responses[1]["structuredContent"]
        value["robust_across_samples"] = not value["robust_across_samples"]
    envelope["sha256"] = hashlib.sha256(canonical(envelope["payload"])).hexdigest()
    path.write_text(json.dumps(envelope))
    with pytest.raises(ValueError, match="counterfactuals fail reference witnesses"):
        asyncio.run(graph_campaign_matrix(tmp_path / "rejected", "hardened", "stdio", manifest, resume_checkpoint=path))


@pytest.mark.parametrize("problem", ["root", "scope", "candidate", "overflow", "outage", "duplicates"])
def test_invalid_counterfactual_manifests_fail_before_creating_fixture(tmp_path, problem):
    manifest = generate_graph_manifest(7, 60, nodes=8, width=2, analysis_stress=True)
    action = next(row for row in manifest["actions"] if row["kind"] == "counterfactual")
    if problem == "root":
        action["mitigation"]["scenario"]["record_id"] = "PAY-001"
    elif problem == "scope":
        action["mitigation"]["scenario"]["faults"][0]["record_id"] = "PAY-001"
    elif problem == "candidate":
        action["mitigation"]["candidates"][0]["index"] = 99
    elif problem == "overflow":
        action["sensitivity"]["scenario"]["durations"][0]["investigate_ms"] = 1000
        action["sensitivity"]["duration_percent"] = [100, 400]
    elif problem == "outage":
        action["sensitivity"]["scenario"]["worker_outages"][0]["worker"] = 9
    else:
        faults = action["mitigation"]["scenario"]["faults"]
        faults.append(copy.deepcopy(faults[0]))
    destination = tmp_path / "invalid"
    with pytest.raises(ValueError):
        asyncio.run(graph_campaign_matrix(destination, "hardened", "stdio", manifest))
    assert not destination.exists()
