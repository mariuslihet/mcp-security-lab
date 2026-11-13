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
from simlab.graph_campaign import (GraphOracle, check_diagnostic_action, generate_graph_manifest,
                                  graph_campaign_matrix, validate_graph_manifest)
from simlab.recovery_explanations import WAITS_OUTPUT, FAILURES_OUTPUT
from simlab.resilience import closure
from test_outage_recovery import DIAMOND, operations
from test_resilience import scenario


def request(graph, base=None, max_causes=8):
    base = base or scenario()
    return {"scenario": base, "trace": graph.recovery_resilience(base), "max_causes": max_causes}


def analyze(graph, args):
    return graph.recovery_explanation("analyze_recovery_waits", {key: args[key] for key in ("scenario", "trace")})


def explain(graph, args):
    return graph.recovery_explanation("explain_recovery_failures", args)


def test_waits_separate_ready_queueing_from_dependencies_and_retry_backoff(tmp_path):
    _, config, _, graph = operations(tmp_path)
    base = scenario();base["max_parallel"] = 1
    base["worker_outages"] = [{"worker": 0, "start_ms": 0, "end_ms": 2}, {"worker": 0, "start_ms": 1, "end_ms": 3}]
    base["faults"] = [{"record_id": "GR-000", "status": "investigating", "failed_attempts": 1}]
    args = request(graph, base);original = copy.deepcopy(args)
    before = Path(config["state_path"]).read_bytes()
    result = analyze(graph, args)
    Draft202012Validator(WAITS_OUTPUT).validate(result)
    first = next(row for row in result["attempts"] if row["record_id"] == "GR-000" and row["attempt"] == 1)
    assert first["ready_ms"] == 0 and first["start_ms"] == 3 and first["outage_wait_ms"] == 3
    retry = next(row for row in result["attempts"] if row["record_id"] == "GR-000" and row["attempt"] == 2)
    assert retry["required_backoff_ms"] == 2 and retry["retry_ready_ms"] == 6
    assert result["totals"]["busy_wait_ms"] > 0 and result["totals"]["dispatch_gap_ms"] == 0
    assert result["totals"]["required_backoff_ms"] == 2
    for row in result["attempts"]:
        assert row["waiting_ms"] == row["start_ms"]-max(row["dependency_ready_ms"],row["retry_ready_ms"])
        assert row["waiting_ms"] == row["outage_wait_ms"]+row["busy_wait_ms"]+row["dispatch_gap_ms"]
    assert args == original and Path(config["state_path"]).read_bytes() == before


def test_legal_dispatch_gaps_are_explained_without_claiming_they_are_outages(tmp_path):
    _, _, _, graph = operations(tmp_path)
    args = request(graph)
    for event in args["trace"]["attempts"]:
        event["start_ms"] += 10;event["end_ms"] += 10
    args["trace"]["elapsed_ms"] += 10
    result = analyze(graph, args)
    first = result["attempts"][0]
    assert first["ready_ms"] == 0 and first["dispatch_gap_ms"] == 10
    assert first["outage_wait_ms"] == 0 and result["totals"]["dispatch_gap_ms"] >= 20


def test_failure_paths_include_phase_edges_and_deterministic_shortest_diamond_path(tmp_path):
    _, _, _, graph = operations(tmp_path)
    base = scenario();base["max_attempts"] = 1
    base["faults"] = [{"record_id": "GR-000", "status": "investigating", "failed_attempts": 1}]
    result = explain(graph, request(graph, base))
    Draft202012Validator(FAILURES_OUTPUT).validate(result)
    assert result["roots"] == [{"record_id": "GR-000", "status": "investigating", "stopped_ms": 1,
        "attempt_count": 1, "reason": "injected_failure", "affected_record_count": 4}]
    tip = next(row for row in result["targets"] if row["record_id"] == "GR-003")
    assert [(row["record_id"],row["status"]) for row in tip["causes"][0]["path"]] == [
        ("GR-000","investigating"),("GR-000","resolved"),("GR-001","resolved"),("GR-003","resolved")]


def test_multi_root_causes_are_counted_before_truncation_and_deduplicated(tmp_path):
    dependencies = {"GR-000": [], "GR-001": [], "GR-002": ["GR-000","GR-001"], "GR-003": ["GR-002"]}
    _, _, _, graph = operations(tmp_path, dependencies)
    base = scenario();base["max_attempts"] = 1
    base["faults"] = [{"record_id": key, "status": "investigating", "failed_attempts": 1} for key in ("GR-000","GR-001")]
    args = request(graph, base, 1)
    result = explain(graph, args)
    tip = result["targets"][-1]
    assert tip["cause_count"] == 2 and tip["truncated"] and len(tip["causes"]) == 1
    assert tip["causes"][0]["root"]["record_id"] == "GR-000"
    assert [row["affected_record_count"] for row in result["roots"]] == [3,3]
    args["max_causes"] = 8
    assert len(explain(graph,args)["targets"][-1]["causes"]) == 2


def test_shortest_paths_use_forward_lexical_order_even_when_reverse_order_differs(tmp_path):
    dependencies = {"GR-000":[],"GR-001":["GR-000"],"GR-002":["GR-000"],
        "GR-004":["GR-002"],"GR-005":["GR-001"],"GR-006":["GR-004","GR-005"]}
    _, config, _, graph = operations(tmp_path,dependencies)
    base = {**scenario(),"record_id":"GR-006","max_attempts":1,
        "faults":[{"record_id":"GR-000","status":"investigating","failed_attempts":1}]}
    args = request(graph,base)
    result = explain(graph,args)
    assert [task["record_id"] for task in result["targets"][-1]["causes"][0]["path"]] == [
        "GR-000","GR-000","GR-001","GR-005","GR-006"]
    results = [types.CallToolResult(content=[],structuredContent=value) for value in [args["trace"],analyze(graph,args),result]]
    assert check_diagnostic_action(GraphOracle(config,True),{"arguments":base,"max_causes":8},results)


def test_investigating_snapshot_has_no_invented_investigation_failure_edge(tmp_path):
    _, config, _, graph = operations(tmp_path)
    path = Path(config["state_path"]);data = json.loads(path.read_text())
    data["records"]["GR-000"]["status"] = "investigating";path.write_text(json.dumps(data))
    base = {**scenario(),"max_attempts":1,"faults":[{"record_id":"GR-000","status":"resolved","failed_attempts":1}]}
    result = explain(graph,request(graph,base))
    assert result["roots"][0]["status"] == "resolved"
    own = result["targets"][0]["causes"][0]["path"]
    assert own == [{"record_id":"GR-000","status":"resolved"}]


def test_exhausted_worker_interruption_is_a_root_with_its_actual_stop_time(tmp_path):
    _, _, _, graph = operations(tmp_path)
    base = scenario();base["max_parallel"] = base["max_attempts"] = 1
    base["durations"] = [{"record_id":"GR-000","investigate_ms":5,"resolve_ms":1}]
    base["worker_outages"] = [{"worker":0,"start_ms":2,"end_ms":4}]
    result = explain(graph,request(graph,base))
    assert result["roots"][0]["reason"] == "worker_outage" and result["roots"][0]["stopped_ms"] == 2


def test_completed_and_empty_recoveries_have_no_invented_failures_or_waits(tmp_path):
    _, config, _, graph = operations(tmp_path)
    assert explain(graph,request(graph))["targets"] == []
    path = Path(config["state_path"]);data = json.loads(path.read_text())
    for key in DIAMOND: data["records"][key]["status"] = "resolved"
    path.write_text(json.dumps(data))
    args = request(graph)
    assert explain(graph,args)["roots"] == []
    result = analyze(graph,args)
    assert result["attempts"] == result["record_totals"] == [] and not any(result["totals"].values())


@pytest.mark.parametrize("name", ["analyze_recovery_waits","explain_recovery_failures"])
@pytest.mark.parametrize("problem", ["forged","stale","hidden_parent","bound"])
def test_explanations_reject_untrusted_evidence_and_protected_prerequisites(tmp_path,name,problem):
    _, config, _, graph = operations(tmp_path)
    args = request(graph)
    if problem == "forged": args["trace"]["attempts"][0]["expected_version"] += 1
    elif problem == "stale":
        path = Path(config["state_path"]);data = json.loads(path.read_text())
        data["records"]["GR-000"]["version"] += 1;path.write_text(json.dumps(data))
    elif problem == "hidden_parent": config["allowed_records"].remove("GR-000")
    else: args["max_causes"] = 9
    if name == "analyze_recovery_waits" and problem != "bound": args.pop("max_causes")
    before = Path(config["state_path"]).read_bytes()
    with pytest.raises(Denied): graph.recovery_explanation(name,args)
    assert Path(config["state_path"]).read_bytes() == before


def test_whole_valued_json_numbers_and_trace_order_do_not_change_explanations(tmp_path):
    _, _, _, graph = operations(tmp_path)
    args = request(graph)
    expected = analyze(graph,args)
    args["trace"]["attempts"].reverse()
    def floats(value):
        if isinstance(value,dict): return {key:floats(item) for key,item in value.items()}
        if isinstance(value,list): return [floats(item) for item in value]
        return float(value) if type(value) is int else value
    assert analyze(graph,floats(args)) == expected
    assert explain(graph,floats(args)) == explain(graph,args)


@pytest.mark.parametrize("nodes,seed", [(8,7),(32,23),(128,41)])
@pytest.mark.parametrize("exhausted", [False,True])
def test_dense_randomized_explanations_match_independent_overlap_and_reverse_graph_oracles(tmp_path,nodes,seed,exhausted):
    graph_spec = generate_graph(seed,nodes,4)
    _, config, _, graph = operations(tmp_path,graph_spec)
    rng = random.Random(seed)
    target = sorted(graph_spec)[-1];selected = closure(target,graph_spec)
    base = {**scenario(),"record_id":target,"max_parallel":4,"max_attempts":1 if exhausted else 4,
        "durations":[{"record_id":key,"investigate_ms":rng.randint(1,7),"resolve_ms":rng.randint(1,9)} for key in selected],
        "faults":[{"record_id":key,"status":"investigating","failed_attempts":rng.randint(1,2)} for key in selected[:3]],
        "worker_outages":[{"worker":worker,"start_ms":0,"end_ms":worker+2} for worker in range(4)]
            + [{"worker":0,"start_ms":1,"end_ms":5},{"worker":2,"start_ms":10,"end_ms":13}]}
    args = request(graph,base,max_causes=1 if exhausted else 8)
    results = [types.CallToolResult(content=[],structuredContent=value) for value in [args["trace"],analyze(graph,args),explain(graph,args)]]
    action = {"arguments":base,"max_causes":args["max_causes"]}
    assert check_diagnostic_action(GraphOracle(config,True),action,results)
    for response,field in ((1,"waiting_ms"),(2,"completed")):
        forged = copy.deepcopy(results)
        if response == 1: forged[response].structuredContent["totals"][field] += 1
        else: forged[response].structuredContent[field] = not forged[response].structuredContent[field]
        assert not check_diagnostic_action(GraphOracle(config,True),action,forged)


@pytest.mark.parametrize("mode", ["vulnerable","hardened"])
@pytest.mark.parametrize("transport", ["stdio","sse","streamable-http"])
def test_explanation_tools_live_contract_authority_and_error_recovery(tmp_path,mode,transport):
    config_path, config, _, _ = operations(tmp_path)
    before = Path(config["state_path"]).read_bytes()
    async def run():
        prefix = "sim_" if mode == "hardened" else ""
        async with connect(config_path,mode,tmp_path/"wire.jsonl",transport) as session:
            tools = {tool.name:tool for tool in (await session.list_tools()).tools}
            base = scenario();trace = (await session.call_tool(prefix+"simulate_recovery_resilience",base)).structuredContent
            for name in ("analyze_recovery_waits","explain_recovery_failures"):
                assert tools[prefix+name].annotations.readOnlyHint and tools[prefix+name].annotations.idempotentHint
                args = {"scenario":base,"trace":trace,**({"max_causes":2} if name.startswith("explain") else {})}
                result = await session.call_tool(prefix+name,args)
                assert not result.isError
                Draft202012Validator(tools[prefix+name].outputSchema).validate(result.structuredContent)
                forged = copy.deepcopy(args);forged["trace"]["completed"] = False
                assert (await session.call_tool(prefix+name,forged)).isError
                protected = {**base,"record_id":"PAY-001"}
                outside = await session.call_tool(prefix+"simulate_recovery_resilience",protected)
                result = await session.call_tool(prefix+name,{**args,"scenario":protected,"trace":outside.structuredContent or {}})
                assert bool(result.isError) == (mode == "hardened")
            await session.call_tool(prefix+"set_catalog_profile",{"profile":"compact","handle":CATALOG_HANDLE})
            catalog = {tool.name for tool in (await session.list_tools()).tools}
            assert {prefix+"analyze_recovery_waits",prefix+"explain_recovery_failures"} <= catalog
            assert not (await session.call_tool(prefix+"analyze_recovery_waits",{"scenario":base,"trace":trace})).isError
            assert not (await session.call_tool(prefix+"explain_recovery_failures",{"scenario":base,"trace":trace,"max_causes":2})).isError
            await session.send_ping()
    asyncio.run(run())
    assert Path(config["state_path"]).read_bytes() == before


@pytest.mark.parametrize("problem", ["target","override","outage","duplicate_fault","bound"])
def test_diagnostic_manifest_rejects_invalid_nested_inputs(problem):
    manifest = generate_graph_manifest(7,40,nodes=8,width=2,diagnostics_stress=True)
    action = next(row for row in manifest["actions"] if row["kind"] == "diagnostics")
    base = action["arguments"]
    if problem == "target": base["record_id"] = "PAY-001"
    elif problem == "override": base["durations"][0]["record_id"] = "PAY-001"
    elif problem == "outage": base["worker_outages"][0]["end_ms"] = 0
    elif problem == "duplicate_fault": base["faults"].append(copy.deepcopy(base["faults"][0]))
    else: action["max_causes"] = 9
    with pytest.raises(ValueError): validate_graph_manifest(manifest)


@pytest.mark.parametrize("mode,transport", [("hardened","stdio"),("vulnerable","sse"),("hardened","streamable-http")])
def test_explanation_campaigns_resume_and_reaudit_saved_accounting_and_paths(tmp_path,mode,transport):
    manifest = generate_graph_manifest(7,40,nodes=8,width=2,diagnostics_stress=True)
    assert manifest == generate_graph_manifest(7,40,nodes=8,width=2,diagnostics_stress=True)
    source = tmp_path/"source"
    rows = asyncio.run(graph_campaign_matrix(source,mode,transport,manifest,stop_after=4))
    assert len(rows) == 4 and all(row["passed"] for row in rows)
    rows = asyncio.run(graph_campaign_matrix(tmp_path/"continued",mode,transport,manifest,resume_checkpoint=source/"checkpoint.json"))
    assert len(rows) == 40 and all(row["passed"] for row in rows)


@pytest.mark.parametrize("field", ["waiting","path","impact","boolean"])
def test_rehashed_checkpoint_cannot_forge_waiting_or_failure_paths(tmp_path,field):
    manifest = generate_graph_manifest(7,40,nodes=8,width=2,diagnostics_stress=True)
    source = tmp_path/"source"
    rows = asyncio.run(graph_campaign_matrix(source,"hardened","stdio",manifest,stop_after=4))
    assert all(row["passed"] for row in rows)
    path = source/"checkpoint.json";envelope = json.loads(path.read_text())
    responses = envelope["payload"]["rows"][-1]["responses"]
    if field == "waiting": responses[1]["structuredContent"]["totals"]["dispatch_gap_ms"] += 1
    elif field == "path": responses[2]["structuredContent"]["targets"][-1]["causes"][0]["path"].pop()
    elif field == "impact": responses[2]["structuredContent"]["roots"][0]["affected_record_count"] += 1
    else: responses[1]["structuredContent"]["totals"]["dispatch_gap_ms"] = False
    envelope["sha256"] = hashlib.sha256(canonical(envelope["payload"])).hexdigest();path.write_text(json.dumps(envelope))
    with pytest.raises(ValueError,match="recovery explanations fail independent verification"):
        asyncio.run(graph_campaign_matrix(tmp_path/"rejected","hardened","stdio",manifest,resume_checkpoint=path))
