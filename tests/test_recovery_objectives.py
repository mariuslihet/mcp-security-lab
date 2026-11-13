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
from simlab.graph_campaign import (GraphOracle,check_objective_action,generate_graph_manifest,graph_campaign_matrix,validate_graph_manifest)
from simlab.objective_oracle import witnesses
from simlab.recovery_objectives import OBJECTIVES_OUTPUT,CAPACITY_OUTPUT
from simlab.resilience import closure
from test_outage_recovery import DIAMOND,operations
from test_resilience import scenario


def goals():
    return {"weights":[{"record_id":"GR-000","weight":1},{"record_id":"GR-003","weight":2}],
        "horizon_ms":5,"milestones":[{"at_ms":2,"required_basis_points":3333},{"at_ms":5,"required_basis_points":10000}]}


def search_args():
    return {"scenario":scenario(),**goals(),"worker_options":[1,2,4],"require_complete":True,
            "max_worker_busy_ms":1000,"max_unresolved_weight_ms":1000000}


def evaluated(graph,args=None):
    args = args or search_args()
    return graph.evaluate_recovery_objectives({"scenario":args["scenario"],"trace":graph.recovery_resilience(args["scenario"]),
        **{key:args[key] for key in ("weights","milestones","horizon_ms")}})


def test_weighted_coverage_and_unresolved_integral_match_hand_calculation(tmp_path):
    _,config,_,graph = operations(tmp_path)
    before = Path(config["state_path"]).read_bytes()
    result = evaluated(graph)
    Draft202012Validator(OBJECTIVES_OUTPUT).validate(result)
    assert result["targets"] == [{"record_id":"GR-000","weight":1,"completion_ms":2},
                                 {"record_id":"GR-003","weight":2,"completion_ms":5}]
    assert result["unresolved_weight_ms"] == 12 and result["time_coverage_basis_points"] == 2000
    assert result["milestones"][0]["covered_weight"] == 1 and result["milestones"][0]["coverage_basis_points"] == 3333
    assert result["all_milestones_met"] and result["horizon_coverage_basis_points"] == 10000
    args = search_args();args["milestones"][0]["required_basis_points"] = 3334
    assert not evaluated(graph,args)["all_milestones_met"]
    assert Path(config["state_path"]).read_bytes() == before


def test_capacity_search_enumerates_nonmonotonic_worker_outcomes(tmp_path):
    _,_,_,graph = operations(tmp_path)
    args = search_args()
    args["scenario"].update(max_attempts=1,worker_outages=[{"worker":0,"start_ms":3,"end_ms":6}],
        durations=[{"record_id":"GR-001","investigate_ms":1,"resolve_ms":5}])
    args.update(horizon_ms=100,milestones=[{"at_ms":100,"required_basis_points":10000}],worker_options=[2,1])
    result = graph.search_recovery_capacity(args)
    Draft202012Validator(CAPACITY_OUTPUT).validate(result)
    assert [(row["workers"],row["completed"]) for row in result["candidates"]] == [(1,True),(2,False)]
    assert result["recommended_workers"] == 1


@pytest.mark.parametrize("constraint",["max_worker_busy_ms","max_unresolved_weight_ms"])
def test_capacity_search_obeys_inclusive_budgets_and_returns_no_infeasible_recommendation(tmp_path,constraint):
    _,_,_,graph = operations(tmp_path)
    args = search_args();args["worker_options"] = [2]
    value = graph.search_recovery_capacity(args)["candidates"][0]
    budget = value["worker_busy_ms" if constraint == "max_worker_busy_ms" else "unresolved_weight_ms"]
    args[constraint] = budget
    assert graph.search_recovery_capacity(args)["recommended_workers"] == 2
    args[constraint] = budget-1
    assert graph.search_recovery_capacity(args)["recommended_workers"] is None


def test_critical_target_success_is_distinct_from_global_completion(tmp_path):
    _,_,_,graph = operations(tmp_path)
    args = search_args()
    args["scenario"].update(max_attempts=1,faults=[{"record_id":"GR-001","status":"investigating","failed_attempts":1}])
    args.update(weights=[{"record_id":"GR-002","weight":10}],horizon_ms=100,
        milestones=[{"at_ms":100,"required_basis_points":10000}],require_complete=False)
    result = evaluated(graph,args)
    assert result["all_targets_completed"] and result["all_milestones_met"] and not result["global_completed"]
    assert graph.search_recovery_capacity(args)["recommended_workers"] == 1
    args["require_complete"] = True
    assert graph.search_recovery_capacity(args)["recommended_workers"] is None


def test_zero_horizon_resolved_weights_and_all_sixteen_worker_options(tmp_path):
    _,config,_,graph = operations(tmp_path)
    path = Path(config["state_path"]);data = json.loads(path.read_text())
    for key in DIAMOND: data["records"][key]["status"] = "resolved"
    path.write_text(json.dumps(data))
    args = search_args();args.update(horizon_ms=0,milestones=[{"at_ms":0,"required_basis_points":10000}],
        worker_options=list(range(16,0,-1)),max_worker_busy_ms=0,max_unresolved_weight_ms=0)
    result = evaluated(graph,args)
    assert result["time_coverage_basis_points"] is None and result["horizon_coverage_basis_points"] == 10000
    assert result["unresolved_weight_ms"] == 0 and result["all_milestones_met"]
    searched = graph.search_recovery_capacity(args)
    assert len(searched["candidates"]) == 16 and searched["recommended_workers"] == 1


def test_unfinished_targets_remain_uncovered_after_simulator_stops(tmp_path):
    _,_,_,graph = operations(tmp_path)
    args = search_args();args["scenario"].update(max_attempts=1,faults=[{"record_id":"GR-000","status":"investigating","failed_attempts":1}])
    args.update(horizon_ms=100,milestones=[{"at_ms":100,"required_basis_points":1}])
    result = evaluated(graph,args)
    assert result["unresolved_weight_ms"] == 300 and result["time_coverage_basis_points"] == 0
    assert result["horizon_coverage_basis_points"] == 0 and not result["all_milestones_met"]


def test_maximum_weighted_burden_stays_exact_at_all_input_bounds(tmp_path):
    dependencies = {f'GR-{index:03}':[] if index == 0 else [f'GR-{index-1:03}'] for index in range(128)}
    _,config,_,graph = operations(tmp_path,dependencies)
    base = {**scenario(),'record_id':'GR-127','max_attempts':1,
        'faults':[{'record_id':key,'status':'investigating','failed_attempts':1} for key in dependencies]}
    args = {'scenario':base,'weights':[{'record_id':key,'weight':1000} for key in dependencies],
        'horizon_ms':1000000,'milestones':[{'at_ms':index*60000,'required_basis_points':10000} for index in range(16)],
        'worker_options':[1],'require_complete':True,'max_worker_busy_ms':1000000,'max_unresolved_weight_ms':128000000000}
    traces = [graph.recovery_resilience(variant) for variant in witnesses(args)]
    objective = graph.evaluate_recovery_objectives({'scenario':witnesses(args)[0],'trace':traces[0],
        **{key:args[key] for key in ('weights','milestones','horizon_ms')}})
    assert objective['total_weight'] == 128000 and objective['unresolved_weight_ms'] == 128000000000
    assert objective['time_coverage_basis_points'] == 0 and len(objective['milestones']) == 16
    searched = graph.search_recovery_capacity(args)
    results = [types.CallToolResult(content=[],structuredContent=value) for value in [searched,objective,*traces]]
    assert check_objective_action(GraphOracle(config,True),{'arguments':args},results)


@pytest.mark.parametrize("problem",["weights","zero_weight","outside","milestones","horizon","worker","bool_budget","too_many"])
def test_objective_search_rejects_ambiguous_or_unbounded_inputs(tmp_path,problem):
    _,_,_,graph = operations(tmp_path)
    args = search_args()
    if problem == "weights": args["weights"].append(copy.deepcopy(args["weights"][0]))
    elif problem == "zero_weight": args["weights"][0]["weight"] = 0
    elif problem == "outside": args["weights"][0]["record_id"] = "PAY-001"
    elif problem == "milestones": args["milestones"].append({"at_ms":2,"required_basis_points":1})
    elif problem == "horizon": args["milestones"][1]["at_ms"] = 6
    elif problem == "worker": args["scenario"]["worker_outages"] = [{"worker":1,"start_ms":0,"end_ms":1}]
    elif problem == "bool_budget": args["max_worker_busy_ms"] = True
    else: args["worker_options"] = list(range(1,18))
    with pytest.raises(Denied): graph.search_recovery_capacity(args)


@pytest.mark.parametrize("problem",["forged","stale","hidden_parent"])
def test_objective_evaluation_rejects_stale_forged_and_unauthorized_evidence(tmp_path,problem):
    _,config,_,graph = operations(tmp_path)
    args = {"scenario":scenario(),"trace":graph.recovery_resilience(scenario()),**goals()}
    if problem == "forged": args["trace"]["completed"] = False
    elif problem == "stale":
        path = Path(config["state_path"]);data = json.loads(path.read_text());data["records"]["GR-000"]["version"] += 1
        path.write_text(json.dumps(data))
    else: config["allowed_records"].remove("GR-000")
    before = Path(config["state_path"]).read_bytes()
    with pytest.raises(Denied): graph.evaluate_recovery_objectives(args)
    assert Path(config["state_path"]).read_bytes() == before


def test_reordering_and_whole_valued_json_numbers_preserve_results(tmp_path):
    _,_,_,graph = operations(tmp_path)
    args = search_args();original = copy.deepcopy(args)
    expected = graph.search_recovery_capacity(args)
    assert args == original
    args["weights"].reverse();args["milestones"].reverse();args["worker_options"].reverse()
    def floats(value):
        if isinstance(value,dict): return {key:floats(item) for key,item in value.items()}
        if isinstance(value,list): return [floats(item) for item in value]
        return float(value) if type(value) is int else value
    assert graph.search_recovery_capacity(floats(args)) == expected
    base = {"scenario":scenario(),"trace":graph.recovery_resilience(scenario()),**goals()}
    assert graph.evaluate_recovery_objectives(floats(base)) == graph.evaluate_recovery_objectives(base)


@pytest.mark.parametrize("nodes,seed",[(8,11),(32,23),(128,41)])
def test_dense_weighted_objectives_match_independent_event_integrals_and_trace_witnesses(tmp_path,nodes,seed):
    dependencies = generate_graph(seed,nodes,4)
    _,config,_,graph = operations(tmp_path,dependencies)
    target = sorted(dependencies)[-1];selected = closure(target,dependencies);rng = random.Random(seed)
    args = {"scenario":{**scenario(),"record_id":target,"max_parallel":4,
                "durations":[{"record_id":key,"investigate_ms":rng.randint(1,8),"resolve_ms":rng.randint(1,9)} for key in selected],
                "faults":[{"record_id":key,"status":"investigating","failed_attempts":1} for key in selected[:2]],
                "worker_outages":[{"worker":0,"start_ms":3,"end_ms":7}]},
        "weights":[{"record_id":key,"weight":rng.randint(1,1000)} for key in selected],
        "horizon_ms":nodes*10,"milestones":[{"at_ms":index*nodes,"required_basis_points":index*1000} for index in range(1,11)],
        "worker_options":list(range(1,17)),"require_complete":True,"max_worker_busy_ms":1000000,"max_unresolved_weight_ms":128000000000}
    traces = [graph.recovery_resilience(variant) for variant in witnesses(args)]
    searched = graph.search_recovery_capacity(args)
    first = witnesses(args)[0]
    objective = graph.evaluate_recovery_objectives({"scenario":first,"trace":traces[0],
        **{key:args[key] for key in ("weights","milestones","horizon_ms")}})
    results = [types.CallToolResult(content=[],structuredContent=value) for value in [searched,objective,*traces]]
    assert check_objective_action(GraphOracle(config,True),{"arguments":args},results)
    bad = copy.deepcopy(results);bad[1].structuredContent["unresolved_weight_ms"] += 1
    assert not check_objective_action(GraphOracle(config,True),{"arguments":args},bad)
    bad = copy.deepcopy(results);bad[0].structuredContent["candidates"][0]["busy_budget_met"] = 1
    assert not check_objective_action(GraphOracle(config,True),{"arguments":args},bad)


@pytest.mark.parametrize("mode",["vulnerable","hardened"])
@pytest.mark.parametrize("transport",["stdio","sse","streamable-http"])
def test_weighted_objective_tools_live_discovery_contract_scope_and_compact_calls(tmp_path,mode,transport):
    config_path,config,_,_ = operations(tmp_path)
    before = Path(config["state_path"]).read_bytes()
    async def run():
        prefix = "sim_" if mode == "hardened" else ""
        async with connect(config_path,mode,tmp_path/'wire.jsonl',transport) as session:
            tools = {tool.name:tool for tool in (await session.list_tools()).tools}
            args = search_args()
            trace = (await session.call_tool(prefix+'simulate_recovery_resilience',scenario())).structuredContent
            evaluation = {"scenario":scenario(),"trace":trace,**goals()}
            for name,request in [('search_recovery_capacity',args),('evaluate_recovery_objectives',evaluation)]:
                assert tools[prefix+name].annotations.readOnlyHint and tools[prefix+name].annotations.idempotentHint
                result = await session.call_tool(prefix+name,request)
                assert not result.isError
                Draft202012Validator(tools[prefix+name].outputSchema).validate(result.structuredContent)
                protected = copy.deepcopy(request);protected['scenario']['record_id'] = 'PAY-001'
                protected['weights'] = [{'record_id':'PAY-001','weight':1}]
                if name.startswith('evaluate'):
                    outside = await session.call_tool(prefix+'simulate_recovery_resilience',protected['scenario'])
                    protected['trace'] = outside.structuredContent or {}
                denied = await session.call_tool(prefix+name,protected)
                assert bool(denied.isError) == (mode == 'hardened')
            bad = copy.deepcopy(evaluation);bad['trace']['completed'] = False
            assert (await session.call_tool(prefix+'evaluate_recovery_objectives',bad)).isError
            await session.call_tool(prefix+'set_catalog_profile',{'profile':'compact','handle':CATALOG_HANDLE})
            assert not (await session.call_tool(prefix+'search_recovery_capacity',args)).isError
            assert not (await session.call_tool(prefix+'evaluate_recovery_objectives',evaluation)).isError
            await session.send_ping()
    asyncio.run(run())
    assert Path(config['state_path']).read_bytes() == before


@pytest.mark.parametrize("problem",['scope','duplicate','horizon','worker','type'])
def test_objective_manifest_validation_checks_all_nested_constraints(problem):
    manifest = generate_graph_manifest(7,40,nodes=8,width=2,objectives_stress=True)
    args = next(row['arguments'] for row in manifest['actions'] if row['kind'] == 'objectives')
    if problem == 'scope': args['weights'][0]['record_id'] = 'PAY-001'
    elif problem == 'duplicate': args['milestones'].append(copy.deepcopy(args['milestones'][0]))
    elif problem == 'horizon': args['horizon_ms'] = 0
    elif problem == 'worker': args['scenario']['worker_outages'][0]['worker'] = 3
    else: args['require_complete'] = 1
    with pytest.raises(ValueError): validate_graph_manifest(manifest)


@pytest.mark.parametrize("mode,transport",[('hardened','stdio'),('vulnerable','sse'),('hardened','streamable-http')])
def test_objective_campaigns_replay_and_resume_with_all_candidate_witnesses(tmp_path,mode,transport):
    manifest = generate_graph_manifest(7,40,nodes=8,width=2,objectives_stress=True)
    assert manifest == generate_graph_manifest(7,40,nodes=8,width=2,objectives_stress=True)
    source = tmp_path/'source'
    partial = asyncio.run(graph_campaign_matrix(source,mode,transport,manifest,stop_after=3))
    assert all(row['passed'] for row in partial)
    rows = asyncio.run(graph_campaign_matrix(tmp_path/'resumed',mode,transport,manifest,resume_checkpoint=source/'checkpoint.json'))
    assert len(rows) == 40 and all(row['passed'] for row in rows)


@pytest.mark.parametrize("field",['burden','winner','boolean','trace'])
def test_rehashed_checkpoint_cannot_forge_objective_metrics_or_capacity_selection(tmp_path,field):
    manifest = generate_graph_manifest(7,40,nodes=8,width=2,objectives_stress=True)
    source = tmp_path/'source'
    rows = asyncio.run(graph_campaign_matrix(source,'hardened','stdio',manifest,stop_after=3))
    assert all(row['passed'] for row in rows)
    path = source/'checkpoint.json';envelope = json.loads(path.read_text());responses = envelope['payload']['rows'][-1]['responses']
    if field == 'burden': responses[1]['structuredContent']['unresolved_weight_ms'] += 1
    elif field == 'winner': responses[0]['structuredContent']['recommended_workers'] = 16
    elif field == 'boolean': responses[0]['structuredContent']['candidates'][0]['busy_budget_met'] = 1
    else: responses[2]['structuredContent']['attempts'][0]['expected_version'] += 1
    envelope['sha256'] = hashlib.sha256(canonical(envelope['payload'])).hexdigest();path.write_text(json.dumps(envelope))
    with pytest.raises(ValueError,match='recovery objectives fail independent verification'):
        asyncio.run(graph_campaign_matrix(tmp_path/'rejected','hardened','stdio',manifest,resume_checkpoint=path))
