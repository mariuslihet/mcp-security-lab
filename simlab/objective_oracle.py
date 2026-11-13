"""Verify weighted objectives by event-window integration and separate traces."""
import copy

from jsonschema import Draft202012Validator

from .recovery_objectives import OBJECTIVES_OUTPUT, CAPACITY_OUTPUT
from .resilience import integer_arguments


def witnesses(arguments):
    args = integer_arguments(arguments)
    return [{**copy.deepcopy(args["scenario"]), "max_parallel": workers} for workers in sorted(args["worker_options"])]


def _objectives(args, trace):
    targets = []
    for row in args["weights"]:
        initial = next(record for record in trace["snapshot"] if record["id"] == row["record_id"])
        events = [event["end_ms"] for event in trace["attempts"] if event["record_id"] == row["record_id"]
                  and event["status"] == "resolved" and event["outcome"] == "succeeded"]
        end = 0 if initial["status"] == "resolved" else min(events) if events else None
        targets.append({"record_id": row["record_id"], "weight": row["weight"], "completion_ms": end})
    targets.sort(key=lambda row: row["record_id"])
    total, horizon = sum(row["weight"] for row in targets), args["horizon_ms"]
    boundaries = sorted({0,horizon} | {min(horizon,row["completion_ms"]) for row in targets if row["completion_ms"] is not None})
    burden = 0
    for start,end in zip(boundaries,boundaries[1:]):
        unresolved = sum(row["weight"] for row in targets if row["completion_ms"] is None or row["completion_ms"] > start)
        burden += (end-start)*unresolved
    milestones = []
    for goal in sorted(args["milestones"],key=lambda row: row["at_ms"]):
        weight = total - sum(row["weight"] for row in targets if row["completion_ms"] is None or row["completion_ms"] > goal["at_ms"])
        points = weight*10000//total
        milestones.append({"at_ms":goal["at_ms"],"required_basis_points":goal["required_basis_points"],
            "covered_weight":weight,"coverage_basis_points":points,"met":points >= goal["required_basis_points"]})
    final_weight = sum(row["weight"] for row in targets if row["completion_ms"] is not None and row["completion_ms"] <= horizon)
    return {"record_id":trace["record_id"],"horizon_ms":horizon,"total_weight":total,
        "global_completed":all(row["status"] == "resolved" for row in trace["final_records"]),
        "all_targets_completed":all(row["completion_ms"] is not None for row in targets),
        "all_milestones_met":all(row["met"] for row in milestones),"horizon_coverage_basis_points":final_weight*10000//total,
        "unresolved_weight_ms":burden,"time_coverage_basis_points":None if horizon == 0 else 10000-(burden*10000 + total*horizon-1)//(total*horizon),
        "targets":targets,"milestones":milestones,"snapshot":copy.deepcopy(trace["snapshot"])}


def verify(oracle, action, responses, matches):
    args = integer_arguments(action["arguments"])
    scenarios = witnesses(args)
    if len(responses) != len(scenarios)+2 or any(result.isError for result in responses):
        return False
    if (not Draft202012Validator(CAPACITY_OUTPUT).is_valid(responses[0].structuredContent)
            or not Draft202012Validator(OBJECTIVES_OUTPUT).is_valid(responses[1].structuredContent)):
        return False
    candidates, evaluated = [], []
    for scenario, result in zip(scenarios,responses[2:]):
        if not matches(oracle.call("simulate_recovery_resilience",scenario),result,oracle.graph):
            return False
        trace = integer_arguments(result.structuredContent)
        objective = _objectives(args,trace)
        evaluated.append(objective)
        busy = sum(row["end_ms"]-row["start_ms"] for row in trace["attempts"])
        busy_met = busy <= args["max_worker_busy_ms"]
        burden_met = objective["unresolved_weight_ms"] <= args["max_unresolved_weight_ms"]
        feasible = objective["all_milestones_met"] and busy_met and burden_met
        if args["require_complete"] and not objective["global_completed"]:
            feasible = False
        candidates.append({"workers":scenario["max_parallel"],"completed":objective["global_completed"],
            "elapsed_ms":max((event["end_ms"] for event in trace["attempts"]),default=0),"worker_busy_ms":busy,
            "attempt_count":len(trace["attempts"]),"unresolved_weight_ms":objective["unresolved_weight_ms"],
            "horizon_coverage_basis_points":objective["horizon_coverage_basis_points"],"objectives_met":objective["all_milestones_met"],
            "busy_budget_met":busy_met,"burden_budget_met":burden_met,"feasible":feasible})
    winner = next((row["workers"] for row in candidates if row["feasible"]),None)
    expected = {"record_id":args["scenario"]["record_id"],"horizon_ms":args["horizon_ms"],"require_complete":args["require_complete"],
        "max_worker_busy_ms":args["max_worker_busy_ms"],"max_unresolved_weight_ms":args["max_unresolved_weight_ms"],
        "total_weight":sum(row["weight"] for row in args["weights"]),"recommended_workers":winner,"candidates":candidates,
        "snapshot":[copy.deepcopy(oracle.records[key]) for key in sorted(oracle.closure(args["scenario"]["record_id"]))]}
    return responses[0].structuredContent == expected and responses[1].structuredContent == evaluated[0]
