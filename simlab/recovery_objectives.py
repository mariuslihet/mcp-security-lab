"""Weighted recovery objectives and exhaustive bounded worker-pool search."""
import copy

from .recovery_portfolio import NAT, closed
from .resilience import RECORD, closure, integer_arguments, simulate


WEIGHTS = {"type": "array", "minItems": 1, "maxItems": 128, "items": closed({
    "record_id": {"type": "string"}, "weight": {"type": "integer", "minimum": 1, "maximum": 1000}})}
MILESTONES = {"type": "array", "minItems": 1, "maxItems": 16, "items": closed({
    "at_ms": {"type": "integer", "minimum": 0, "maximum": 1000000},
    "required_basis_points": {"type": "integer", "minimum": 0, "maximum": 10000}})}
POINTS = {"type": "integer", "minimum": 0, "maximum": 10000}
OBJECTIVES_OUTPUT = closed({"record_id": {"type": "string"}, "horizon_ms": NAT, "total_weight": NAT,
    "global_completed": {"type": "boolean"}, "all_targets_completed": {"type": "boolean"},
    "all_milestones_met": {"type": "boolean"}, "horizon_coverage_basis_points": POINTS,
    "unresolved_weight_ms": NAT, "time_coverage_basis_points": {"type": ["integer", "null"], "minimum": 0, "maximum": 10000},
    "targets": {"type": "array", "minItems": 1, "maxItems": 128, "items": closed({
        "record_id": {"type": "string"}, "weight": NAT, "completion_ms": {"type": ["integer", "null"], "minimum": 0}})},
    "milestones": {"type": "array", "minItems": 1, "maxItems": 16, "items": closed({
        "at_ms": NAT, "required_basis_points": POINTS, "covered_weight": NAT, "coverage_basis_points": POINTS, "met": {"type": "boolean"}})},
    "snapshot": {"type": "array", "minItems": 1, "maxItems": 128, "items": RECORD}})
CAPACITY_OUTPUT = closed({"record_id": {"type": "string"}, "horizon_ms": NAT, "require_complete": {"type": "boolean"},
    "max_worker_busy_ms": NAT, "max_unresolved_weight_ms": NAT, "total_weight": NAT,
    "recommended_workers": {"type": ["integer", "null"], "minimum": 1, "maximum": 16},
    "candidates": {"type": "array", "minItems": 1, "maxItems": 16, "items": closed({
        "workers": {"type": "integer", "minimum": 1, "maximum": 16}, "completed": {"type": "boolean"},
        "elapsed_ms": NAT, "worker_busy_ms": NAT, "attempt_count": NAT, "unresolved_weight_ms": NAT,
        "horizon_coverage_basis_points": POINTS, "objectives_met": {"type": "boolean"},
        "busy_budget_met": {"type": "boolean"}, "burden_budget_met": {"type": "boolean"}, "feasible": {"type": "boolean"}})},
    "snapshot": {"type": "array", "minItems": 1, "maxItems": 128, "items": RECORD}})


def evaluate(arguments):
    args = integer_arguments(arguments)
    trace, horizon = args["trace"], args["horizon_ms"]
    completed = {row["id"]: 0 for row in trace["snapshot"] if row["status"] == "resolved"}
    completed.update({event["record_id"]: event["end_ms"] for event in trace["attempts"]
                      if event["status"] == "resolved" and event["outcome"] == "succeeded"})
    targets = [{**row, "completion_ms": completed.get(row["record_id"])} for row in sorted(args["weights"], key=lambda row: row["record_id"])]
    total = sum(row["weight"] for row in targets)
    def covered(time):
        return sum(row["weight"] for row in targets if row["completion_ms"] is not None and row["completion_ms"] <= time)
    milestones = []
    for goal in sorted(args["milestones"], key=lambda row: row["at_ms"]):
        weight = covered(goal["at_ms"])
        milestones.append({**goal, "covered_weight": weight, "coverage_basis_points": 10000*weight//total,
                           "met": weight*10000 >= goal["required_basis_points"]*total})
    burden = sum(row["weight"] * (horizon if row["completion_ms"] is None else min(horizon,row["completion_ms"])) for row in targets)
    return {"record_id": trace["record_id"], "horizon_ms": horizon, "total_weight": total,
        "global_completed": trace["completed"], "all_targets_completed": all(row["completion_ms"] is not None for row in targets),
        "all_milestones_met": all(row["met"] for row in milestones), "horizon_coverage_basis_points": covered(horizon)*10000//total,
        "unresolved_weight_ms": burden, "time_coverage_basis_points": (total*horizon-burden)*10000//(total*horizon) if horizon else None,
        "targets": targets, "milestones": milestones, "snapshot": copy.deepcopy(trace["snapshot"])}


def capacity_search(arguments, graph, records):
    args = integer_arguments(arguments)
    rows = []
    for workers in sorted(args["worker_options"]):
        scenario = {**copy.deepcopy(args["scenario"]), "max_parallel": workers}
        trace = simulate(scenario,graph,records)
        objectives = evaluate({**args,"trace":trace})
        busy = sum(event["end_ms"]-event["start_ms"] for event in trace["attempts"])
        busy_met = busy <= args["max_worker_busy_ms"]
        burden_met = objectives["unresolved_weight_ms"] <= args["max_unresolved_weight_ms"]
        rows.append({"workers": workers, "completed": trace["completed"], "elapsed_ms": trace["elapsed_ms"],
            "worker_busy_ms": busy, "attempt_count": len(trace["attempts"]), "unresolved_weight_ms": objectives["unresolved_weight_ms"],
            "horizon_coverage_basis_points": objectives["horizon_coverage_basis_points"],
            "objectives_met": objectives["all_milestones_met"], "busy_budget_met": busy_met, "burden_budget_met": burden_met,
            "feasible": objectives["all_milestones_met"] and busy_met and burden_met and (trace["completed"] or not args["require_complete"])})
    eligible = [row["workers"] for row in rows if row["feasible"]]
    return {"record_id": args["scenario"]["record_id"], "horizon_ms": args["horizon_ms"], "require_complete": args["require_complete"],
        "max_worker_busy_ms": args["max_worker_busy_ms"], "max_unresolved_weight_ms": args["max_unresolved_weight_ms"],
        "total_weight": sum(row["weight"] for row in args["weights"]), "recommended_workers": min(eligible) if eligible else None,
        "candidates": rows, "snapshot": [copy.deepcopy(records[key]) for key in closure(args["scenario"]["record_id"],graph)]}
