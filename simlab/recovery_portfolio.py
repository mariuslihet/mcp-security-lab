"""Bounded cross-scenario policy evaluation and audited trace differences."""
import copy

from .recovery_decisions import strategy_scenario
from .resilience import RECORD, closure, integer_arguments, simulate


def closed(properties):
    return {"type": "object", "additionalProperties": False, "required": list(properties), "properties": properties}


NAT = {"type": "integer", "minimum": 0}
NULL_TIME = {"type": ["integer", "null"], "minimum": 0}
LABEL = {"type": "string", "pattern": "^[A-Za-z0-9_-]{1,40}$"}
METRICS = {"completed": {"type": "boolean"}, "elapsed_ms": NAT, "worker_busy_ms": NAT,
           "attempt_count": NAT, "retry_count": NAT, "unfinished_count": NAT}
CELL = closed({"scenario": LABEL, "strategy": LABEL, **METRICS,
    "deadline_met": {"type": "boolean"}, "budget_met": {"type": "boolean"}, "eligible": {"type": "boolean"}})
POLICY = closed({"label": LABEL, "eligible_count": NAT, "completed_count": NAT,
    "worst_elapsed_ms": NULL_TIME, "worst_worker_busy_ms": NAT, "total_attempt_count": NAT})
PORTFOLIO_OUTPUT = closed({"record_id": {"type": "string"}, "deadline_ms": NAT, "max_worker_busy_ms": NAT,
    "scenario_count": {"type": "integer", "minimum": 2, "maximum": 8},
    "cells": {"type": "array", "minItems": 4, "maxItems": 64, "items": CELL},
    "strategies": {"type": "array", "minItems": 2, "maxItems": 8, "items": POLICY},
    "robust_strategy": {"type": ["string", "null"]},
    "pareto_strategies": {"type": "array", "maxItems": 8, "uniqueItems": True, "items": LABEL},
    "snapshot": {"type": "array", "minItems": 1, "maxItems": 128, "items": RECORD}})
CHANGES = ("improved", "regressed", "unchanged", "recovered", "lost", "unfinished")
TRACE_COMPARISON_OUTPUT = closed({"record_id": {"type": "string"}, "deadline_ms": NAT,
    "baseline": closed(METRICS), "candidate": closed(METRICS),
    "delta": closed({"elapsed_ms": {"type": ["integer", "null"]},
        **{key: {"type": "integer"} for key in ("worker_busy_ms", "attempt_count", "retry_count", "unfinished_count")}}),
    "counts": closed({key: NAT for key in CHANGES}),
    "targets": {"type": "array", "minItems": 1, "maxItems": 128, "items": closed({
        "record_id": {"type": "string"}, "baseline_completion_ms": NULL_TIME, "candidate_completion_ms": NULL_TIME,
        "delta_ms": {"type": ["integer", "null"]}, "change": {"enum": list(CHANGES)},
        "baseline_deadline_met": {"type": "boolean"}, "candidate_deadline_met": {"type": "boolean"}})},
    "snapshot": {"type": "array", "minItems": 1, "maxItems": 128, "items": RECORD}})


def metrics(trace):
    return {"completed": trace["completed"], "elapsed_ms": trace["elapsed_ms"],
        "worker_busy_ms": sum(event["end_ms"] - event["start_ms"] for event in trace["attempts"]),
        "attempt_count": len(trace["attempts"]), "retry_count": trace["retry_count"],
        "unfinished_count": len(trace["unfinished_records"])}


def portfolio(arguments, graph, records):
    args = integer_arguments(arguments)
    cells, policies = [], []
    for strategy in sorted(args["strategies"], key=lambda row: row["label"]):
        rows = []
        for sample in sorted(args["scenarios"], key=lambda row: row["label"]):
            value = metrics(simulate(strategy_scenario(sample["scenario"], strategy), graph, records))
            deadline = value["completed"] and value["elapsed_ms"] <= args["deadline_ms"]
            budget = value["worker_busy_ms"] <= args["max_worker_busy_ms"]
            rows.append({"scenario": sample["label"], "strategy": strategy["label"], **value,
                         "deadline_met": deadline, "budget_met": budget, "eligible": deadline and budget})
        cells.extend(rows)
        policies.append({"label": strategy["label"], "eligible_count": sum(row["eligible"] for row in rows),
            "completed_count": sum(row["completed"] for row in rows),
            "worst_elapsed_ms": max(row["elapsed_ms"] for row in rows) if all(row["completed"] for row in rows) else None,
            "worst_worker_busy_ms": max(row["worker_busy_ms"] for row in rows),
            "total_attempt_count": sum(row["attempt_count"] for row in rows)})
    def cost(row):
        return (-row["eligible_count"], -row["completed_count"],
                row["worst_elapsed_ms"] if row["worst_elapsed_ms"] is not None else float("inf"), row["worst_worker_busy_ms"])
    frontier = [row["label"] for row in policies if not any(
        all(a <= b for a, b in zip(cost(other), cost(row))) and any(a < b for a, b in zip(cost(other), cost(row)))
        for other in policies)]
    eligible = [row for row in policies if row["eligible_count"] == len(args["scenarios"])]
    winner = min(eligible, key=lambda row: (row["worst_elapsed_ms"], row["worst_worker_busy_ms"],
                                           row["total_attempt_count"], row["label"])) if eligible else None
    target = args["scenarios"][0]["scenario"]["record_id"]
    return {"record_id": target, "deadline_ms": args["deadline_ms"], "max_worker_busy_ms": args["max_worker_busy_ms"],
        "scenario_count": len(args["scenarios"]), "cells": cells, "strategies": policies,
        "robust_strategy": winner["label"] if winner else None, "pareto_strategies": frontier,
        "snapshot": [copy.deepcopy(records[key]) for key in closure(target, graph)]}


def compare_traces(arguments):
    args = integer_arguments(arguments)
    baseline, candidate = args["baseline"]["trace"], args["candidate"]["trace"]
    def completions(trace):
        result = {row["id"]: 0 if row["status"] == "resolved" else None for row in trace["snapshot"]}
        result.update({event["record_id"]: event["end_ms"] for event in trace["attempts"]
                       if event["status"] == "resolved" and event["outcome"] == "succeeded"})
        return result
    before, after = completions(baseline), completions(candidate)
    rows = []
    for key in sorted(before):
        first, second = before[key], after[key]
        change = ("unfinished" if second is None else "recovered") if first is None else (
            "lost" if second is None else "improved" if second < first else "regressed" if second > first else "unchanged")
        rows.append({"record_id": key, "baseline_completion_ms": first, "candidate_completion_ms": second,
            "delta_ms": second - first if first is not None and second is not None else None, "change": change,
            "baseline_deadline_met": first is not None and first <= args["deadline_ms"],
            "candidate_deadline_met": second is not None and second <= args["deadline_ms"]})
    left, right = metrics(baseline), metrics(candidate)
    delta = {key: right[key] - left[key] for key in left if key != "completed"}
    if not (left["completed"] and right["completed"]):
        delta["elapsed_ms"] = None
    return {"record_id": baseline["record_id"], "deadline_ms": args["deadline_ms"], "baseline": left, "candidate": right,
        "delta": delta, "counts": {key: sum(row["change"] == key for row in rows) for key in CHANGES},
        "targets": rows, "snapshot": copy.deepcopy(baseline["snapshot"])}
