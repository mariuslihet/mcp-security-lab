"""Counterfactual policy comparisons and evidence-backed recovery deadlines."""
import copy

from .resilience import RECORD, closure, simulate


STRATEGY_SCHEMA = {"type": "object", "additionalProperties": False,
    "required": ["label", "max_parallel", "max_attempts", "retry_backoff_ms"],
    "properties": {"label": {"type": "string", "pattern": "^[A-Za-z0-9_-]{1,40}$"},
        "max_parallel": {"type": "integer", "minimum": 1, "maximum": 16},
        "max_attempts": {"type": "integer", "minimum": 1, "maximum": 4},
        "retry_backoff_ms": {"type": "integer", "minimum": 0, "maximum": 1000}}}
DEADLINES_SCHEMA = {"type": "array", "minItems": 1, "maxItems": 128, "items": {
    "type": "object", "additionalProperties": False, "required": ["record_id", "deadline_ms"],
    "properties": {"record_id": {"type": "string"}, "deadline_ms": {"type": "integer", "minimum": 0, "maximum": 1000000}}}}
COMPARISON_SCHEMA = {"type": "object", "additionalProperties": False,
    "required": ["record_id", "deadline_ms", "strategies", "best_strategy", "snapshot"],
    "properties": {"record_id": {"type": "string"}, "deadline_ms": {"type": "integer", "minimum": 0},
        "best_strategy": {"type": ["string", "null"]}, "snapshot": {"type": "array", "items": RECORD},
        "strategies": {"type": "array", "minItems": 2, "maxItems": 8, "items": {
            "type": "object", "additionalProperties": False,
            "required": ["label", "completed", "elapsed_ms", "attempt_count", "retry_count", "unfinished_count", "deadline_met", "worker_busy_ms"],
            "properties": {"label": {"type": "string"}, "completed": {"type": "boolean"}, "deadline_met": {"type": "boolean"},
                **{key: {"type": "integer", "minimum": 0} for key in ("elapsed_ms", "attempt_count", "retry_count", "unfinished_count", "worker_busy_ms")}}}}}}
DEADLINE_RESULT_SCHEMA = {"type": "object", "additionalProperties": False,
    "required": ["record_id", "all_met", "met_count", "late_count", "unfinished_count", "targets", "snapshot"],
    "properties": {"record_id": {"type": "string"}, "all_met": {"type": "boolean"},
        **{key: {"type": "integer", "minimum": 0} for key in ("met_count", "late_count", "unfinished_count")},
        "snapshot": {"type": "array", "items": RECORD}, "targets": {"type": "array", "maxItems": 128, "items": {
            "type": "object", "additionalProperties": False,
            "required": ["record_id", "deadline_ms", "completion_ms", "lateness_ms", "outcome", "cause", "retry_count"],
            "properties": {"record_id": {"type": "string"}, "deadline_ms": {"type": "integer", "minimum": 0},
                "retry_count": {"type": "integer", "minimum": 0},
                "completion_ms": {"type": ["integer", "null"], "minimum": 0}, "lateness_ms": {"type": ["integer", "null"], "minimum": 0},
                "outcome": {"enum": ["met", "late", "unfinished"]},
                "cause": {"enum": ["none", "deadline_exceeded", "attempts_exhausted", "dependency_blocked"]}}}}}}


def strategy_scenario(base, strategy):
    return {**copy.deepcopy(base), **{key: strategy[key] for key in ("max_parallel", "max_attempts", "retry_backoff_ms")}}


def compare(arguments, graph, records):
    base, rows = arguments["scenario"], []
    for strategy in arguments["strategies"]:
        trace = simulate(strategy_scenario(base, strategy), graph, records)
        rows.append({"label": strategy["label"], "completed": trace["completed"], "elapsed_ms": trace["elapsed_ms"],
            "attempt_count": len(trace["attempts"]), "retry_count": trace["retry_count"],
            "unfinished_count": len(trace["unfinished_records"]),
            "deadline_met": trace["completed"] and trace["elapsed_ms"] <= arguments["deadline_ms"],
            "worker_busy_ms": sum(row["end_ms"] - row["start_ms"] for row in trace["attempts"])})
    eligible = [row for row in rows if row["completed"]]
    winner = min(eligible, key=lambda row: (row["elapsed_ms"], row["attempt_count"], row["label"])) if eligible else None
    return {"record_id": base["record_id"], "deadline_ms": arguments["deadline_ms"], "strategies": rows,
            "best_strategy": winner["label"] if winner else None,
            "snapshot": [copy.deepcopy(records[key]) for key in closure(base["record_id"], graph)]}


def deadlines(trace, requested):
    initial = {row["id"]: row for row in trace["snapshot"]}
    resolved = {row["record_id"]: row["end_ms"] for row in trace["attempts"]
                if row["status"] == "resolved" and row["outcome"] == "succeeded"}
    exhausted = {row["record_id"] for row in trace["failed_tasks"]}
    rows = []
    for request in sorted(requested, key=lambda row: row["record_id"]):
        key, limit = request["record_id"], request["deadline_ms"]
        completion = 0 if initial[key]["status"] == "resolved" else resolved.get(key)
        outcome = "unfinished" if completion is None else "met" if completion <= limit else "late"
        cause = ("attempts_exhausted" if key in exhausted else "dependency_blocked") if outcome == "unfinished" else (
            "deadline_exceeded" if outcome == "late" else "none")
        rows.append({"record_id": key, "deadline_ms": limit, "completion_ms": completion,
            "lateness_ms": None if completion is None else max(0, completion - limit), "outcome": outcome, "cause": cause,
            "retry_count": sum(row["attempt"] > 1 for row in trace["attempts"] if row["record_id"] == key)})
    return {"record_id": trace["record_id"], "all_met": all(row["outcome"] == "met" for row in rows),
            **{field: sum(row["outcome"] == outcome for row in rows)
               for field, outcome in (("met_count", "met"), ("late_count", "late"), ("unfinished_count", "unfinished"))},
            "targets": rows, "snapshot": copy.deepcopy(trace["snapshot"])}
