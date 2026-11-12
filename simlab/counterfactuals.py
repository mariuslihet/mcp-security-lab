"""Bounded disruption-removal searches and logical-duration perturbations."""
import copy
import itertools

from .resilience import RECORD, closure, simulate, integer_arguments


CANDIDATE = {"type": "object", "additionalProperties": False, "required": ["kind", "index"],
             "properties": {"kind": {"enum": ["fault", "outage"]}, "index": {"type": "integer", "minimum": 0, "maximum": 127}}}
CANDIDATES = {"type": "array", "minItems": 1, "maxItems": 8, "uniqueItems": True, "items": CANDIDATE}
PERCENTAGES = {"type": "array", "minItems": 2, "maxItems": 8, "uniqueItems": True,
               "items": {"type": "integer", "minimum": 25, "maximum": 400}}
METRICS = {"completed": {"type": "boolean"}, "deadline_met": {"type": "boolean"},
           **{key: {"type": "integer", "minimum": 0} for key in ("elapsed_ms", "attempt_count", "retry_count", "unfinished_count")}}
SEARCH_OUTPUT = {"type": "object", "additionalProperties": False,
    "required": ["record_id", "deadline_ms", "total_trials", "evaluated_trials", "search_complete", "best_trial", "trials", "snapshot"],
    "properties": {"record_id": {"type": "string"}, "deadline_ms": {"type": "integer", "minimum": 0},
        "total_trials": {"type": "integer", "minimum": 1, "maximum": 37}, "evaluated_trials": {"type": "integer", "minimum": 1, "maximum": 37},
        "search_complete": {"type": "boolean"}, "best_trial": {"type": ["integer", "null"], "minimum": 0},
        "snapshot": {"type": "array", "items": RECORD}, "trials": {"type": "array", "maxItems": 37, "items": {
            "type": "object", "additionalProperties": False, "required": ["removed", *METRICS],
            "properties": {"removed": {"type": "array", "maxItems": 2, "items": CANDIDATE}, **METRICS}}}}}
SENSITIVITY_OUTPUT = {"type": "object", "additionalProperties": False,
    "required": ["record_id", "deadline_ms", "samples", "robust_across_samples", "worst_completed_elapsed_ms", "snapshot"],
    "properties": {"record_id": {"type": "string"}, "deadline_ms": {"type": "integer", "minimum": 0},
        "robust_across_samples": {"type": "boolean"}, "worst_completed_elapsed_ms": {"type": ["integer", "null"], "minimum": 0},
        "snapshot": {"type": "array", "items": RECORD}, "samples": {"type": "array", "minItems": 2, "maxItems": 8, "items": {
            "type": "object", "additionalProperties": False, "required": ["duration_percent", *METRICS],
            "properties": {"duration_percent": {"type": "integer", "minimum": 25, "maximum": 400}, **METRICS}}}}}


def removals(arguments):
    candidates = sorted(arguments["candidates"], key=lambda row: (row["kind"], row["index"]))
    trials = [()]
    for size in range(1, arguments["max_removals"] + 1):
        trials.extend(itertools.combinations(candidates, size))
    return trials


def removed_scenario(base, removed):
    variant = copy.deepcopy(base)
    for kind, field in (("fault", "faults"), ("outage", "worker_outages")):
        excluded = {row["index"] for row in removed if row["kind"] == kind}
        variant[field] = [row for index, row in enumerate(variant[field]) if index not in excluded]
    return variant


def scaled_scenario(base, selected, percentage):
    variant = copy.deepcopy(base)
    overrides = {row["record_id"]: row for row in base["durations"]}
    variant["durations"] = [{"record_id": key, **{phase: (overrides.get(key, {}).get(phase, 1) * percentage + 99) // 100
        for phase in ("investigate_ms", "resolve_ms")}} for key in sorted(selected)]
    if any(row[phase] > 1000 for row in variant["durations"] for phase in ("investigate_ms", "resolve_ms")):
        raise ValueError("scaled_duration_out_of_bounds")
    return variant


def metrics(trace, deadline):
    return {"completed": trace["completed"], "elapsed_ms": trace["elapsed_ms"], "attempt_count": len(trace["attempts"]),
            "retry_count": trace["retry_count"], "unfinished_count": len(trace["unfinished_records"]),
            "deadline_met": trace["completed"] and trace["elapsed_ms"] <= deadline}


def mitigation_search(arguments, graph, records):
    arguments = integer_arguments(arguments)
    base, trials = arguments["scenario"], []
    combinations = removals(arguments)
    for removed in combinations[:arguments["max_evaluations"]]:
        trace = simulate(removed_scenario(base, removed), graph, records)
        trials.append({"removed": [dict(row) for row in removed], **metrics(trace, arguments["deadline_ms"])})
    eligible = [index for index, row in enumerate(trials) if row["deadline_met"]]
    winner = min(eligible, key=lambda index: (len(trials[index]["removed"]), trials[index]["elapsed_ms"],
                 trials[index]["attempt_count"], tuple((row["kind"], row["index"]) for row in trials[index]["removed"]))) if eligible else None
    return {"record_id": base["record_id"], "deadline_ms": arguments["deadline_ms"], "total_trials": len(combinations),
            "evaluated_trials": len(trials), "search_complete": len(trials) == len(combinations), "best_trial": winner, "trials": trials,
            "snapshot": [copy.deepcopy(records[key]) for key in closure(base["record_id"], graph)]}


def duration_sensitivity(arguments, graph, records):
    arguments = integer_arguments(arguments)
    base, rows = arguments["scenario"], []
    selected = closure(base["record_id"], graph)
    for percentage in sorted(arguments["duration_percent"]):
        trace = simulate(scaled_scenario(base, selected, percentage), graph, records)
        rows.append({"duration_percent": percentage, **metrics(trace, arguments["deadline_ms"])})
    completed = [row["elapsed_ms"] for row in rows if row["completed"]]
    return {"record_id": base["record_id"], "deadline_ms": arguments["deadline_ms"], "samples": rows,
            "robust_across_samples": all(row["deadline_met"] for row in rows),
            "worst_completed_elapsed_ms": max(completed) if completed else None,
            "snapshot": [copy.deepcopy(records[key]) for key in selected]}
