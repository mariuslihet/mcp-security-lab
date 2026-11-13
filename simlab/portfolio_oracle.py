"""Independent checks from separately requested, audited simulation witnesses."""
import copy

from jsonschema import Draft202012Validator

from .resilience import integer_arguments
from .recovery_portfolio import PORTFOLIO_OUTPUT, TRACE_COMPARISON_OUTPUT


def witnesses(arguments):
    args = integer_arguments(arguments)
    return [{**copy.deepcopy(sample["scenario"]), **{key: strategy[key]
             for key in ("max_parallel", "max_attempts", "retry_backoff_ms")}}
            for sample in sorted(args["scenarios"], key=lambda row: row["label"])
            for strategy in sorted(args["strategies"], key=lambda row: row["label"])]


def verify(oracle, action, responses, matches):
    args = integer_arguments(action["arguments"])
    scenarios = witnesses(args)
    if len(responses) != len(scenarios) + 2 or any(result.isError for result in responses):
        return False
    if (not Draft202012Validator(PORTFOLIO_OUTPUT).is_valid(responses[0].structuredContent)
            or not Draft202012Validator(TRACE_COMPARISON_OUTPUT).is_valid(responses[1].structuredContent)):
        return False
    traces = []
    for scenario, result in zip(scenarios, responses[2:]):
        expected = oracle.call("simulate_recovery_resilience", scenario)
        if expected["error"] or not matches(expected, result, oracle.graph):
            return False
        traces.append(integer_arguments(result.structuredContent))
    def measure(trace):
        unfinished = sum(record["status"] != "resolved" for record in trace["final_records"])
        return {"completed": unfinished == 0, "elapsed_ms": max((row["end_ms"] for row in trace["attempts"]), default=0),
            "worker_busy_ms": sum(row["end_ms"] - row["start_ms"] for row in trace["attempts"]),
            "attempt_count": len(trace["attempts"]), "retry_count": sum(row["attempt"] != 1 for row in trace["attempts"]),
            "unfinished_count": unfinished}
    samples = sorted(args["scenarios"], key=lambda row: row["label"])
    strategies = sorted(args["strategies"], key=lambda row: row["label"])
    cells = []
    for index, trace in enumerate(traces):
        sample, policy = samples[index // len(strategies)], strategies[index % len(strategies)]
        metrics = measure(trace)
        met = metrics["completed"] and metrics["elapsed_ms"] <= args["deadline_ms"]
        budget = metrics["worker_busy_ms"] <= args["max_worker_busy_ms"]
        cells.append({"scenario": sample["label"], "strategy": policy["label"], **metrics,
                      "deadline_met": met, "budget_met": budget, "eligible": met and budget})
    cells.sort(key=lambda row: (row["strategy"], row["scenario"]))
    policies = []
    for strategy in strategies:
        rows = [row for row in cells if row["strategy"] == strategy["label"]]
        finished = sum(row["completed"] for row in rows)
        policies.append({"label": strategy["label"], "completed_count": finished,
            "eligible_count": sum(row["eligible"] for row in rows),
            "worst_elapsed_ms": max(row["elapsed_ms"] for row in rows) if finished == len(samples) else None,
            "worst_worker_busy_ms": max(row["worker_busy_ms"] for row in rows),
            "total_attempt_count": sum(row["attempt_count"] for row in rows)})
    frontier = []
    for row in policies:
        dominated = False
        for other in policies:
            tests = [other["eligible_count"] - row["eligible_count"], other["completed_count"] - row["completed_count"],
                (row["worst_elapsed_ms"] if row["worst_elapsed_ms"] is not None else 10**30)
                - (other["worst_elapsed_ms"] if other["worst_elapsed_ms"] is not None else 10**30),
                row["worst_worker_busy_ms"] - other["worst_worker_busy_ms"]]
            dominated |= min(tests) >= 0 and max(tests) > 0
        if not dominated:
            frontier.append(row["label"])
    ranked = sorted((row for row in policies if row["eligible_count"] == len(samples)),
        key=lambda row: (row["worst_elapsed_ms"], row["worst_worker_busy_ms"], row["total_attempt_count"], row["label"]))
    expected_portfolio = {"record_id": scenarios[0]["record_id"], "deadline_ms": args["deadline_ms"],
        "max_worker_busy_ms": args["max_worker_busy_ms"], "scenario_count": len(samples), "cells": cells,
        "strategies": policies, "pareto_strategies": frontier, "robust_strategy": ranked[0]["label"] if ranked else None,
        "snapshot": [copy.deepcopy(oracle.records[key]) for key in sorted(oracle.closure(scenarios[0]["record_id"]))]}
    left, right = traces[:2]
    targets = []
    for record in left["snapshot"]:
        def completion(trace):
            if record["status"] == "resolved":
                return 0
            events = [row["end_ms"] for row in trace["attempts"]
                      if row["record_id"] == record["id"] and row["status"] == "resolved" and row["outcome"] == "succeeded"]
            return events[0] if events else None
        a, b = completion(left), completion(right)
        if a is None or b is None:
            change = {(True, True): "unfinished", (True, False): "recovered", (False, True): "lost"}[(a is None, b is None)]
        else:
            change = "unchanged" if a == b else "improved" if b < a else "regressed"
        targets.append({"record_id": record["id"], "baseline_completion_ms": a, "candidate_completion_ms": b,
            "delta_ms": None if a is None or b is None else b - a, "change": change,
            "baseline_deadline_met": a is not None and a <= args["deadline_ms"],
            "candidate_deadline_met": b is not None and b <= args["deadline_ms"]})
    before, after = measure(left), measure(right)
    differences = {key: after[key] - before[key] for key in before if key != "completed"}
    if before["unfinished_count"] or after["unfinished_count"]:
        differences["elapsed_ms"] = None
    expected_comparison = {"record_id": scenarios[0]["record_id"], "deadline_ms": args["deadline_ms"],
        "baseline": before, "candidate": after, "delta": differences,
        "counts": {key: sum(row["change"] == key for row in targets)
                   for key in ("improved", "regressed", "unchanged", "recovered", "lost", "unfinished")},
        "targets": sorted(targets, key=lambda row: row["record_id"]), "snapshot": expected_portfolio["snapshot"]}
    return responses[0].structuredContent == expected_portfolio and responses[1].structuredContent == expected_comparison
