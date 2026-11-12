"""Independently enumerate counterfactual witnesses and verify reported metrics."""
import copy


def selected(root, graph):
    found, queue = set(), [root]
    while queue:
        key = queue.pop()
        if key not in found:
            found.add(key)
            queue.extend(graph.get(key, []))
    return sorted(found)


def witnesses(action, graph):
    from .resilience import integer_arguments
    action = integer_arguments(action)
    search, sensitivity = action["mitigation"], action["sensitivity"]
    refs = sorted(search["candidates"], key=lambda row: (row["kind"], row["index"]))
    subsets = [tuple(refs[index] for index in range(len(refs)) if mask & (1 << index))
               for mask in range(1 << len(refs)) if mask.bit_count() <= search["max_removals"]]
    subsets.sort(key=lambda rows: (len(rows), tuple((row["kind"], row["index"]) for row in rows)))
    visited = subsets[:search["max_evaluations"]]
    scenarios = []
    for subset in visited:
        base = copy.deepcopy(search["scenario"])
        for field, kind in (("faults", "fault"), ("worker_outages", "outage")):
            base[field] = [row for index, row in enumerate(base[field]) if not any(ref["kind"] == kind and ref["index"] == index for ref in subset)]
        scenarios.append(base)
    percentages = sorted(sensitivity["duration_percent"])
    base = sensitivity["scenario"]
    for percentage in percentages:
        variant = copy.deepcopy(base)
        costs = {row["record_id"]: row for row in base["durations"]}
        variant["durations"] = [{"record_id": key, **{phase: -(-costs.get(key, {}).get(phase, 1) * percentage // 100)
            for phase in ("investigate_ms", "resolve_ms")}} for key in selected(base["record_id"], graph)]
        scenarios.append(variant)
    return scenarios, visited, len(subsets), percentages


def verify(oracle, action, responses, matches):
    scenarios, removed, total, percentages = witnesses(action, oracle.graph)
    if len(responses) != 2 + len(scenarios) or responses[0].isError or responses[1].isError:
        return False
    traces = []
    for scenario, result in zip(scenarios, responses[2:]):
        expected = oracle.call("simulate_recovery_resilience", scenario)
        if expected["error"] or not matches(expected, result, oracle.graph):
            return False
        traces.append(result.structuredContent)
    def metrics(trace, deadline):
        elapsed = max((event["end_ms"] for event in trace["attempts"]), default=0)
        unfinished = sum(row["status"] != "resolved" for row in trace["final_records"])
        return {"completed": unfinished == 0, "elapsed_ms": elapsed, "attempt_count": len(trace["attempts"]),
                "retry_count": sum(event["attempt"] > 1 for event in trace["attempts"]), "unfinished_count": unfinished,
                "deadline_met": unfinished == 0 and elapsed <= deadline}
    search, sensitivity = action["mitigation"], action["sensitivity"]
    trials = [{"removed": [dict(ref) for ref in subset], **metrics(trace, search["deadline_ms"])}
              for subset, trace in zip(removed, traces)]
    feasible = [index for index, row in enumerate(trials) if row["deadline_met"]]
    feasible.sort(key=lambda index: (len(trials[index]["removed"]), trials[index]["elapsed_ms"], trials[index]["attempt_count"],
                  tuple((ref["kind"], ref["index"]) for ref in trials[index]["removed"])))
    search_snapshot = [copy.deepcopy(oracle.records[key]) for key in selected(search["scenario"]["record_id"], oracle.graph)]
    expected_search = {"record_id": search["scenario"]["record_id"], "deadline_ms": search["deadline_ms"],
        "total_trials": total, "evaluated_trials": len(trials), "search_complete": len(trials) == total,
        "best_trial": feasible[0] if feasible else None, "trials": trials, "snapshot": search_snapshot}
    samples = [{"duration_percent": percentage, **metrics(trace, sensitivity["deadline_ms"])}
               for percentage, trace in zip(percentages, traces[len(removed):])]
    completed = [row["elapsed_ms"] for row in samples if row["completed"]]
    expected_sensitivity = {"record_id": sensitivity["scenario"]["record_id"], "deadline_ms": sensitivity["deadline_ms"],
        "samples": samples, "robust_across_samples": all(row["deadline_met"] for row in samples),
        "worst_completed_elapsed_ms": max(completed) if completed else None,
        "snapshot": [copy.deepcopy(oracle.records[key]) for key in selected(sensitivity["scenario"]["record_id"], oracle.graph)]}
    return responses[0].structuredContent == expected_search and responses[1].structuredContent == expected_sensitivity
