"""Independent interval-sweep verification of recovery capacity diagnostics."""
import copy

from .resilience import integer_arguments


def verify(oracle, action, simulated, analyzed, matches):
    expected = oracle.call("simulate_recovery_resilience", action["arguments"])
    if not matches(expected, simulated, oracle.graph):
        return False
    if expected["error"]:
        return bool(analyzed.isError)
    if analyzed.isError:
        return False
    scenario, trace = integer_arguments(action["arguments"]), integer_arguments(simulated.structuredContent)
    horizon, workers = trace["elapsed_ms"], []
    for worker in range(scenario["max_parallel"]):
        events = [event for event in trace["attempts"] if event["worker"] == worker]
        windows = [row for row in scenario["worker_outages"] if row["worker"] == worker]
        points = {0, horizon}
        for row in events + windows:
            points.update((max(0, min(horizon, row["start_ms"])), max(0, min(horizon, row["end_ms"]))))
        counts = {"busy_ms": 0, "productive_ms": 0, "failed_attempt_ms": 0, "outage_ms": 0, "idle_ms": 0}
        ordered = sorted(points)
        for start, end in zip(ordered, ordered[1:]):
            event = next((event for event in events if event["start_ms"] <= start < event["end_ms"]), None)
            if event:
                counts["busy_ms"] += end - start
                counts["productive_ms" if event["outcome"] == "succeeded" else "failed_attempt_ms"] += end - start
            else:
                counts["outage_ms" if any(row["start_ms"] <= start < row["end_ms"] for row in windows) else "idle_ms"] += end - start
        available = horizon - counts["outage_ms"]
        workers.append({"worker": worker, "capacity_ms": horizon, "available_ms": available, **counts,
            "utilization_basis_points": counts["busy_ms"] * 10000 // available if available else None})
    fields = ("capacity_ms", "available_ms", "busy_ms", "productive_ms", "failed_attempt_ms", "outage_ms", "idle_ms")
    totals = {key: sum(row[key] for row in workers) for key in fields}
    totals["utilization_basis_points"] = totals["busy_ms"] * 10000 // totals["available_ms"] if totals["available_ms"] else None
    required, additional = 0, 0
    events = sorted(trace["attempts"], key=lambda event: (event["record_id"], event["status"], event["attempt"]))
    for previous, following in zip(events, events[1:]):
        if (previous["record_id"], previous["status"]) == (following["record_id"], following["status"]):
            delay = scenario["retry_backoff_ms"] * 2 ** (previous["attempt"] - 1)
            required += delay
            additional += following["start_ms"] - previous["end_ms"] - delay
    value = {"record_id": trace["record_id"], "elapsed_ms": horizon, "workers": workers, "totals": totals,
        "retry_wait": {"required_backoff_ms": required, "additional_wait_ms": additional},
        "snapshot": [copy.deepcopy(oracle.records[key]) for key in sorted(oracle.closure(trace["record_id"]))]}
    return analyzed.structuredContent == value
