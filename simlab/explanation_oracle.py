"""Independent overlap accounting and reverse-distance failure-path verification."""
import copy
from collections import deque

from jsonschema import Draft202012Validator

from .recovery_explanations import WAITS_OUTPUT, FAILURES_OUTPUT
from .resilience import integer_arguments


def verify(oracle, action, responses, matches):
    if len(responses) != 3 or any(result.isError for result in responses):
        return False
    scenario = integer_arguments(action["arguments"])
    if not matches(oracle.call("simulate_recovery_resilience", scenario), responses[0], oracle.graph):
        return False
    if (not Draft202012Validator(WAITS_OUTPUT).is_valid(responses[1].structuredContent)
            or not Draft202012Validator(FAILURES_OUTPUT).is_valid(responses[2].structuredContent)):
        return False
    trace = integer_arguments(responses[0].structuredContent)
    initial = {row["id"]: row for row in trace["snapshot"]}
    tasks = set()
    for key, row in initial.items():
        if row["status"] == "open": tasks.add((key, "investigating"))
        if row["status"] != "resolved": tasks.add((key, "resolved"))
    parents = {}
    for key, phase in tasks:
        candidates = [] if phase == "investigating" else [(key, "investigating"), *[(parent, "resolved") for parent in oracle.graph.get(key, [])]]
        parents[(key, phase)] = [token for token in candidates if token in tasks]
    succeeded = {(row["record_id"], row["status"]): row["end_ms"] for row in trace["attempts"] if row["outcome"] == "succeeded"}
    horizon = trace["elapsed_ms"]
    points = sorted({0, horizon} | {max(0, min(horizon, row[field]))
        for row in trace["attempts"] + scenario["worker_outages"] for field in ("start_ms", "end_ms")})
    windows = [[], [], []]
    for start, end in zip(points, points[1:]):
        available = [worker for worker in range(scenario["max_parallel"]) if not any(
            row["worker"] == worker and row["start_ms"] <= start < row["end_ms"] for row in scenario["worker_outages"])]
        free = [worker for worker in available if not any(row["worker"] == worker and row["start_ms"] <= start < row["end_ms"]
                                                        for row in trace["attempts"])]
        windows[0 if not available else 2 if free else 1].append((start, end))
    rows = []
    for event in trace["attempts"]:
        token = (event["record_id"], event["status"])
        dependency_ready = max([0, *[succeeded[parent] for parent in parents[token]]])
        previous = next((row for row in trace["attempts"] if (row["record_id"], row["status"]) == token
                         and row["attempt"] == event["attempt"]-1), None)
        backoff = 0 if previous is None else scenario["retry_backoff_ms"] * (1 << (previous["attempt"]-1))
        retry_ready = 0 if previous is None else previous["end_ms"] + backoff
        ready = max(dependency_ready, retry_ready)
        overlap = [sum(max(0, min(end, event["start_ms"])-max(start, ready)) for start, end in intervals) for intervals in windows]
        rows.append({"record_id": token[0], "status": token[1], "attempt": event["attempt"], "worker": event["worker"],
            "dependency_ready_ms": dependency_ready, "retry_ready_ms": retry_ready, "ready_ms": ready,
            "start_ms": event["start_ms"], "waiting_ms": event["start_ms"]-ready, "outage_wait_ms": overlap[0],
            "busy_wait_ms": overlap[1], "dispatch_gap_ms": overlap[2], "required_backoff_ms": backoff})
    rows.sort(key=lambda row: (row["start_ms"], row["worker"], row["record_id"], row["status"], row["attempt"]))
    totals = {key: sum(row[key] for row in rows) for key in ("waiting_ms", "outage_wait_ms", "busy_wait_ms", "dispatch_gap_ms", "required_backoff_ms")}
    summaries = [{"record_id": key, **{field: sum(row[field] for row in rows if row["record_id"] == key)
                  for field in ("waiting_ms", "required_backoff_ms")}} for key in {row["record_id"] for row in rows}]
    summaries.sort(key=lambda row: (-row["waiting_ms"], -row["required_backoff_ms"], row["record_id"]))
    expected_waits = {"record_id": trace["record_id"], "elapsed_ms": horizon, "attempts": rows,
                      "totals": totals, "record_totals": summaries, "snapshot": copy.deepcopy(trace["snapshot"])}
    failed = {(row["record_id"], row["status"]) for row in trace["failed_tasks"]}
    stopped = failed | {(row["record_id"], row["status"]) for row in trace["blocked_tasks"]}
    all_causes = {}
    def task(token): return {"record_id": token[0], "status": token[1]}
    for key in trace["unfinished_records"]:
        target = (key, "resolved")
        distance, queue = {target: 0}, deque([target])
        while queue:
            token = queue.popleft()
            for parent in parents[token]:
                if parent in stopped and parent not in distance:
                    distance[parent] = distance[token]+1;queue.append(parent)
        candidates = []
        for root in failed & distance.keys():
            path = [root]
            while path[-1] != target:
                current = path[-1]
                choices = [child for child in distance if current in parents[child] and distance[child] == distance[current]-1]
                path.append(min(choices))
            candidates.append({"root": task(root), "path": [task(token) for token in path]})
        candidates.sort(key=lambda row: (len(row["path"]), row["root"]["record_id"], row["root"]["status"]))
        all_causes[key] = candidates
    roots = []
    for token in failed:
        events = [row for row in trace["attempts"] if (row["record_id"], row["status"]) == token]
        terminal = next(row for row in events if row["outcome"] == "exhausted")
        roots.append({**task(token), "stopped_ms": terminal["end_ms"], "attempt_count": len(events), "reason": terminal["reason"],
            "affected_record_count": sum(any(cause["root"] == task(token) for cause in values) for values in all_causes.values())})
    expected_failures = {"record_id": trace["record_id"], "completed": trace["completed"], "max_causes": action["max_causes"],
        "roots": sorted(roots, key=lambda row: (-row["affected_record_count"], row["record_id"], row["status"])),
        "targets": [{"record_id": key, "cause_count": len(values), "truncated": len(values) > action["max_causes"],
                     "causes": values[:int(action["max_causes"])]} for key, values in sorted(all_causes.items())],
        "snapshot": copy.deepcopy(trace["snapshot"])}
    return responses[1].structuredContent == expected_waits and responses[2].structuredContent == expected_failures
