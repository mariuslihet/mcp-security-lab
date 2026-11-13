"""Explain audited recovery waits and failure propagation without changing state."""
from bisect import bisect_right
from collections import Counter, defaultdict, deque
import copy

from .recovery_portfolio import NAT, closed
from .resilience import RECORD, TASK, integer_arguments


WAIT_FIELDS = ("waiting_ms", "outage_wait_ms", "busy_wait_ms", "dispatch_gap_ms", "required_backoff_ms")
WAIT_ROW = closed({**TASK["properties"], **{key: NAT for key in (
    "attempt", "worker", "dependency_ready_ms", "retry_ready_ms", "ready_ms", "start_ms", *WAIT_FIELDS)}})
WAITS_OUTPUT = closed({"record_id": {"type": "string"}, "elapsed_ms": NAT,
    "attempts": {"type": "array", "maxItems": 1024, "items": WAIT_ROW},
    "totals": closed({key: NAT for key in WAIT_FIELDS}),
    "record_totals": {"type": "array", "maxItems": 128, "items": closed({
        "record_id": {"type": "string"}, "waiting_ms": NAT, "required_backoff_ms": NAT})},
    "snapshot": {"type": "array", "minItems": 1, "maxItems": 128, "items": RECORD}})
CAUSE = closed({"root": TASK, "path": {"type": "array", "minItems": 1, "maxItems": 256, "items": TASK}})
FAILURES_OUTPUT = closed({"record_id": {"type": "string"}, "completed": {"type": "boolean"},
    "max_causes": {"type": "integer", "minimum": 1, "maximum": 8},
    "roots": {"type": "array", "maxItems": 128, "items": closed({**TASK["properties"],
        "stopped_ms": NAT, "attempt_count": NAT, "reason": {"enum": ["injected_failure", "worker_outage"]},
        "affected_record_count": NAT})},
    "targets": {"type": "array", "maxItems": 128, "items": closed({"record_id": {"type": "string"},
        "cause_count": NAT, "truncated": {"type": "boolean"},
        "causes": {"type": "array", "minItems": 1, "maxItems": 8, "items": CAUSE}})},
    "snapshot": {"type": "array", "minItems": 1, "maxItems": 128, "items": RECORD}})


def requirements(snapshot, graph):
    tasks = {(row["id"], phase) for row in snapshot for phase in
             (["investigating", "resolved"] if row["status"] == "open" else ["resolved"] if row["status"] == "investigating" else [])}
    return {token: ({(parent, "resolved") for parent in graph.get(token[0], [])} | {(token[0], "investigating")}) & tasks
            if token[1] == "resolved" else set() for token in tasks}


def _capacity_integrals(scenario, trace):
    """Sweep once; prefix integrals classify ready-to-dispatch intervals cheaply."""
    horizon = trace["elapsed_ms"]
    changes = defaultdict(list, {0: [], horizon: []})
    for kind, events in (("busy", trace["attempts"]), ("outage", scenario["worker_outages"])):
        for event in events:
            start, end = max(0, event["start_ms"]), min(horizon, event["end_ms"])
            if start < end:
                changes[start].append((kind, event["worker"], 1))
                changes[end].append((kind, event["worker"], -1))
    points = sorted(changes)
    counters = {"busy": Counter(), "outage": Counter()}
    categories, prefixes = [], [[0, 0, 0]]
    for start, end in zip(points, points[1:]):
        for kind, worker, delta in changes[start]:
            counters[kind][worker] += delta
        unavailable = {worker for worker, count in counters["outage"].items() if count > 0}
        occupied = {worker for worker, count in counters["busy"].items() if count > 0}
        category = 0 if len(unavailable) == scenario["max_parallel"] else (
            1 if len(unavailable | occupied) == scenario["max_parallel"] else 2)
        categories.append(category)
        row = prefixes[-1].copy();row[category] += end-start;prefixes.append(row)
    def integral(time):
        index = bisect_right(points, time)-1
        value = prefixes[index].copy()
        if index < len(categories):
            value[categories[index]] += time-points[index]
        return value
    return integral


def waits(arguments, graph):
    args = integer_arguments(arguments)
    scenario, trace = args["scenario"], args["trace"]
    needed = requirements(trace["snapshot"], graph)
    succeeded = {(event["record_id"], event["status"]): event["end_ms"]
                 for event in trace["attempts"] if event["outcome"] == "succeeded"}
    integral = _capacity_integrals(scenario, trace)
    previous, rows = {}, []
    for event in sorted(trace["attempts"], key=lambda row: (row["start_ms"], row["worker"], row["record_id"], row["status"], row["attempt"])):
        token = (event["record_id"], event["status"])
        dependency_ready = max((succeeded[parent] for parent in needed[token]), default=0)
        backoff = scenario["retry_backoff_ms"] * 2 ** (event["attempt"]-2) if event["attempt"] > 1 else 0
        retry_ready = previous[token]["end_ms"] + backoff if token in previous else 0
        ready = max(dependency_ready, retry_ready)
        before, after = integral(ready), integral(event["start_ms"])
        outage, busy, gap = [right-left for left, right in zip(before, after)]
        rows.append({"record_id": event["record_id"], "status": event["status"], "attempt": event["attempt"],
            "worker": event["worker"], "dependency_ready_ms": dependency_ready, "retry_ready_ms": retry_ready,
            "ready_ms": ready, "start_ms": event["start_ms"], "waiting_ms": event["start_ms"]-ready,
            "outage_wait_ms": outage, "busy_wait_ms": busy, "dispatch_gap_ms": gap, "required_backoff_ms": backoff})
        previous[token] = event
    by_record = {}
    for row in rows:
        summary = by_record.setdefault(row["record_id"], {"record_id": row["record_id"], "waiting_ms": 0, "required_backoff_ms": 0})
        for key in ("waiting_ms", "required_backoff_ms"):
            summary[key] += row[key]
    return {"record_id": trace["record_id"], "elapsed_ms": trace["elapsed_ms"], "attempts": rows,
        "totals": {key: sum(row[key] for row in rows) for key in WAIT_FIELDS},
        "record_totals": sorted(by_record.values(), key=lambda row: (-row["waiting_ms"], -row["required_backoff_ms"], row["record_id"])),
        "snapshot": copy.deepcopy(trace["snapshot"])}


def failures(arguments, graph):
    args = integer_arguments(arguments)
    trace, limit = args["trace"], args["max_causes"]
    needed = requirements(trace["snapshot"], graph)
    stopped = {(row["record_id"], row["status"]) for row in trace["failed_tasks"] + trace["blocked_tasks"]}
    children = defaultdict(list)
    for child, parents in needed.items():
        if child in stopped:
            for parent in parents & stopped:
                children[parent].append(child)
    causes = defaultdict(list)
    roots = []
    def task(token):
        return {"record_id": token[0], "status": token[1]}
    for failed in sorted((row["record_id"], row["status"]) for row in trace["failed_tasks"]):
        paths, queue = {failed: [failed]}, deque([failed])
        while queue:
            current = queue.popleft()
            for child in sorted(children[current]):
                if child not in paths:
                    paths[child] = paths[current] + [child];queue.append(child)
        affected = 0
        for key in trace["unfinished_records"]:
            target = (key, "resolved")
            if target in paths:
                affected += 1
                causes[key].append({"root": task(failed), "path": [task(token) for token in paths[target]]})
        attempts = [event for event in trace["attempts"] if (event["record_id"], event["status"]) == failed]
        last = max(attempts, key=lambda event: event["attempt"])
        roots.append({**task(failed), "stopped_ms": last["end_ms"], "attempt_count": len(attempts),
                      "reason": last["reason"], "affected_record_count": affected})
    targets = []
    for key in sorted(causes):
        ranked = sorted(causes[key], key=lambda row: (len(row["path"]), row["root"]["record_id"], row["root"]["status"]))
        targets.append({"record_id": key, "cause_count": len(ranked), "truncated": len(ranked) > limit, "causes": ranked[:limit]})
    return {"record_id": trace["record_id"], "completed": trace["completed"], "max_causes": limit,
        "roots": sorted(roots, key=lambda row: (-row["affected_record_count"], row["record_id"], row["status"])),
        "targets": targets, "snapshot": copy.deepcopy(trace["snapshot"])}
