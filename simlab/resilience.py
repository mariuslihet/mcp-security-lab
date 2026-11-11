"""Logical recovery faults and independent legality checks for attempt traces."""
import copy

from jsonschema import Draft202012Validator


TASK = {"type": "object", "additionalProperties": False, "required": ["record_id", "status"],
        "properties": {"record_id": {"type": "string"}, "status": {"enum": ["investigating", "resolved"]}}}
RECORD = {"type": "object", "additionalProperties": False, "required": ["id", "status", "version"],
          "properties": {"id": {"type": "string"}, "status": {"enum": ["open", "investigating", "resolved"]},
                         "version": {"type": "integer", "minimum": 1}}}
ATTEMPT = {"type": "object", "additionalProperties": False,
    "required": ["record_id", "status", "expected_version", "attempt", "worker", "start_ms", "end_ms", "outcome", "reason"],
    "properties": {**TASK["properties"], "expected_version": {"type": "integer", "minimum": 1},
        "attempt": {"type": "integer", "minimum": 1, "maximum": 4}, "worker": {"type": "integer", "minimum": 0, "maximum": 15},
        "start_ms": {"type": "integer", "minimum": 0}, "end_ms": {"type": "integer", "minimum": 1},
        "outcome": {"enum": ["succeeded", "retry", "exhausted"]},
        "reason": {"enum": ["none", "injected_failure", "worker_outage"]}}}
TRACE_SCHEMA = {"type": "object", "additionalProperties": False,
    "required": ["record_id", "max_parallel", "attempts", "completed", "elapsed_ms", "retry_count", "failed_tasks", "blocked_tasks", "unfinished_records", "snapshot", "final_records"],
    "properties": {"record_id": {"type": "string"}, "max_parallel": {"type": "integer", "minimum": 1, "maximum": 16},
        "attempts": {"type": "array", "maxItems": 1024, "items": ATTEMPT}, "completed": {"type": "boolean"},
        "elapsed_ms": {"type": "integer", "minimum": 0}, "retry_count": {"type": "integer", "minimum": 0},
        **{key: {"type": "array", "maxItems": 256, "uniqueItems": True, "items": TASK} for key in ("failed_tasks", "blocked_tasks")},
        "unfinished_records": {"type": "array", "maxItems": 128, "uniqueItems": True, "items": {"type": "string"}},
        **{key: {"type": "array", "minItems": 1, "maxItems": 128, "items": RECORD} for key in ("snapshot", "final_records")}}}


def closure(target, graph):
    selected, todo = set(), [target]
    while todo:
        key = todo.pop()
        if key not in selected:
            selected.add(key)
            todo.extend(graph.get(key, []))
    return sorted(selected)


def simulate(args, graph, records):
    selected = closure(args["record_id"], graph)
    initial = [copy.deepcopy(records[key]) for key in selected]
    proposed = {record["id"]: copy.deepcopy(record) for record in initial}
    durations = {row["record_id"]: row for row in args["durations"]}
    faults = {(row["record_id"], row["status"]): row["failed_attempts"] for row in args["faults"]}
    outages = {worker: sorted((row["start_ms"], row["end_ms"]) for row in args["worker_outages"] if row["worker"] == worker)
               for worker in range(args["max_parallel"])}
    jobs, predecessors = {}, {}
    for key in selected:
        record = records[key]
        phases = ["investigating", "resolved"] if record["status"] == "open" else ["resolved"] if record["status"] == "investigating" else []
        for status in phases:
            jobs[(key, status)] = {"state": "pending", "attempt": 0, "eligible": 0,
                "version": record["version"] + int(status == "resolved" and record["status"] == "open")}
    for token in jobs:
        key, status = token
        predecessors[token] = ({(parent, "resolved") for parent in graph.get(key, [])} | {(key, "investigating")}) & jobs.keys() if status == "resolved" else set()
    now, attempts, running = 0, [], {}
    while True:
        for token, event in list(running.items()):
            if event["end_ms"] > now:
                continue
            del running[token]
            job = jobs[token]
            if event["outcome"] == "succeeded":
                job["state"] = "succeeded"
                proposed[token[0]].update(status=token[1], version=job["version"] + 1)
            elif event["outcome"] == "exhausted":
                job["state"] = "exhausted"
            else:
                job["state"] = "pending"
                job["eligible"] = now + args["retry_backoff_ms"] * 2 ** (job["attempt"] - 1)
        while True:
            blocked = [token for token, job in jobs.items() if job["state"] == "pending"
                       and any(jobs[parent]["state"] in ("exhausted", "blocked") for parent in predecessors[token])]
            if not blocked:
                break
            for token in blocked:
                jobs[token]["state"] = "blocked"
        if all(job["state"] in ("succeeded", "exhausted", "blocked") for job in jobs.values()):
            break
        busy = {event["worker"] for event in running.values()}
        idle = [worker for worker in range(args["max_parallel"]) if worker not in busy
                and not any(start <= now < end for start, end in outages[worker])]
        ready = sorted((token for token, job in jobs.items() if job["state"] == "pending" and job["eligible"] <= now
                        and all(jobs[parent]["state"] == "succeeded" for parent in predecessors[token])),
                       key=lambda token: (token[1] != "resolved", token[0]))
        for worker, token in zip(idle, ready):
            key, status = token
            job = jobs[token]
            job["attempt"] += 1
            end = now + durations.get(key, {}).get("investigate_ms" if status == "investigating" else "resolve_ms", 1)
            cuts = [start for start, _ in outages[worker] if now < start < end]
            reason = "none"
            if cuts:
                end, reason = min(cuts), "worker_outage"
            elif job["attempt"] <= faults.get(token, 0):
                reason = "injected_failure"
            outcome = "succeeded" if reason == "none" else "exhausted" if job["attempt"] == args["max_attempts"] else "retry"
            event = {"record_id": key, "status": status, "expected_version": job["version"], "attempt": job["attempt"],
                     "worker": worker, "start_ms": now, "end_ms": end, "outcome": outcome, "reason": reason}
            attempts.append(event)
            running[token] = event
            job["state"] = "running"
        future = [event["end_ms"] for event in running.values()]
        future += [job["eligible"] for job in jobs.values() if job["state"] == "pending" and job["eligible"] > now]
        future += [end for periods in outages.values() for _, end in periods if end > now]
        if not future:
            raise ValueError("resilience_schedule_blocked")
        now = min(future)
    def task_list(state):
        return [{"record_id": key, "status": status} for (key, status), job in sorted(jobs.items()) if job["state"] == state]
    failed, blocked = task_list("exhausted"), task_list("blocked")
    return {"record_id": args["record_id"], "max_parallel": args["max_parallel"], "attempts": attempts,
            "completed": not failed and not blocked, "elapsed_ms": max((event["end_ms"] for event in attempts), default=0),
            "retry_count": sum(event["attempt"] > 1 for event in attempts), "failed_tasks": failed, "blocked_tasks": blocked,
            "unfinished_records": sorted({key for (key, _), job in jobs.items() if job["state"] != "succeeded"}),
            "snapshot": initial, "final_records": [proposed[key] for key in selected]}


def audit(args, graph, records, trace):
    """Replay claimed evidence; never call the simulator or assume its dispatch order."""
    if not Draft202012Validator(TRACE_SCHEMA).is_valid(trace):
        return {"valid": False, "violations": ["invalid_trace_shape"]}
    errors = set()
    selected = closure(args["record_id"], graph)
    snapshot = [copy.deepcopy(records[key]) for key in selected]
    if trace["snapshot"] != snapshot:
        errors.add("snapshot_mismatch")
    if trace["record_id"] != args["record_id"] or trace["max_parallel"] != args["max_parallel"]:
        errors.add("scenario_mismatch")
    costs = {row["record_id"]: row for row in args["durations"]}
    faults = {(row["record_id"], row["status"]): row["failed_attempts"] for row in args["faults"]}
    versions, requirements = {}, {}
    for record in snapshot:
        key, status = record["id"], record["status"]
        if status == "open":
            versions[(key, "investigating")] = record["version"]
        if status != "resolved":
            versions[(key, "resolved")] = record["version"] + (status == "open")
    for key, status in versions:
        needed = [(parent, "resolved") for parent in graph.get(key, [])] + [(key, "investigating")] if status == "resolved" else []
        requirements[(key, status)] = set(needed) & versions.keys()
    groups = {token: [] for token in versions}
    workers = {}
    for event in trace["attempts"]:
        token = (event["record_id"], event["status"])
        if token not in groups:
            errors.add("unexpected_task")
            continue
        groups[token].append(event)
        workers.setdefault(event["worker"], []).append(event)
        if event["worker"] >= args["max_parallel"]:
            errors.add("invalid_worker")
        if event["expected_version"] != versions[token]:
            errors.add("version_mismatch")
    for events in workers.values():
        ordered = sorted(events, key=lambda row: (row["start_ms"], row["end_ms"]))
        if any(left["end_ms"] > right["start_ms"] for left, right in zip(ordered, ordered[1:])):
            errors.add("worker_overlap")
    outcomes, success_times = {}, {}
    for token, events in groups.items():
        previous = None
        for number, event in enumerate(sorted(events, key=lambda row: row["start_ms"]), 1):
            if event["attempt"] != number or number > args["max_attempts"]:
                errors.add("attempt_budget_mismatch")
            if previous is not None and event["start_ms"] < previous["end_ms"] + args["retry_backoff_ms"] * 2 ** (number - 2):
                errors.add("retry_backoff_violation")
            if token in outcomes:
                errors.add("attempt_after_terminal_outcome")
            periods = [row for row in args["worker_outages"] if row["worker"] == event["worker"]]
            if any(row["start_ms"] <= event["start_ms"] < row["end_ms"] for row in periods):
                errors.add("dispatch_during_outage")
            key, status = token
            end = event["start_ms"] + costs.get(key, {}).get("investigate_ms" if status == "investigating" else "resolve_ms", 1)
            interruptions = [row["start_ms"] for row in periods if event["start_ms"] < row["start_ms"] < end]
            reason = "worker_outage" if interruptions else "injected_failure" if number <= faults.get(token, 0) else "none"
            if interruptions:
                end = min(interruptions)
            outcome = "succeeded" if reason == "none" else "exhausted" if number == args["max_attempts"] else "retry"
            if event["end_ms"] != end or event["reason"] != reason or event["outcome"] != outcome:
                errors.add("attempt_result_mismatch")
            if outcome != "retry":
                outcomes[token] = outcome
                if outcome == "succeeded":
                    success_times[token] = end
            previous = event
        if events and token not in outcomes:
            errors.add("incomplete_attempt_chain")
    while True:
        blocked = [token for token in versions if token not in outcomes
                   and any(outcomes.get(parent) in ("exhausted", "blocked") for parent in requirements[token])]
        if not blocked:
            break
        outcomes.update({token: "blocked" for token in blocked})
    for token, events in groups.items():
        if token not in outcomes:
            errors.add("missing_task")
        if events and any(parent not in success_times or success_times[parent] > min(row["start_ms"] for row in events)
                          for parent in requirements[token]):
            errors.add("prerequisite_violation")
    def tasks(state):
        return [{"record_id": key, "status": status} for key, status in sorted(versions) if outcomes.get((key, status)) == state]
    expected = {"failed_tasks": tasks("exhausted"), "blocked_tasks": tasks("blocked"),
        "unfinished_records": sorted({key for key, status in versions if outcomes.get((key, status)) != "succeeded"}),
        "completed": all(outcomes.get(token) == "succeeded" for token in versions),
        "elapsed_ms": max((event["end_ms"] for event in trace["attempts"]), default=0),
        "retry_count": sum(event["attempt"] > 1 for event in trace["attempts"])}
    final = {row["id"]: copy.deepcopy(row) for row in snapshot}
    for key, status in sorted(versions):
        if outcomes.get((key, status)) == "succeeded":
            final[key].update(status=status, version=versions[(key, status)] + 1)
    expected["final_records"] = [final[key] for key in selected]
    if any(trace[key] != value for key, value in expected.items()):
        errors.add("summary_mismatch")
    return {"valid": not errors, "violations": sorted(errors)}
