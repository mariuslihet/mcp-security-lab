"""Independent task-dependency reference for timed recovery and bottleneck previews."""
import copy
from functools import lru_cache


def preview(tool, args, graph, records, selected):
    snapshot = [copy.deepcopy(records[key]) for key in sorted(selected)]
    if tool == "rank_dependency_bottlenecks":
        ranking = []
        for seed in selected:
            reached, depths = {seed}, {seed: 0}
            for _ in selected:
                previous = dict(depths)
                for child in selected:
                    parents = [parent for parent in graph.get(child, []) if parent in previous]
                    if parents:
                        depths[child] = max(depths.get(child, 0), max(previous[parent] + 1 for parent in parents))
                        reached.add(child)
                if previous == depths:
                    break
            ranking.append({"record_id": seed, "impacted_count": len(reached),
                "direct_dependents": sum(seed in graph.get(child, []) for child in selected),
                "unresolved_dependents": sum(records[key]["status"] != "resolved" for key in reached - {seed}),
                "downstream_depth": max(depths.values())})
        ranking.sort(key=lambda row: (-row["impacted_count"], -row["unresolved_dependents"], row["record_id"]))
        return {"record_id": args["record_id"], "node_count": len(selected), "ranking": ranking[:args["limit"]], "snapshot": snapshot}
    overrides = {row["record_id"]: row for row in args["durations"]}
    if len(overrides) != len(args["durations"]) or not set(overrides) <= set(selected):
        return None
    jobs = {}
    for key in selected:
        record = records[key]
        for status in (["investigating", "resolved"] if record["status"] == "open" else ["resolved"] if record["status"] == "investigating" else []):
            jobs[(key, status)] = {"record_id": key, "status": status,
                "expected_version": record["version"] + int(status == "resolved" and record["status"] == "open")}
    predecessors, costs = {}, {}
    for token in jobs:
        key, status = token
        predecessors[token] = ({(parent, "resolved") for parent in graph.get(key, [])} | {(key, "investigating")}) & jobs.keys() if status == "resolved" else set()
        costs[token] = overrides.get(key, {}).get("investigate_ms" if status == "investigating" else "resolve_ms", 1)
    @lru_cache(None)
    def earliest_end(token):
        return costs[token] + max((earliest_end(parent) for parent in predecessors[token]), default=0)
    pending, started, finished, events, now = set(jobs), {}, set(), [], 0
    workers = args["max_parallel"]
    while pending or len(finished) < len(jobs):
        finished = {token for token, event in started.items() if event["end_ms"] <= now}
        busy = {event["worker"] for event in started.values() if event["end_ms"] > now}
        ready = sorted((token for token in pending if predecessors[token] <= finished), key=lambda token: (token[1] != "resolved", token[0]))
        for worker, token in zip(sorted(set(range(workers)) - busy), ready):
            event = {**jobs[token], "worker": worker, "start_ms": now, "end_ms": now + costs[token]}
            events.append(event)
            started[token] = event
            pending.remove(token)
        future = [event["end_ms"] for event in events if event["end_ms"] > now]
        if not future:
            break
        now = min(future)
    work = sum(costs.values())
    return {"record_id": args["record_id"], "max_parallel": workers, "events": events, "makespan_ms": now,
            "total_work_ms": work, "critical_path_ms": max(map(earliest_end, jobs), default=0),
            "worker_lower_bound_ms": (work + workers - 1) // workers, "snapshot": snapshot}
