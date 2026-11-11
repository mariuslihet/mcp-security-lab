"""Verify decisions using independently audited real MCP simulation witnesses."""
import copy


def verify(oracle, action, responses, matches):
    arguments = action["arguments"]
    base, strategies = arguments["scenario"], arguments["strategies"]
    count = len(strategies)
    if len(responses) != 1 + 2 * count:
        return False
    comparison, witnesses, scores = responses[0], responses[1:count + 1], responses[count + 1:]
    selected = oracle.closure(base["record_id"])
    targets = [row["record_id"] for row in action["deadlines"]]
    target_error = len(set(targets)) != len(targets) or not set(targets) <= selected
    labels = [row["label"] for row in strategies]
    comparison_error = oracle.call("simulate_recovery_resilience", base)["error"] or len(set(labels)) != len(labels)
    summaries = []
    for policy, witness, score in zip(strategies, witnesses, scores):
        variant = {**copy.deepcopy(base), **{key: policy[key] for key in ("max_parallel", "max_attempts", "retry_backoff_ms")}}
        expected = oracle.call("simulate_recovery_resilience", variant)
        if not matches(expected, witness, oracle.graph):
            return False
        comparison_error |= expected["error"]
        if expected["error"]:
            if not score.isError:
                return False
            continue
        trace = witness.structuredContent
        if action["tamper"] or target_error:
            if not score.isError:
                return False
        else:
            if score.isError:
                return False
            rows = []
            for target in sorted(action["deadlines"], key=lambda row: row["record_id"]):
                key, limit = target["record_id"], target["deadline_ms"]
                finishes = [event["end_ms"] for event in trace["attempts"] if event["record_id"] == key
                            and event["status"] == "resolved" and event["outcome"] == "succeeded"]
                completion = 0 if oracle.records[key]["status"] == "resolved" else next(iter(finishes), None)
                outcome = "unfinished" if completion is None else "late" if completion > limit else "met"
                direct_failure = any(task["record_id"] == key for task in trace["failed_tasks"])
                cause = ("attempts_exhausted" if direct_failure else "dependency_blocked") if completion is None else (
                    "deadline_exceeded" if completion > limit else "none")
                rows.append({**target, "completion_ms": completion, "lateness_ms": None if completion is None else max(0, completion - limit),
                    "outcome": outcome, "cause": cause,
                    "retry_count": len([event for event in trace["attempts"] if event["record_id"] == key and event["attempt"] > 1])})
            expected_score = {"record_id": base["record_id"], "snapshot": trace["snapshot"], "targets": rows,
                "all_met": all(row["outcome"] == "met" for row in rows),
                "met_count": sum(row["outcome"] == "met" for row in rows),
                "late_count": sum(row["outcome"] == "late" for row in rows),
                "unfinished_count": sum(row["outcome"] == "unfinished" for row in rows)}
            if score.structuredContent != expected_score:
                return False
        summaries.append({"label": policy["label"], "completed": trace["completed"], "elapsed_ms": trace["elapsed_ms"],
            "attempt_count": len(trace["attempts"]), "retry_count": sum(event["attempt"] > 1 for event in trace["attempts"]),
            "unfinished_count": len(trace["unfinished_records"]), "deadline_met": trace["completed"] and trace["elapsed_ms"] <= arguments["deadline_ms"],
            "worker_busy_ms": sum(event["end_ms"] - event["start_ms"] for event in trace["attempts"])})
    if comparison_error:
        return bool(comparison.isError)
    if comparison.isError:
        return False
    completed = sorted((row for row in summaries if row["completed"]), key=lambda row: (row["elapsed_ms"], row["attempt_count"], row["label"]))
    return comparison.structuredContent == {"record_id": base["record_id"], "deadline_ms": arguments["deadline_ms"],
        "strategies": summaries, "best_strategy": completed[0]["label"] if completed else None,
        "snapshot": [copy.deepcopy(oracle.records[key]) for key in sorted(selected)]}
