"""Worker-capacity accounting for independently audited recovery traces."""
import copy

from .resilience import RECORD, integer_arguments


TIME_FIELDS = ("capacity_ms", "available_ms", "busy_ms", "productive_ms", "failed_attempt_ms", "outage_ms", "idle_ms")
ACCOUNTING = {**{key: {"type": "integer", "minimum": 0} for key in TIME_FIELDS},
              "utilization_basis_points": {"type": ["integer", "null"], "minimum": 0, "maximum": 10000}}
UTILIZATION_OUTPUT = {"type": "object", "additionalProperties": False,
    "required": ["record_id", "elapsed_ms", "workers", "totals", "retry_wait", "snapshot"],
    "properties": {"record_id": {"type": "string"}, "elapsed_ms": {"type": "integer", "minimum": 0},
        "workers": {"type": "array", "minItems": 1, "maxItems": 16, "items": {"type": "object", "additionalProperties": False,
            "required": ["worker", *ACCOUNTING], "properties": {"worker": {"type": "integer", "minimum": 0, "maximum": 15}, **ACCOUNTING}}},
        "totals": {"type": "object", "additionalProperties": False, "required": list(ACCOUNTING), "properties": ACCOUNTING},
        "retry_wait": {"type": "object", "additionalProperties": False, "required": ["required_backoff_ms", "additional_wait_ms"],
            "properties": {key: {"type": "integer", "minimum": 0} for key in ("required_backoff_ms", "additional_wait_ms")}},
        "snapshot": {"type": "array", "items": RECORD}}}


def _outage_time(periods, horizon):
    clipped = sorted((max(0, row["start_ms"]), min(horizon, row["end_ms"])) for row in periods
                     if row["start_ms"] < horizon and row["end_ms"] > 0)
    end, duration = 0, 0
    for start, finish in clipped:
        duration += max(0, finish - max(start, end))
        end = max(end, finish)
    return duration


def utilization(scenario, trace):
    scenario, trace = integer_arguments(scenario), integer_arguments(trace)
    horizon, rows = trace["elapsed_ms"], []
    for worker in range(scenario["max_parallel"]):
        attempts = [row for row in trace["attempts"] if row["worker"] == worker]
        busy = sum(row["end_ms"] - row["start_ms"] for row in attempts)
        productive = sum(row["end_ms"] - row["start_ms"] for row in attempts if row["outcome"] == "succeeded")
        outage = _outage_time([row for row in scenario["worker_outages"] if row["worker"] == worker], horizon)
        available = horizon - outage
        rows.append({"worker": worker, "capacity_ms": horizon, "available_ms": available, "busy_ms": busy,
            "productive_ms": productive, "failed_attempt_ms": busy - productive, "outage_ms": outage,
            "idle_ms": available - busy, "utilization_basis_points": busy * 10000 // available if available else None})
    totals = {key: sum(row[key] for row in rows) for key in TIME_FIELDS}
    totals["utilization_basis_points"] = totals["busy_ms"] * 10000 // totals["available_ms"] if totals["available_ms"] else None
    groups = {}
    for event in trace["attempts"]:
        groups.setdefault((event["record_id"], event["status"]), []).append(event)
    required, extra = 0, 0
    for events in groups.values():
        ordered = sorted(events, key=lambda event: event["attempt"])
        for previous, following in zip(ordered, ordered[1:]):
            backoff = scenario["retry_backoff_ms"] * 2 ** (previous["attempt"] - 1)
            required += backoff
            extra += following["start_ms"] - previous["end_ms"] - backoff
    return {"record_id": trace["record_id"], "elapsed_ms": horizon, "workers": rows, "totals": totals,
            "retry_wait": {"required_backoff_ms": required, "additional_wait_ms": extra}, "snapshot": copy.deepcopy(trace["snapshot"])}
