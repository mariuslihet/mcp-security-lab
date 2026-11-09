"""Client-boundary MCP latency and logical message volume from saved proxy audits."""
from __future__ import annotations

import json
import math
import statistics
from pathlib import Path


def capability(method):
    return {"tools": "Tools", "resources": "Resources", "prompts": "Prompts", "sampling": "Sampling",
            "elicitation": "Elicitation", "roots": "Client roots", "completion": "Completions",
            "logging": "Logging", "ping": "Connection health", "initialize": "Negotiation"}.get(method.split("/")[0], "Other")


def _new_group(key):
    mode, transport, direction, method, tool = key
    return {"mode": mode, "transport": transport, "direction": direction, "method": method, "tool": tool,
            "capability": capability(method), "requests": 0, "completed": 0, "pending": 0, "cancelled": 0,
            "tool_errors": 0, "rpc_errors": 0, "logical_bytes": 0, "_samples": []}


def _finish(groups, totals):
    operations = []
    capability_groups = {}
    for key, group in sorted(groups.items()):
        samples = sorted(group["_samples"])
        values = {name: value for name, value in group.items() if name != "_samples"}
        values.update(p50_ms=round(statistics.median(samples), 3) if samples else None,
                      p95_ms=round(samples[math.ceil(len(samples) * 0.95) - 1], 3) if samples else None,
                      max_ms=round(samples[-1], 3) if samples else None)
        operations.append(values)
        cap_key = (group["mode"], group["transport"], group["direction"], group["capability"], "")
        merged = capability_groups.setdefault(cap_key, _new_group(cap_key))
        merged["capability"] = group["capability"]
        for field in ("requests", "completed", "pending", "cancelled", "tool_errors", "rpc_errors", "logical_bytes"):
            merged[field] += group[field]
        merged["_samples"].extend(samples)
    caps = []
    for group in capability_groups.values():
        samples = sorted(group.pop("_samples"))
        group.update(p50_ms=round(statistics.median(samples), 3) if samples else None,
                     p95_ms=round(samples[math.ceil(len(samples) * 0.95) - 1], 3) if samples else None,
                     max_ms=round(samples[-1], 3) if samples else None)
        caps.append(group)
    for field in ("requests", "completed", "pending", "cancelled", "tool_errors", "rpc_errors"):
        totals[field] = sum(group[field] for group in groups.values())
    return {"schema_version": 1, "totals": totals, "operations": operations, "capabilities": caps}


def _consume(frames, groups, totals, mode, transport):
    pending, ambiguous = {}, set()
    for frame in frames:
        if frame.get("stage") not in ("client_send", "client_receive"):
            continue
        payload, timestamp = frame.get("payload"), frame.get("elapsed_ns")
        if not isinstance(payload, dict) or type(timestamp) is not int or timestamp < 0:
            totals["invalid_frames"] += 1
            continue
        size = len(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        totals["messages"] += 1
        totals["logical_bytes"] += size
        sent = frame["stage"] == "client_send"
        if "method" in payload and "id" not in payload:
            totals["notifications"] += 1
            if payload["method"] == "notifications/cancelled":
                params = payload.get("params", {})
                request_id = params.get("requestId") if isinstance(params, dict) else None
                if type(request_id) in (str, int):
                    key = ("client_to_server" if sent else "server_to_client", type(request_id), request_id)
                    item = pending.pop(key, None)
                    if item:
                        item[0]["cancelled"] += 1
                    ambiguous.discard(key)
            continue
        if type(payload.get("id")) not in (str, int):
            totals["invalid_frames"] += 1
            continue
        request = "method" in payload
        direction = "client_to_server" if (sent if request else not sent) else "server_to_client"
        key = (direction, type(payload["id"]), payload["id"])
        if request:
            method = str(payload["method"])
            params = payload.get("params", {})
            tool = str(params.get("name", "")) if method == "tools/call" and isinstance(params, dict) else ""
            group = groups.setdefault((mode, transport, direction, method, tool), _new_group((mode, transport, direction, method, tool)))
            group["requests"] += 1
            group["logical_bytes"] += size
            if key in pending:
                totals["duplicate_request_ids"] += 1
                pending[key][0]["pending"] += 1
                ambiguous.add(key)
            pending[key] = (group, timestamp)
        elif "result" in payload or "error" in payload:
            item = pending.pop(key, None)
            if item is None:
                totals["unmatched_responses"] += 1
                continue
            group, started = item
            group["logical_bytes"] += size
            if key in ambiguous or timestamp < started:
                group["pending"] += 1
                totals["invalid_frames"] += 1
                ambiguous.discard(key)
                continue
            group["completed"] += 1
            group["rpc_errors"] += int("error" in payload)
            group["tool_errors"] += int(isinstance(payload.get("result"), dict) and bool(payload["result"].get("isError")))
            group["_samples"].append((timestamp - started) / 1_000_000)
    for group, _ in pending.values():
        group["pending"] += 1


def _totals():
    return {"audits": 0, "messages": 0, "logical_bytes": 0, "notifications": 0, "unmatched_responses": 0,
            "invalid_frames": 0, "duplicate_request_ids": 0}


def summarize_frames(frames, *, mode="not_recorded", transport="not_recorded"):
    groups, totals = {}, _totals()
    _consume(frames, groups, totals, mode, transport)
    return _finish(groups, totals)


def collect_protocol_metrics(rows, directory: Path):
    groups, totals, audits = {}, _totals(), {}
    for row in rows:
        if not row.get("audit"):
            continue
        path = Path(row["audit"])
        path = path if path.is_absolute() else directory / path
        try:
            path = path.resolve()
            path.relative_to(directory.resolve())
        except (ValueError, OSError):
            continue
        scope = (str(row.get("mode", "not_recorded")), str(row.get("transport", "not_recorded")))
        if path in audits and audits[path] != scope:
            audits[path] = ("mixed", "mixed")
        else:
            audits[path] = scope
    for path, (mode, transport) in audits.items():
        if not path.is_file():
            continue
        def frames():
            with path.open(encoding="utf-8") as stream:
                for line in stream:
                    try:
                        value = json.loads(line)
                    except ValueError:
                        totals["invalid_frames"] += 1
                        continue
                    if isinstance(value, dict):
                        yield value
                    else:
                        totals["invalid_frames"] += 1
        _consume(frames(), groups, totals, mode, transport)
        totals["audits"] += 1
    return _finish(groups, totals)
