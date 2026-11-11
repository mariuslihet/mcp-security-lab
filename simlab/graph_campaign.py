"""Replayable DAG campaigns with atomicity, legal-serialization, and notification oracles."""
from __future__ import annotations

import asyncio
import copy
import json
import random
from collections import Counter
from pathlib import Path

from jsonschema import Draft202012Validator
from mcp import types

from .client import connect
from .client_profiles import ControlledClient
from .controls import SCHEMAS
from .dependency_graph import generate_graph, validate_graph
from .fixtures import CATALOG_HANDLE, WRITE_HANDLE, create_fixture


GRAPH_TOOLS = ("batch_update_records", "update_record", "guided_update_record", "preview_updates", "get_record",
               "analyze_dependencies", "incident_bundle", "set_catalog_profile", "simulate_dependency_outage", "plan_recovery",
               "simulate_recovery_timeline", "rank_dependency_bottlenecks", "simulate_recovery_resilience")
APPROVALS = ("accept", "decline", "cancel", "false", "wrong_digest")
CALL_SCHEMA = {"oneOf": [{"type": "object", "additionalProperties": False,
    "required": ["kind", "tool", "arguments", "approval", "label"], "properties": {
        "kind": {"const": "call"}, "tool": {"const": tool}, "arguments": SCHEMAS[tool],
        "approval": {"enum": list(APPROVALS)}, "label": {"type": "string", "maxLength": 80}}} for tool in GRAPH_TOOLS]}
RACE_SCHEMA = {"type": "object", "required": ["kind", "requests", "label"], "additionalProperties": False, "properties": {
    "kind": {"const": "race"}, "label": {"type": "string", "maxLength": 80},
    "requests": {"type": "array", "minItems": 2, "maxItems": 32, "items": SCHEMAS["batch_update_records"]}}}
ROOT_CHANGE_SCHEMA = {"type": "object", "required": ["kind", "mode", "label"], "additionalProperties": False,
    "properties": {"kind": {"const": "roots_change"}, "mode": {"enum": ["workspace", "outside", "empty"]},
                   "label": {"type": "string", "maxLength": 80}}}
ROOT_DRIFT_SCHEMA = {"type": "object", "required": ["kind", "arguments", "notify", "label"], "additionalProperties": False,
    "properties": {"kind": {"const": "guided_drift"}, "arguments": SCHEMAS["guided_update_record"],
                   "notify": {"type": "boolean"}, "label": {"type": "string", "maxLength": 80}}}
RESILIENCE_SCHEMA = {"type": "object", "required": ["kind", "arguments", "corruption", "label"], "additionalProperties": False,
    "properties": {"kind": {"const": "resilience"}, "arguments": SCHEMAS["simulate_recovery_resilience"],
        "corruption": {"enum": ["none", "version", "missing", "summary"]}, "label": {"type": "string", "maxLength": 80}}}
STRATEGY_ACTION_SCHEMA = {"type": "object", "required": ["kind", "arguments", "deadlines", "tamper", "label"], "additionalProperties": False,
    "properties": {"kind": {"const": "strategy"}, "arguments": SCHEMAS["compare_recovery_strategies"],
        "deadlines": SCHEMAS["evaluate_recovery_deadlines"]["properties"]["deadlines"], "tamper": {"type": "boolean"},
        "label": {"type": "string", "maxLength": 80}}}
GRAPH_MANIFEST_SCHEMA = {"type": "object", "required": ["schema_version", "seed", "graph", "actions"], "additionalProperties": False,
    "properties": {"schema_version": {"const": 2}, "seed": {"type": "integer"}, "graph": {"type": "object"},
        "actions": {"type": "array", "minItems": 1, "maxItems": 200,
                    "items": {"oneOf": [CALL_SCHEMA, RACE_SCHEMA, ROOT_CHANGE_SCHEMA, ROOT_DRIFT_SCHEMA, RESILIENCE_SCHEMA, STRATEGY_ACTION_SCHEMA]}}}}


def validate_graph_manifest(manifest):
    if not Draft202012Validator(GRAPH_MANIFEST_SCHEMA).is_valid(manifest):
        raise ValueError("invalid dependency campaign manifest")
    validate_graph(manifest["graph"])
    allowed = set(manifest["graph"]) | {"PAY-001"}
    for action in manifest["actions"]:
        if action["kind"] == "roots_change":
            continue
        if action["kind"] == "strategy" and any(row["record_id"] not in allowed for row in action["deadlines"]):
            raise ValueError("dependency campaign references an unsupported deadline record")
        requests = action["requests"] if action["kind"] == "race" else [action["arguments"]["scenario"] if action["kind"] == "strategy" else action["arguments"]]
        for arguments in requests:
            if any(row["record_id"] not in allowed for row in arguments.get("faults", [])):
                raise ValueError("dependency campaign references an unsupported fault record")
            if any(row["record_id"] not in allowed for row in arguments.get("durations", [])):
                raise ValueError("dependency campaign references an unsupported duration record")
            if any(key not in allowed for key in arguments.get("failed_records", [])):
                raise ValueError("dependency campaign references an unsupported outage record")
            updates = arguments.get("updates", [arguments])
            if any(item.get("record_id") not in allowed for item in updates if "record_id" in item):
                raise ValueError("dependency campaign references an unsupported record")
        if action["kind"] == "race":
            if any(len({item["record_id"] for item in request["updates"]}) != len(request["updates"]) for request in action["requests"]):
                raise ValueError("graph race requests cannot repeat a record within a batch")
            if len({request["idempotency_key"] for request in action["requests"]}) != len(action["requests"]):
                raise ValueError("graph race request keys must be distinct")
    return manifest


def generate_graph_manifest(seed, steps=60, *, nodes=32, width=4, parallel_calls=8, race_topology="shared", root_churn=False, outage_stress=False, timeline_stress=False, resilience_stress=False, strategy_stress=False):
    if type(steps) is not int or not 1 <= steps <= 200 or type(parallel_calls) is not int or not 2 <= parallel_calls <= 32:
        raise ValueError("graph campaigns require 1 to 200 actions and 2 to 32 parallel requests")
    if race_topology not in ("shared", "mixed") or any(type(flag) is not bool for flag in (root_churn, outage_stress, timeline_stress, resilience_stress, strategy_stress)):
        raise ValueError("invalid graph campaign stress profile")
    graph = generate_graph(seed, nodes, width)
    layers, rng, actions = validate_graph(graph), random.Random(seed), []
    tip = sorted(graph)[-1]

    def update(key, status="resolved", version=2):
        return {"record_id": key, "expected_version": version, "status": status}
    def call(tool, arguments, label, approval="accept"):
        actions.append({"kind": "call", "tool": tool, "arguments": arguments, "approval": approval, "label": label})
    def batch(updates, key):
        return {"updates": updates, "handle": WRITE_HANDLE, "idempotency_key": key}
    def guided(key, receipt, approval="accept"):
        call("guided_update_record", {**update(key), "handle": WRITE_HANDLE, "idempotency_key": receipt}, receipt, approval)
    def resilience_probe(label, corruption="none", attempts=3):
        actions.append({"kind": "resilience", "label": label, "corruption": corruption, "arguments": {
            "record_id": tip, "max_parallel": 3, "durations": [{"record_id": layers[0][0], "investigate_ms": 10, "resolve_ms": 3}],
            "max_attempts": attempts, "retry_backoff_ms": 2,
            "faults": [{"record_id": layers[0][0], "status": "investigating", "failed_attempts": 2}],
            "worker_outages": [{"worker": 0, "start_ms": 1, "end_ms": 6}, {"worker": 1, "start_ms": 0, "end_ms": 3}]}})
    def strategy_probe(label, tamper=False):
        actions.append({"kind": "strategy", "label": label, "tamper": tamper,
            "deadlines": [{"record_id": layers[0][0], "deadline_ms": 20}, {"record_id": tip, "deadline_ms": 1}],
            "arguments": {"deadline_ms": 20000, "scenario": {"record_id": tip, "max_parallel": 3,
                "max_attempts": 3, "retry_backoff_ms": 1, "durations": [],
                "faults": [{"record_id": layers[0][0], "status": "investigating", "failed_attempts": 1}],
                "worker_outages": [{"worker": 0, "start_ms": 0, "end_ms": 2}]},
                "strategies": [{"label": "fragile", "max_parallel": 1, "max_attempts": 1, "retry_backoff_ms": 0},
                    {"label": "resilient", "max_parallel": 3, "max_attempts": 3, "retry_backoff_ms": 1}]}})

    call("analyze_dependencies", {"record_id": tip}, "initial_analysis")
    call("incident_bundle", {"record_id": tip}, "linked_resources")
    if strategy_stress:
        strategy_probe("recovery_policy_tradeoff")
        strategy_probe("tampered_deadline_evidence", tamper=True)
    if resilience_stress:
        resilience_probe("retry_and_outage_recovery")
        resilience_probe("exhausted_recovery_budget", attempts=1)
        resilience_probe("tampered_recovery_version", "version")
        resilience_probe("missing_recovery_attempt", "missing")
    def timed_preview(budget, label):
        call("simulate_recovery_timeline", {"record_id": tip, "max_parallel": budget, "durations": [
            {"record_id": key, "investigate_ms": rng.randint(1, 50), "resolve_ms": rng.randint(1, 100)}
            for key in (layers[0][0], layers[0][1], tip)]}, label)
    if timeline_stress:
        call("rank_dependency_bottlenecks", {"record_id": tip, "limit": 20}, "initial_bottleneck_ranking")
        for budget in (1, 16):
            timed_preview(budget, "weighted_recovery_timeline")
    if outage_stress:
        call("simulate_dependency_outage", {"failed_records": layers[0][:2]}, "root_outage")
        call("plan_recovery", {"record_id": tip, "max_parallel": 3}, "initial_recovery_plan")
    call("set_catalog_profile", {"profile": "compact", "handle": CATALOG_HANDLE}, "compact_catalog")
    call("update_record", {**update("GR-000", "investigating", 1), "handle": WRITE_HANDLE, "idempotency_key": "hidden"}, "disabled_tool")
    call("set_catalog_profile", {"profile": "standard", "handle": CATALOG_HANDLE}, "restore_catalog")
    ordered = sorted(graph)
    first_batch = None
    for index in range(0, len(ordered), 16):
        members = list(reversed(ordered[index:index + 16]))
        arguments = batch([update(key, "investigating", 1) for key in members], f"graph-start-{index}")
        call("batch_update_records", arguments, "start_wave")
        if index == 0:
            first_batch = copy.deepcopy(arguments)
            call("batch_update_records", copy.deepcopy(arguments), "lost_ack_retry")
    call("preview_updates", {"updates": [update(tip)], "handle": WRITE_HANDLE}, "blocked_tip_preview")
    guided(tip, "blocked_tip")
    guided(tip, "blocked_tip")
    guided("GR-002", "declined_review", "decline")
    if root_churn:
        actions.append({"kind": "roots_change", "mode": "outside", "label": "workspace_withdrawn"})
        guided("GR-000", "root_boundary_denied")
        actions.append({"kind": "roots_change", "mode": "workspace", "label": "workspace_restored"})
        for notify in (True, False):
            actions.append({"kind": "guided_drift", "arguments": {**update("GR-000"), "handle": WRITE_HANDLE,
                "idempotency_key": "notified-drift" if notify else "silent-drift"}, "notify": notify,
                "label": "notified_approval_root_drift" if notify else "silent_approval_root_drift"})
            actions.append({"kind": "roots_change", "mode": "workspace", "label": "workspace_recovered"})
    active_roots = ["GR-000", "GR-001"] if race_topology == "shared" else layers[0][:min(max(2, width - 1), parallel_calls)]
    guided_target = next((key for key in layers[0] if key not in active_roots), "GR-002")
    shared = [update(key) for key in active_roots]
    requests = []
    for index in range(parallel_calls):
        selected = shared
        handle = WRITE_HANDLE
        if race_topology == "mixed":
            if index < len(active_roots):
                selected = [update(active_roots[index])]
            elif index % 4 == 1:
                selected = [update(key) for key in rng.sample(active_roots, min(2, len(active_roots)))]
            elif index % 4 == 2:
                selected = [update(key) for key in rng.sample(active_roots, rng.randint(1, len(active_roots)))]
            elif index % 4 == 3:
                selected, handle = [update(active_roots[index % len(active_roots)])], "synthetic-read-handle"
        requests.append({**batch(copy.deepcopy(selected), f"graph-race-{index}"), "handle": handle})
    race = {"kind": "race", "label": "overlapping_root_resolutions",
            "requests": requests}
    actions.extend([race, {**copy.deepcopy(race), "label": "replayed_race"}])
    conflict = copy.deepcopy(first_batch)
    conflict["updates"][0]["status"] = "resolved"
    call("batch_update_records", conflict, "receipt_payload_conflict")
    guided(guided_target, "approved_root")
    guided(guided_target, "approved_root")
    if strategy_stress:
        strategy_probe("mid_campaign_deadlines")
    if resilience_stress:
        resilience_probe("mid_campaign_worker_outage")
    if timeline_stress:
        timed_preview(3, "contended_recovery_timeline")
        call("rank_dependency_bottlenecks", {"record_id": tip, "limit": 5}, "mid_campaign_bottlenecks")
    if outage_stress:
        call("simulate_dependency_outage", {"failed_records": layers[len(layers) // 2][:2]}, "mid_graph_outage")
        for budget in (1, 16):
            call("plan_recovery", {"record_id": tip, "max_parallel": budget}, "constrained_recovery_plan")
    for layer in layers:
        members = [key for key in layer if key not in set(active_roots) | {guided_target}]
        for offset in range(0, len(members), 16):
            selected = list(reversed(members[offset:offset + 16]))
            call("batch_update_records", batch([update(key) for key in selected], f"resolve-{len(actions)}"), "dependency_wave")
    call("analyze_dependencies", {"record_id": tip}, "completed_analysis")
    call("incident_bundle", {"record_id": tip}, "completed_resources")
    if strategy_stress:
        strategy_probe("completed_policy_comparison")
    if resilience_stress:
        resilience_probe("completed_recovery_audit")
        resilience_probe("tampered_recovery_summary", "summary")
    if timeline_stress:
        timed_preview(16, "completed_recovery_timeline")
        call("rank_dependency_bottlenecks", {"record_id": "PAY-001", "limit": 1}, "protected_bottleneck_probe")
    if outage_stress:
        call("plan_recovery", {"record_id": tip, "max_parallel": 16}, "completed_recovery_plan")
        call("simulate_dependency_outage", {"failed_records": ["PAY-001"]}, "protected_outage_probe")
    minimum = len(actions)
    if steps < minimum:
        raise ValueError(f"this graph needs at least {minimum} campaign actions")
    while len(actions) < steps:
        index, key = len(actions), rng.choice(ordered)
        if strategy_stress and index % 13 == 0:
            strategy_probe("post_stress_policy", tamper=index % 2 == 0)
        elif resilience_stress and index % 11 == 0:
            resilience_probe("post_stress_resilience", rng.choice(["none", "version", "missing", "summary"]))
        elif timeline_stress and index % 9 == 0:
            call("simulate_recovery_timeline", {"record_id": key, "max_parallel": rng.randint(1, 16), "durations": []}, "post_stress_timeline")
        elif timeline_stress and index % 9 == 1:
            call("rank_dependency_bottlenecks", {"record_id": key, "limit": rng.randint(1, 20)}, "post_stress_bottlenecks")
        elif outage_stress and index % 7 == 0:
            call("simulate_dependency_outage", {"failed_records": rng.sample(ordered, rng.randint(1, min(16, nodes)))}, "multi_fault_outage")
        elif outage_stress and index % 7 == 1:
            call("plan_recovery", {"record_id": key, "max_parallel": rng.randint(1, 16)}, "post_stress_recovery")
        elif index % 5 == 0:
            call("analyze_dependencies", {"record_id": key}, "post_stress_analysis")
        elif index % 5 == 1:
            call("incident_bundle", {"record_id": key}, "post_stress_links")
        elif index % 5 == 2:
            call("get_record", {"record_id": key}, "post_stress_read")
        elif index % 5 == 3:
            call("preview_updates", {"updates": [update(key, "open", 99)], "handle": WRITE_HANDLE}, "stale_reopen_preview")
        else:
            call("guided_update_record", {**update(key, "open", 3), "handle": WRITE_HANDLE,
                "idempotency_key": f"post-stress-{index}"}, "reopen_attempt", rng.choice(APPROVALS))
    return validate_graph_manifest({"schema_version": 2, "seed": seed, "graph": graph, "actions": actions})


class GraphOracle:
    """Reference model independent of IncidentStore; state is published only after all constraints pass."""
    def __init__(self, config, hardened):
        state = json.loads(Path(config["state_path"]).read_text(encoding="utf-8"))
        self.records, self.receipts = state["records"], state["receipts"]
        self.allowed, self.graph = set(config["allowed_records"]), config["dependencies"]
        self.session, self.hardened = config["session"], hardened
        self.faults, self.profile = dict(config["faults"]), "standard"
        self.root_mode = "workspace"

    def roots_changed(self, mode):
        self.root_mode = mode
        return {"error": self.profile == "compact", "changed": [], "value": {"workspace_advertised": mode == "workspace"}}

    def graph_preview(self, tool, args):
        """Independent task-DAG/shortest-path reference, separate from server planning."""
        unchanged = {"error": True, "changed": []}
        if tool == "simulate_dependency_outage":
            failed = sorted(args["failed_records"])
            if self.hardened and not set(failed) <= self.allowed:
                return unchanged
            visible = self.allowed if self.hardened else set(self.records)
            paths = {key: [key] for key in failed}
            for _ in range(len(visible)):
                previous = copy.deepcopy(paths)
                for key in sorted(visible):
                    candidates = [previous[parent] + [key] for parent in self.graph.get(key, []) if parent in previous]
                    if key in previous:
                        candidates.append(previous[key])
                    if candidates:
                        paths[key] = min(candidates, key=lambda path: (len(path), path))
                if paths == previous:
                    break
            selected = sorted(paths)
            value = {"failed_records": failed, "impacted_records": selected,
                "waves": [[key for key in selected if len(paths[key]) == depth] for depth in range(1, max(map(len, paths.values())) + 1)],
                "paths": {key: paths[key] for key in selected}, "unaffected_count": len(visible - set(paths)),
                "snapshot": [copy.deepcopy(self.records[key]) for key in selected]}
        else:
            key = args["record_id"]
            selected = sorted(self.closure(key))
            if self.hardened and not set(selected) <= self.allowed:
                return unchanged
            tasks, prerequisites = {}, {}
            for record_id in selected:
                record = self.records[record_id]
                for status in (["investigating", "resolved"] if record["status"] == "open" else ["resolved"] if record["status"] == "investigating" else []):
                    token = (record_id, status)
                    tasks[token] = {"record_id": record_id, "status": status,
                        "expected_version": record["version"] + int(status == "resolved" and record["status"] == "open")}
            for token in tasks:
                record_id, status = token
                prerequisites[token] = ({(parent, "resolved") for parent in self.graph.get(record_id, [])}
                    | {(record_id, "investigating")}) & tasks.keys() if status == "resolved" else set()
            pending, waves = set(tasks), []
            while pending:
                ready = sorted((token for token in pending if not prerequisites[token] & pending),
                               key=lambda token: (token[1] != "resolved", token[0]))[:args["max_parallel"]]
                waves.append([tasks[token] for token in ready])
                pending.difference_update(ready)
            value = {"record_id": key, "max_parallel": args["max_parallel"], "waves": waves,
                "total_updates": len(tasks), "snapshot": [copy.deepcopy(self.records[key]) for key in selected]}
        return {"error": False, "value": value, "changed": []}

    def closure(self, key):
        selected, todo = set(), [key]
        while todo:
            current = todo.pop()
            if current not in selected:
                selected.add(current)
                todo += self.graph.get(current, [])
        return selected

    def call(self, tool, args, approval="accept", *, roots_drift=False):
        unchanged = {"error": True, "changed": []}
        if tool == "simulate_recovery_resilience":
            selected = self.closure(args["record_id"])
            if (self.hardened and not selected <= self.allowed or
                    len({row["record_id"] for row in args["durations"]}) != len(args["durations"]) or
                    any(row["record_id"] not in selected for row in args["durations"] + args["faults"]) or
                    len({(row["record_id"], row["status"]) for row in args["faults"]}) != len(args["faults"]) or
                    any(row["worker"] >= args["max_parallel"] or row["start_ms"] >= row["end_ms"] for row in args["worker_outages"])):
                return unchanged
            return {"error": False, "changed": [], "resilience": {"arguments": copy.deepcopy(args),
                "records": {key: copy.deepcopy(self.records[key]) for key in selected}}}
        if tool in ("simulate_recovery_timeline", "rank_dependency_bottlenecks"):
            selected = self.closure(args["record_id"])
            if self.hardened and not selected <= self.allowed:
                return unchanged
            from .timeline_oracle import preview
            value = preview(tool, args, self.graph, self.records, selected)
            return unchanged if value is None else {"error": False, "changed": [], "value": value}
        if tool in ("simulate_dependency_outage", "plan_recovery"):
            return self.graph_preview(tool, args)
        if self.profile == "compact" and tool in {"update_record", "batch_update_records", "guided_update_record", "preview_updates"}:
            return unchanged
        if tool == "set_catalog_profile":
            if self.hardened and args["handle"] != CATALOG_HANDLE:
                return unchanged
            changed = self.profile != args["profile"]
            self.profile = args["profile"]
            return {"error": False, "value": {"profile": self.profile, "changed": changed}, "changed": [], "catalog_changed": changed}
        updates = args.get("updates", [args])
        targets = [item["record_id"] for item in updates]
        if self.hardened and any(key not in self.allowed for key in targets):
            return unchanged
        if self.faults.get(tool, 0):
            self.faults[tool] -= 1
            return unchanged
        if tool in ("analyze_dependencies", "incident_bundle", "get_record"):
            key = args["record_id"]
            if tool == "get_record":
                value = {"record": copy.deepcopy(self.records[key])}
            else:
                selected = self.closure(key)
                if tool == "incident_bundle":
                    return {"error": False, "record": copy.deepcopy(self.records[key]),
                            "resource_set": {"lab://incidents/" + item for item in selected}, "changed": []}
                todo, layers = set(selected), []
                while todo:
                    ready = sorted(item for item in todo if not (set(self.graph.get(item, [])) & todo))
                    layers.append(ready)
                    todo.difference_update(ready)
                value = {"record_id": key, "node_count": len(selected),
                         "edge_count": sum(len(self.graph.get(item, [])) for item in selected), "layers": layers,
                         "unresolved": sorted(item for item in selected if self.records[item]["status"] != "resolved")}
                return {"error": False, "value": value, "critical_length": len(layers), "changed": []}
            return {"error": False, "value": value, "changed": []}
        if self.hardened and args["handle"] != WRITE_HANDLE:
            return unchanged
        key = self.session + ":" + args.get("idempotency_key", "")
        fingerprint = json.dumps({"operation": tool, "arguments": args}, sort_keys=True)
        if tool != "preview_updates" and self.hardened and key in self.receipts:
            receipt = self.receipts[key]
            return (unchanged if receipt["fingerprint"] != fingerprint else
                    {"error": False, "value": {**copy.deepcopy(receipt["result"]), "deduplicated": True}, "changed": []})
        candidate, results = copy.deepcopy(self.records), []
        if self.hardened and len(set(targets)) != len(targets):
            return unchanged
        for update in updates:
            record = candidate[update["record_id"]]
            if self.hardened and (record["version"] != update["expected_version"] or
                    (record["status"], update["status"]) not in {("open", "investigating"), ("investigating", "resolved")}):
                return unchanged
            record.update(status=update["status"], version=record["version"] + 1)
            results.append(copy.deepcopy(record))
        if self.hardened and any(candidate[target]["status"] == "resolved" and
                any(candidate[parent]["status"] != "resolved" for parent in self.graph.get(target, [])) for target in targets):
            return unchanged
        if tool == "preview_updates":
            return {"error": False, "value": {"records": results, "would_commit": True}, "changed": []}
        if tool == "guided_update_record":
            if self.hardened and self.root_mode != "workspace":
                return unchanged
            if roots_drift:
                self.root_mode = "outside"
                if self.hardened:
                    return unchanged
        if tool == "guided_update_record" and approval != "accept":
            if approval == "wrong_digest":
                return unchanged
            return {"error": False, "value": {"committed": False, "action": "decline" if approval == "false" else approval}, "changed": []}
        result = {"records" if tool == "batch_update_records" else "record": results if tool == "batch_update_records" else results[0],
                  "deduplicated": False}
        self.records = candidate
        self.receipts[key] = {"fingerprint": fingerprint, "result": copy.deepcopy(result)}
        fault = tool + "_after_commit"
        if self.faults.get(fault, 0):
            self.faults[fault] -= 1
            return {"error": True, "changed": targets, "committed_before_error": True}
        return {"error": False, "value": result, "changed": targets}


def matches(expected, result, graph):
    if bool(result.isError) != expected["error"]:
        return False
    if expected["error"]:
        return True
    value = result.structuredContent or {}
    if "resilience" in expected:
        from .resilience import audit
        spec = expected["resilience"]
        return audit(spec["arguments"], graph, spec["records"], value)["valid"]
    if "resource_set" in expected:
        links = [str(block.uri) for block in result.content if isinstance(block, types.ResourceLink)]
        return (value.get("record") == expected["record"] and set(value.get("resources", [])) == expected["resource_set"]
                and set(links) == expected["resource_set"] and len(links) == len(expected["resource_set"]))
    valid = all(value.get(key) == item for key, item in expected.get("value", {}).items())
    if "critical_length" in expected:
        path = value.get("critical_path", [])
        valid &= (len(path) == expected["critical_length"] and len(set(path)) == len(path)
                  and bool(path) and path[-1] == value.get("record_id")
                  and all(parent in graph.get(child, []) for parent, child in zip(path, path[1:])))
    return valid


def corrupt_recovery_trace(trace, corruption):
    changed = copy.deepcopy(trace)
    if corruption == "version" and changed.get("attempts"):
        changed["attempts"][0]["expected_version"] += 1
    elif corruption == "missing" and changed.get("attempts"):
        changed["attempts"].pop()
    elif corruption != "none":
        changed["completed"] = not changed.get("completed", False)
    return changed


def check_resilience_pair(oracle, action, simulated, checked):
    from .resilience import audit
    expected = oracle.call("simulate_recovery_resilience", action["arguments"])
    if not matches(expected, simulated, oracle.graph):
        return False
    if expected["error"]:
        return bool(checked.isError)
    trace = corrupt_recovery_trace(simulated.structuredContent, action["corruption"])
    verified = audit(action["arguments"], oracle.graph, oracle.records, trace)
    return (not checked.isError and checked.structuredContent == verified
            and verified["valid"] == (action["corruption"] == "none"))


def check_strategy_action(oracle, action, responses):
    from .decision_oracle import verify
    return verify(oracle, action, responses, matches)


def verify_race(oracle, requests, results, published_receipts):
    """Find a legal order from per-record version witnesses and dependency constraints.

    Rejections/replays are consumed at the earliest point where the reference
    model agrees without changing state. They can therefore precede a commit
    that later removes an unresolved dependency.
    """
    witnesses, edges, valid = {}, {}, True
    for index, (request, result) in enumerate(zip(requests, results)):
        key = oracle.session + ":" + request["idempotency_key"]
        receipt = published_receipts.get(key)
        fingerprint = json.dumps({"operation": "batch_update_records", "arguments": request}, sort_keys=True)
        value = result.structuredContent or {}
        if value.get("deduplicated") is True:
            continue
        if not result.isError:
            witnesses[index] = value.get("records", [])
        elif receipt and receipt.get("fingerprint") == fingerprint and receipt != oracle.receipts.get(key):
            witnesses[index] = receipt.get("result", {}).get("records", [])
        if index in witnesses:
            edges[index] = set()
    by_record = {}
    for index, records in witnesses.items():
        for record in records:
            by_record.setdefault(record["id"], []).append((record["version"], index))
    for versions in by_record.values():
        ordered = sorted(versions)
        for (version, before), (next_version, after) in zip(ordered, ordered[1:]):
            if version == next_version:
                valid = False
            edges[after].add(before)
    if oracle.hardened:
        for index, records in witnesses.items():
            own = {record["id"]: record for record in records}
            for record in records:
                if record["status"] != "resolved":
                    continue
                for parent in oracle.graph.get(record["id"], []):
                    if (parent in own and own[parent]["status"] == "resolved") or oracle.records[parent]["status"] == "resolved":
                        continue
                    for other, targets in witnesses.items():
                        if other != index and any(target["id"] == parent and target["status"] == "resolved" for target in targets):
                            edges[index].add(other)
    remaining, commits = set(witnesses), []
    while remaining:
        ready = sorted(index for index in remaining if not (edges[index] & remaining))
        if not ready:
            valid = False
            commits.extend(sorted(remaining))
            break
        commits.extend(ready)
        remaining.difference_update(ready)
    nonmutating = set(range(len(requests))) - set(witnesses)
    order, changed = [], []
    def consume_rejections():
        for index in sorted(list(nonmutating)):
            trial = copy.deepcopy(oracle)
            expected = trial.call("batch_update_records", requests[index])
            if not expected["changed"] and matches(expected, results[index], trial.graph):
                oracle.faults = trial.faults
                nonmutating.remove(index)
                order.append(index)
    for index in commits:
        consume_rejections()
        expected = oracle.call("batch_update_records", requests[index])
        valid &= matches(expected, results[index], oracle.graph)
        changed.extend(expected["changed"])
        order.append(index)
    consume_rejections()
    for index in sorted(nonmutating):
        expected = oracle.call("batch_update_records", requests[index])
        valid &= matches(expected, results[index], oracle.graph)
        changed.extend(expected["changed"])
        order.append(index)
    return bool(valid), order, changed


async def graph_campaign_matrix(directory: Path, mode: str, transport: str, manifest: dict, *,
                                stop_after: int | None = None, resume_checkpoint: Path | None = None):
    from .checkpoint import canonical, load_checkpoint, rebuild_oracle, restore_history, save_checkpoint
    validate_graph_manifest(manifest)
    resumed = None
    if resume_checkpoint is not None:
        saved_manifest, resumed = load_checkpoint(resume_checkpoint)
        if canonical(saved_manifest) != canonical(manifest) or resumed["mode"] != mode or resumed["transport"] != transport:
            raise ValueError("resume must preserve the manifest, mode, and transport")
        if directory.exists():
            raise ValueError("resume destination must be a new directory")
    first = resumed["next_action"] if resumed else 0
    limit = len(manifest["actions"]) if stop_after is None else stop_after
    if type(limit) is not int or not first <= limit <= len(manifest["actions"]):
        raise ValueError("stop_after must be between saved progress and campaign length")
    config_path, config = create_fixture(directory, dense=True, fault_profile="transient", dependency_graph=manifest["graph"])
    if resumed:
        original_session = config["session"]
        config["session"] = resumed["session"]
        for handle in config["handles"].values():
            if handle["session"] == original_session:
                handle["session"] = config["session"]
    saved = directory / "campaign.json"
    saved.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    hardened, rows, notifications = mode == "hardened", [], []
    notification_arrived = asyncio.Event()
    client = ControlledClient(config, directory / "client.jsonl")
    oracle = GraphOracle(config, hardened)
    if resumed:
        rebuild_oracle(oracle, manifest, resumed)
        rows = restore_history(resume_checkpoint.parent, directory, resumed)
        Path(config["state_path"]).write_text(json.dumps(resumed["state"], indent=2), encoding="utf-8")
        config["faults"] = dict(oracle.faults)
        config["initial_catalog_profile"] = oracle.profile
        config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
        client.root_mode = oracle.root_mode
    save_checkpoint(directory, manifest, mode, transport, config, oracle, rows)
    if first == limit:
        return rows
    subscribed = {"lab://incidents/" + key for key in (sorted(manifest["graph"])[0], sorted(manifest["graph"])[-1])}
    async def receive(message):
        if isinstance(message, types.ServerNotification):
            notifications.append(message.model_dump(mode="json", by_alias=True))
            notification_arrived.set()
    async with connect(config_path, mode, directory / "wire.jsonl", transport,
                       message_handler=receive, **client.callbacks()) as session:
        for uri in sorted(subscribed):
            await session.subscribe_resource(uri)
        async def call(tool, arguments):
            return await session.call_tool(("sim_" if hardened else "") + tool, arguments)
        for index in range(first, limit):
            action = manifest["actions"][index]
            start, trace_start = len(notifications), len(client.events)
            expected_notifications, expected_catalog, response_ok = [], 0, True
            root_checks = {}
            if action["kind"] == "strategy":
                from .recovery_decisions import strategy_scenario
                comparison = await call("compare_recovery_strategies", action["arguments"])
                variants = [strategy_scenario(action["arguments"]["scenario"], row) for row in action["arguments"]["strategies"]]
                witnesses = await asyncio.gather(*(call("simulate_recovery_resilience", variant) for variant in variants))
                scores = await asyncio.gather(*(call("evaluate_recovery_deadlines", {"scenario": variant,
                    "deadlines": action["deadlines"], "trace": corrupt_recovery_trace(witness.structuredContent or {}, "version" if action["tamper"] else "none")})
                    for variant, witness in zip(variants, witnesses)))
                returned = [comparison, *witnesses, *scores]
                response_ok = check_strategy_action(oracle, action, returned)
                responses = [item.model_dump(mode="json") for item in returned]
                expected_summary = {"strategy_verified": response_ok, "tampered_deadlines": action["tamper"]}
            elif action["kind"] == "resilience":
                simulated = await call("simulate_recovery_resilience", action["arguments"])
                trace = corrupt_recovery_trace(simulated.structuredContent or {}, action["corruption"])
                checked = await call("validate_recovery_trace", {"scenario": action["arguments"], "trace": trace})
                response_ok = check_resilience_pair(oracle, action, simulated, checked)
                responses = [simulated.model_dump(mode="json"), checked.model_dump(mode="json")]
                expected_summary = {"trace_verified": response_ok, "audit_expected_valid": action["corruption"] == "none"}
            elif action["kind"] == "roots_change":
                before_status = await call("get_client_root_status", {})
                client.root_mode = action["mode"]
                await session.send_roots_list_changed()
                await session.send_ping()
                after_status = await call("get_client_root_status", {})
                expected = oracle.roots_changed(action["mode"])
                result = await call("inspect_client_roots", {})
                root_valid = (not before_status.isError and not after_status.isError
                    and after_status.structuredContent["generation"] == before_status.structuredContent["generation"] + 1
                    and after_status.structuredContent["dirty"] is True)
                response_ok = root_valid and matches(expected, result, oracle.graph)
                root_checks = {"root_status_before": before_status.model_dump(mode="json"),
                               "root_status_after_notification": after_status.model_dump(mode="json"), "root_change_verified": root_valid}
                responses, expected_summary = [result.model_dump(mode="json")], expected
            elif action["kind"] in ("call", "guided_drift"):
                drift = action["kind"] == "guided_drift"
                tool = "guided_update_record" if drift else action["tool"]
                approval = "accept" if drift else action["approval"]
                client.approval = approval
                if drift:
                    async def change_roots(context, params):
                        client.root_mode = "outside"
                        if action["notify"]:
                            await context.session.send_roots_list_changed()
                    client.before_approval = change_roots
                expected = oracle.call(tool, action["arguments"], approval, roots_drift=drift)
                try:
                    result = await call(tool, action["arguments"])
                finally:
                    client.before_approval = None
                response_ok = matches(expected, result, oracle.graph)
                expected_notifications += ["lab://incidents/" + key for key in expected["changed"]]
                expected_catalog = int(expected.get("catalog_changed", False))
                responses = [result.model_dump(mode="json")]
                expected_summary = {key: value for key, value in expected.items() if key not in ("resource_set",)}
            else:
                results = await asyncio.gather(*(call("batch_update_records", request) for request in action["requests"]))
                receipts = json.loads(Path(config["state_path"]).read_text(encoding="utf-8"))["receipts"]
                response_ok, order, changed = verify_race(oracle, action["requests"], results, receipts)
                expected_notifications += ["lab://incidents/" + key for key in changed]
                responses = [result.model_dump(mode="json") for result in results]
                expected_summary = {"legal_serialization": order, "accepted": sum(not result.isError for result in results),
                                    "serialization_verified": response_ok}
            expected_uris = Counter(uri for uri in expected_notifications if uri in subscribed)
            # HTTP delivers unsolicited notifications on a separate stream. A
            # tool response is not a delivery barrier for that stream.
            def notifications_complete():
                delivered = notifications[start:]
                updates = Counter(item["params"]["uri"] for item in delivered
                                  if item.get("method") == "notifications/resources/updated")
                return (all(updates[uri] >= count for uri, count in expected_uris.items())
                        and all(sum(item.get("method") == method for item in delivered) >= expected_catalog
                                for method in ("notifications/tools/list_changed", "notifications/resources/list_changed", "notifications/prompts/list_changed")))
            try:
                async with asyncio.timeout(3):
                    while not notifications_complete():
                        notification_arrived.clear()
                        await notification_arrived.wait()
            except TimeoutError:
                pass  # Missing deliveries remain assertion failures below.
            actual_state = json.loads(Path(config["state_path"]).read_text(encoding="utf-8"))
            delivered = notifications[start:]
            actual_uris = Counter(item["params"]["uri"] for item in delivered if item.get("method") == "notifications/resources/updated")
            catalog_methods = ("notifications/tools/list_changed", "notifications/resources/list_changed", "notifications/prompts/list_changed")
            catalog_ok = all(sum(item.get("method") == method for item in delivered) == expected_catalog for method in catalog_methods)
            state_ok = (actual_state["records"] == oracle.records and actual_state["receipts"] == oracle.receipts
                        and client.root_mode == oracle.root_mode)
            rows.append({"case": f"graph_campaign_{manifest['seed']}_{index:03}_{action['label']}", "mode": mode,
                "transport": transport, "evaluation": "protocol", "suite": "dense", "kind": "resilience",
                "feature": "Recovery decisions" if action["kind"] == "strategy" else "Recovery resilience" if action["kind"] == "resilience" else "Dependency graph campaigns", "campaign_seed": manifest["seed"], "campaign_step": index,
                "passed": bool(response_ok and state_ok and expected_uris == actual_uris and catalog_ok),
                "graph_nodes": len(manifest["graph"]), "graph_edges": sum(map(len, manifest["graph"].values())),
                "action": action, "responses": responses, "expected": expected_summary,
                "client_root_mode": client.root_mode, **root_checks,
                "state_matches_oracle": state_ok, "resource_notifications_match": expected_uris == actual_uris,
                "catalog_notifications_match": catalog_ok, "notifications": delivered, "client_requests": client.events[trace_start:],
                "receipt_count": len(actual_state["receipts"]), "audit": str(directory / "wire.jsonl"),
                "effects": str(directory / "effects.jsonl"), "client": str(directory / "client.jsonl"),
                "manifest": str(saved), "state_file": str(Path(config["state_path"]))})
            if index == 0:
                rows[-1]["graph_definition"] = copy.deepcopy(manifest["graph"])
            if all(row["passed"] for row in rows):
                save_checkpoint(directory, manifest, mode, transport, config, oracle, rows)
        for uri in sorted(subscribed):
            await session.unsubscribe_resource(uri)
        await session.send_ping()
    return rows
