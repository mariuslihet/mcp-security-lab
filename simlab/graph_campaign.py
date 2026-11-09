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
               "analyze_dependencies", "incident_bundle", "set_catalog_profile")
APPROVALS = ("accept", "decline", "cancel", "false", "wrong_digest")
CALL_SCHEMA = {"oneOf": [{"type": "object", "additionalProperties": False,
    "required": ["kind", "tool", "arguments", "approval", "label"], "properties": {
        "kind": {"const": "call"}, "tool": {"const": tool}, "arguments": SCHEMAS[tool],
        "approval": {"enum": list(APPROVALS)}, "label": {"type": "string", "maxLength": 80}}} for tool in GRAPH_TOOLS]}
RACE_SCHEMA = {"type": "object", "required": ["kind", "requests", "label"], "additionalProperties": False, "properties": {
    "kind": {"const": "race"}, "label": {"type": "string", "maxLength": 80},
    "requests": {"type": "array", "minItems": 2, "maxItems": 32, "items": SCHEMAS["batch_update_records"]}}}
GRAPH_MANIFEST_SCHEMA = {"type": "object", "required": ["schema_version", "seed", "graph", "actions"], "additionalProperties": False,
    "properties": {"schema_version": {"const": 2}, "seed": {"type": "integer"}, "graph": {"type": "object"},
        "actions": {"type": "array", "minItems": 1, "maxItems": 200, "items": {"oneOf": [CALL_SCHEMA, RACE_SCHEMA]}}}}


def validate_graph_manifest(manifest):
    if not Draft202012Validator(GRAPH_MANIFEST_SCHEMA).is_valid(manifest):
        raise ValueError("invalid dependency campaign manifest")
    validate_graph(manifest["graph"])
    allowed = set(manifest["graph"]) | {"PAY-001"}
    for action in manifest["actions"]:
        requests = action["requests"] if action["kind"] == "race" else [action["arguments"]]
        for arguments in requests:
            updates = arguments.get("updates", [arguments])
            if any(item.get("record_id") not in allowed for item in updates if "record_id" in item):
                raise ValueError("dependency campaign references an unsupported record")
        if action["kind"] == "race":
            # Every request shares the same two updates, differing only in receipt key.
            first = action["requests"][0]
            if len(first["updates"]) != 2 or len({item["record_id"] for item in first["updates"]}) != 2:
                raise ValueError("graph races require two distinct shared records")
            if any(request["updates"] != first["updates"] or request["handle"] != first["handle"] for request in action["requests"]):
                raise ValueError("graph races must share the same update set and authority")
            if len({request["idempotency_key"] for request in action["requests"]}) != len(action["requests"]):
                raise ValueError("graph race request keys must be distinct")
    return manifest


def generate_graph_manifest(seed, steps=60, *, nodes=32, width=4, parallel_calls=8):
    if type(steps) is not int or not 1 <= steps <= 200 or type(parallel_calls) is not int or not 2 <= parallel_calls <= 32:
        raise ValueError("graph campaigns require 1 to 200 actions and 2 to 32 parallel requests")
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

    call("analyze_dependencies", {"record_id": tip}, "initial_analysis")
    call("incident_bundle", {"record_id": tip}, "linked_resources")
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
    shared = [update("GR-000"), update("GR-001")]
    race = {"kind": "race", "label": "overlapping_root_resolutions",
            "requests": [batch(copy.deepcopy(shared), f"graph-race-{index}") for index in range(parallel_calls)]}
    actions.extend([race, {**copy.deepcopy(race), "label": "replayed_race"}])
    conflict = copy.deepcopy(first_batch)
    conflict["updates"][0]["status"] = "resolved"
    call("batch_update_records", conflict, "receipt_payload_conflict")
    guided("GR-002", "approved_root")
    guided("GR-002", "approved_root")
    for layer in layers:
        members = [key for key in layer if key not in {"GR-000", "GR-001", "GR-002"}]
        for offset in range(0, len(members), 16):
            selected = list(reversed(members[offset:offset + 16]))
            call("batch_update_records", batch([update(key) for key in selected], f"resolve-{len(actions)}"), "dependency_wave")
    call("analyze_dependencies", {"record_id": tip}, "completed_analysis")
    call("incident_bundle", {"record_id": tip}, "completed_resources")
    minimum = len(actions)
    if steps < minimum:
        raise ValueError(f"this graph needs at least {minimum} campaign actions")
    while len(actions) < steps:
        index, key = len(actions), rng.choice(ordered)
        if index % 5 == 0:
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

    def closure(self, key):
        selected, todo = set(), [key]
        while todo:
            current = todo.pop()
            if current not in selected:
                selected.add(current)
                todo += self.graph.get(current, [])
        return selected

    def call(self, tool, args, approval="accept"):
        unchanged = {"error": True, "changed": []}
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
    client = ControlledClient(config, directory / "client.jsonl")
    oracle = GraphOracle(config, hardened)
    if resumed:
        rebuild_oracle(oracle, manifest, resumed)
        rows = restore_history(resume_checkpoint.parent, directory, resumed)
        Path(config["state_path"]).write_text(json.dumps(resumed["state"], indent=2), encoding="utf-8")
        config["faults"] = dict(oracle.faults)
        config["initial_catalog_profile"] = oracle.profile
        config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    save_checkpoint(directory, manifest, mode, transport, config, oracle, rows)
    if first == limit:
        return rows
    subscribed = {"lab://incidents/" + key for key in (sorted(manifest["graph"])[0], sorted(manifest["graph"])[-1])}
    async def receive(message):
        if isinstance(message, types.ServerNotification):
            notifications.append(message.model_dump(mode="json", by_alias=True))
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
            if action["kind"] == "call":
                client.approval = action["approval"]
                expected = oracle.call(action["tool"], action["arguments"], action["approval"])
                result = await call(action["tool"], action["arguments"])
                response_ok = matches(expected, result, oracle.graph)
                expected_notifications += ["lab://incidents/" + key for key in expected["changed"]]
                expected_catalog = int(expected.get("catalog_changed", False))
                responses = [result.model_dump(mode="json")]
                expected_summary = {key: value for key, value in expected.items() if key not in ("resource_set",)}
            else:
                results = await asyncio.gather(*(call("batch_update_records", request) for request in action["requests"]))
                shared = action["requests"][0]["updates"][0]["record_id"]
                def observed_version(index):
                    value = results[index].structuredContent or {}
                    return next((record["version"] for record in value.get("records", []) if record["id"] == shared), float("inf"))
                # A common record's observed versions select a candidate legal serialization.
                # Every response AND the full saved state/receipts must then agree with it.
                order = sorted(range(len(results)), key=observed_version)
                for request_index in order:
                    expected = oracle.call("batch_update_records", action["requests"][request_index])
                    response_ok &= matches(expected, results[request_index], oracle.graph)
                    expected_notifications += ["lab://incidents/" + key for key in expected["changed"]]
                responses = [result.model_dump(mode="json") for result in results]
                expected_summary = {"legal_serialization": order, "accepted": sum(not result.isError for result in results)}
            actual_state = json.loads(Path(config["state_path"]).read_text(encoding="utf-8"))
            delivered = notifications[start:]
            expected_uris = Counter(uri for uri in expected_notifications if uri in subscribed)
            actual_uris = Counter(item["params"]["uri"] for item in delivered if item.get("method") == "notifications/resources/updated")
            catalog_methods = ("notifications/tools/list_changed", "notifications/resources/list_changed", "notifications/prompts/list_changed")
            catalog_ok = all(sum(item.get("method") == method for item in delivered) == expected_catalog for method in catalog_methods)
            state_ok = actual_state["records"] == oracle.records and actual_state["receipts"] == oracle.receipts
            rows.append({"case": f"graph_campaign_{manifest['seed']}_{index:03}_{action['label']}", "mode": mode,
                "transport": transport, "evaluation": "protocol", "suite": "dense", "kind": "resilience",
                "feature": "Dependency graph campaigns", "campaign_seed": manifest["seed"], "campaign_step": index,
                "passed": bool(response_ok and state_ok and expected_uris == actual_uris and catalog_ok),
                "graph_nodes": len(manifest["graph"]), "graph_edges": sum(map(len, manifest["graph"].values())),
                "action": action, "responses": responses, "expected": expected_summary,
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
