"""Seeded, replayable guided-update campaigns checked against an independent state oracle."""
from __future__ import annotations

import copy
import json
import random
from pathlib import Path

from jsonschema import Draft202012Validator

from .client import connect
from .client_profiles import ControlledClient
from .controls import SCHEMAS
from .fixtures import HANDLE, WRITE_HANDLE, create_fixture


MANIFEST_SCHEMA = {"type": "object", "required": ["schema_version", "seed", "actions"], "additionalProperties": False,
    "properties": {"schema_version": {"const": 1}, "seed": {"type": "integer"},
        "actions": {"type": "array", "minItems": 1, "maxItems": 200, "items": {
            "type": "object", "required": ["approval", "arguments"], "additionalProperties": False,
            "properties": {"approval": {"enum": ["accept", "decline", "cancel", "false", "wrong_digest"]},
                           "arguments": SCHEMAS["guided_update_record"]}}}}}


def generate_manifest(seed: int, steps: int) -> dict:
    if type(seed) is not int or type(steps) is not int or not 1 <= steps <= 200:
        raise ValueError("campaign requires an integer seed and 1 to 200 steps")
    rng, actions = random.Random(seed), []
    reference = {f"INC-{index:03}": {"status": "open", "version": 1} for index in range(1, 13)}
    for index in range(steps):
        if index and index % 7 == 0:
            # Identical key/payload retry; client policy may have changed since the original request.
            actions.append(copy.deepcopy(actions[-1]))
            continue
        if index and index % 11 == 0:
            changed = copy.deepcopy(actions[-1])
            changed["arguments"]["status"] = "resolved" if changed["arguments"]["status"] != "resolved" else "open"
            actions.append(changed)
            continue
        key = rng.choice(list(reference) + ["PAY-001"])
        record = reference.get(key, {"status": "open", "version": 1})
        target = rng.choice(["open", "investigating", "resolved"])
        approval = rng.choice(["accept"] * 5 + ["decline", "cancel", "false", "wrong_digest"])
        handle = WRITE_HANDLE if rng.random() > 0.2 else HANDLE
        version = record["version"] if rng.random() > 0.25 else record["version"] + 5
        if index % 5 == 0:
            candidates = [name for name, value in reference.items() if value["status"] != "resolved"]
            if candidates:
                key = rng.choice(candidates)
                record = reference[key]
                target = "investigating" if record["status"] == "open" else "resolved"
                approval, handle, version = "accept", WRITE_HANDLE, record["version"]
        args = {"record_id": key, "expected_version": version, "status": target,
                "handle": handle, "idempotency_key": f"campaign-{seed}-{index}"}
        actions.append({"approval": approval, "arguments": args})
        if (key in reference and version == record["version"] and handle == WRITE_HANDLE and approval == "accept"
                and (record["status"], target) in {("open", "investigating"), ("investigating", "resolved")}):
            reference[key] = {"status": target, "version": version + 1}
    return {"schema_version": 1, "seed": seed, "actions": actions}


def read_manifest(path: Path) -> dict:
    if path.stat().st_size > 1_000_000:
        raise ValueError("campaign manifest exceeds 1 MB")
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(manifest, dict) and manifest.get("schema_version") == 2:
        from .graph_campaign import validate_graph_manifest
        return validate_graph_manifest(manifest)
    if not Draft202012Validator(MANIFEST_SCHEMA).is_valid(manifest):
        raise ValueError("invalid campaign manifest")
    # Manifests are limited to the lab's independent synthetic records, without file or network actions.
    allowed = {f"INC-{index:03}" for index in range(1, 13)} | {"PAY-001"}
    if any(action["arguments"]["record_id"] not in allowed for action in manifest["actions"]):
        raise ValueError("campaign references an unsupported synthetic record")
    return manifest


def expected_step(records, receipts, action, hardened):
    """Small reference model: callbacks never grant authority or change chosen arguments."""
    args, approval = action["arguments"], action["approval"]
    current = records[args["record_id"]]
    authorized = args["record_id"] != "PAY-001" and args["handle"] == WRITE_HANDLE
    fingerprint = json.dumps(args, sort_keys=True)
    receipt = receipts.get(args["idempotency_key"])
    if hardened and not authorized:
        return {"error": True}
    if hardened and receipt:
        return ({"error": True} if receipt["fingerprint"] != fingerprint else
                {"error": False, "record": copy.deepcopy(receipt["record"]), "deduplicated": True})
    valid = (args["expected_version"] == current["version"] and (current["status"], args["status"]) in
             {("open", "investigating"), ("investigating", "resolved")})
    if hardened and not valid or approval == "wrong_digest":
        return {"error": True}
    if approval != "accept":
        return {"error": False, "committed": False, "action": "decline" if approval == "false" else approval}
    current.update(status=args["status"], version=current["version"] + 1)
    receipts[args["idempotency_key"]] = {"fingerprint": fingerprint, "record": copy.deepcopy(current)}
    return {"error": False, "record": copy.deepcopy(current), "deduplicated": False}


async def campaign_matrix(directory: Path, mode: str, transport: str, *, seed=7, steps=40, manifest_path: Path | None = None,
                          graph_nodes=0, graph_width=4, parallel_calls=8, race_topology="shared", root_churn=False, outage_stress=False):
    if manifest_path is not None:
        manifest = read_manifest(manifest_path)
    elif graph_nodes:
        from .graph_campaign import generate_graph_manifest
        manifest = generate_graph_manifest(seed, steps, nodes=graph_nodes, width=graph_width, parallel_calls=parallel_calls,
                                           race_topology=race_topology, root_churn=root_churn, outage_stress=outage_stress)
    else:
        manifest = generate_manifest(seed, steps)
    if manifest["schema_version"] == 2:
        from .graph_campaign import graph_campaign_matrix
        return await graph_campaign_matrix(directory, mode, transport, manifest)
    config_path, config = create_fixture(directory, dense=True)
    saved_manifest = directory / "campaign.json"
    saved_manifest.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    client = ControlledClient(config, directory / "client.jsonl")
    hardened = mode == "hardened"
    records = json.loads(Path(config["state_path"]).read_text(encoding="utf-8"))["records"]
    receipts, rows = {}, []
    async with connect(config_path, mode, directory / "wire.jsonl", transport, **client.callbacks()) as session:
        for index, action in enumerate(manifest["actions"]):
            client.approval = action["approval"]
            expected = expected_step(records, receipts, action, hardened)
            start = len(client.calls)
            event_start = len(client.events)
            result = await session.call_tool(("sim_" if hardened else "") + "guided_update_record", action["arguments"])
            observed = result.structuredContent or {}
            published = json.loads(Path(config["state_path"]).read_text(encoding="utf-8"))
            response_ok = bool(result.isError) == expected["error"]
            if not expected["error"]:
                response_ok &= all(observed.get(key) == value for key, value in expected.items() if key != "error")
            passed = response_ok and published["records"] == records and len(published["receipts"]) == len(receipts)
            rows.append({"case": f"campaign_{manifest['seed']}_{index:03}", "evaluation": "protocol", "suite": "dense",
                "mode": mode, "transport": transport, "kind": "resilience", "feature": "Seeded campaigns", "passed": passed,
                "campaign_seed": manifest["seed"], "campaign_step": index, "arguments": action["arguments"],
                "approval": action["approval"], "expected": expected, "response": result.model_dump(mode="json"),
                "callbacks": client.calls[start:], "published_record": published["records"][action["arguments"]["record_id"]],
                "client_requests": client.events[event_start:],
                "receipt_count": len(published["receipts"]), "audit": str(directory / "wire.jsonl"),
                "effects": str(directory / "effects.jsonl"), "client": str(directory / "client.jsonl"),
                "manifest": str(saved_manifest), "state_file": str(Path(config["state_path"]))})
        await session.send_ping()
    return rows
