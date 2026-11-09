"""Integrity-checked action-boundary checkpoints for local synthetic graph campaigns."""
from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path

from mcp import types


EVIDENCE_FILES = {"audit": "wire.jsonl", "effects": "effects.jsonl", "client": "client.jsonl", "state_file": "state.json"}


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()


def safe_path(directory, relative):
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError("checkpoint evidence path is outside its campaign")
    resolved = (directory / path).resolve()
    if not resolved.is_relative_to(directory.resolve()):
        raise ValueError("checkpoint evidence path escapes its campaign")
    return resolved


def save_checkpoint(directory, manifest, mode, transport, config, oracle, rows):
    normalized, evidence = copy.deepcopy(rows), {}
    for row in normalized:
        row["manifest"] = "campaign.json"
        for kind in EVIDENCE_FILES:
            if not row.get(kind):
                continue
            path = Path(row[kind]).resolve()
            try:
                relative = path.relative_to(directory.resolve()).as_posix()
            except ValueError as exc:
                raise ValueError("checkpoint evidence is outside campaign directory") from exc
            row[kind] = relative
            if relative in evidence:
                continue
            embedded = kind == "state_file" and relative == "state.json"
            data = canonical({"records": oracle.records, "receipts": oracle.receipts}) if embedded else path.read_bytes()
            evidence[relative] = {"kind": kind, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(), "embedded": embedded}
    state = json.loads(Path(config["state_path"]).read_text(encoding="utf-8"))
    if state != {"records": oracle.records, "receipts": oracle.receipts}:
        raise ValueError("cannot checkpoint unverified state")
    payload = {"schema_version": 1, "manifest_sha256": hashlib.sha256(canonical(manifest)).hexdigest(),
        "mode": mode, "transport": transport, "session": config["session"], "next_action": len(rows),
        "state": state, "faults": oracle.faults, "catalog_profile": oracle.profile, "rows": normalized, "evidence": evidence}
    envelope = {"payload": payload, "sha256": hashlib.sha256(canonical(payload)).hexdigest()}
    temporary = directory / "checkpoint.json.tmp"
    temporary.write_text(json.dumps(envelope, indent=2), encoding="utf-8")
    temporary.replace(directory / "checkpoint.json")


def _evidence_bytes(directory, relative, entry, state):
    if entry["embedded"]:
        if entry["kind"] != "state_file" or relative != "state.json":
            raise ValueError("invalid embedded checkpoint evidence")
        data = canonical(state)
    else:
        path = safe_path(directory, relative)
        with path.open("rb") as stream:
            data = stream.read(entry["size"])
    if len(data) != entry["size"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
        raise ValueError("checkpoint evidence integrity mismatch")
    return data


def load_checkpoint(path):
    if path.stat().st_size > 20_000_000:
        raise ValueError("checkpoint exceeds 20 MB")
    envelope = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(envelope, dict) or set(envelope) != {"payload", "sha256"}:
        raise ValueError("invalid checkpoint envelope")
    payload = envelope["payload"]
    if hashlib.sha256(canonical(payload)).hexdigest() != envelope["sha256"]:
        raise ValueError("checkpoint integrity mismatch")
    required = {"schema_version", "manifest_sha256", "mode", "transport", "session", "next_action", "state", "faults", "catalog_profile", "rows", "evidence"}
    if not isinstance(payload, dict) or set(payload) != required or payload["schema_version"] != 1:
        raise ValueError("invalid checkpoint payload")
    if (payload["mode"] not in ("hardened", "vulnerable") or payload["transport"] not in ("stdio", "sse")
            or not isinstance(payload["session"], str) or not re.fullmatch(r"[a-f0-9]{32}", payload["session"])
            or type(payload["next_action"]) is not int or not isinstance(payload["rows"], list)
            or not 0 <= payload["next_action"] <= 200 or len(payload["rows"]) != payload["next_action"]
            or payload["catalog_profile"] not in ("standard", "compact") or not isinstance(payload["evidence"], dict)):
        raise ValueError("invalid checkpoint state metadata")
    from .campaign import read_manifest
    manifest = read_manifest(path.parent / "campaign.json")
    if manifest["schema_version"] != 2 or hashlib.sha256(canonical(manifest)).hexdigest() != payload["manifest_sha256"]:
        raise ValueError("checkpoint manifest mismatch")
    if payload["next_action"] > len(manifest["actions"]):
        raise ValueError("checkpoint exceeds campaign length")
    for index, row in enumerate(payload["rows"]):
        if (not isinstance(row, dict) or row.get("campaign_step") != index or row.get("passed") is not True
                or row.get("action") != manifest["actions"][index] or row.get("mode") != payload["mode"]
                or row.get("transport") != payload["transport"]):
            raise ValueError("checkpoint rows do not match verified campaign progress")
        for kind in EVIDENCE_FILES:
            if (not isinstance(row.get(kind), str) or row[kind] not in payload["evidence"]
                    or not isinstance(payload["evidence"][row[kind]], dict) or payload["evidence"][row[kind]].get("kind") != kind):
                raise ValueError("checkpoint row evidence is missing")
    total = 0
    for relative, entry in payload["evidence"].items():
        if (not isinstance(entry, dict) or set(entry) != {"kind", "size", "sha256", "embedded"}
                or entry["kind"] not in EVIDENCE_FILES or type(entry["size"]) is not int or not 0 <= entry["size"] <= 64_000_000
                or type(entry["embedded"]) is not bool or not isinstance(entry["sha256"], str)
                or not re.fullmatch(r"[a-f0-9]{64}", entry["sha256"])):
            raise ValueError("invalid checkpoint evidence metadata")
        total += entry["size"]
        if total > 256_000_000:
            raise ValueError("checkpoint evidence exceeds 256 MB")
        safe_path(path.parent, relative)
        _evidence_bytes(path.parent, relative, entry, payload["state"])
    return manifest, payload


def rebuild_oracle(oracle, manifest, payload):
    from .graph_campaign import matches
    for index, row in enumerate(payload["rows"]):
        action, responses = manifest["actions"][index], row.get("responses", [])
        if action["kind"] == "call":
            if len(responses) != 1:
                raise ValueError("invalid checkpoint response count")
            expected = oracle.call(action["tool"], action["arguments"], action["approval"])
            if not matches(expected, types.CallToolResult.model_validate(responses[0]), oracle.graph):
                raise ValueError("checkpoint response fails reference oracle")
        else:
            order = row.get("expected", {}).get("legal_serialization", [])
            if (not isinstance(order, list) or any(type(item) is not int for item in order)
                    or sorted(order) != list(range(len(action["requests"]))) or len(responses) != len(order)):
                raise ValueError("invalid checkpoint race serialization")
            for request_index in order:
                expected = oracle.call("batch_update_records", action["requests"][request_index])
                if not matches(expected, types.CallToolResult.model_validate(responses[request_index]), oracle.graph):
                    raise ValueError("checkpoint race fails reference oracle")
    if (payload["state"] != {"records": oracle.records, "receipts": oracle.receipts}
            or payload["faults"] != oracle.faults or payload["catalog_profile"] != oracle.profile):
        raise ValueError("checkpoint state fails reference oracle")


def restore_history(source, destination, payload):
    paths = {}
    for relative, entry in payload["evidence"].items():
        data = _evidence_bytes(source, relative, entry, payload["state"])
        target = destination / "history" / (entry["sha256"] + "-" + EVIDENCE_FILES[entry["kind"]])
        target.parent.mkdir(exist_ok=True)
        target.write_bytes(data)
        paths[relative] = str(target)
    rows = copy.deepcopy(payload["rows"])
    for row in rows:
        row["manifest"] = str(destination / "campaign.json")
        for kind in EVIDENCE_FILES:
            row[kind] = paths[row[kind]]
    return rows
