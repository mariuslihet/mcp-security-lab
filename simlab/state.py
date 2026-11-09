"""Per-server incident state, optimistic updates, and durable retry receipts."""
from __future__ import annotations

import asyncio
import base64
import copy
import hashlib
import hmac
import json
from pathlib import Path

from jsonschema import Draft202012Validator

from .controls import SCHEMAS, Denied, Firewall


class IncidentStore:
    def __init__(self, config: dict, journal):
        self.config = config
        self.path = Path(config["state_path"])
        self.journal = journal
        self.lock = asyncio.Lock()

    def read(self, record_id: str) -> dict:
        data = json.loads(self.path.read_text(encoding="utf-8"))
        if record_id not in data["records"]:
            raise Denied("record_not_found")
        return copy.deepcopy(data["records"][record_id])

    def plan_resolution(self, record_id: str, hardened: bool) -> dict:
        if hardened:
            Firewall(self.config).check("sim_plan_resolution", {"record_id": record_id})
        records = json.loads(self.path.read_text(encoding="utf-8"))["records"]
        steps = self._resolution_steps(record_id, records, hardened)
        self.journal("resolution_planned", record_id=record_id, steps=len(steps))
        return {"record_id": record_id, "steps": steps}

    def _resolution_steps(self, record_id: str, records: dict, hardened: bool) -> list[dict]:
        steps, visiting, visited = [], set(), set()

        def visit(key):
            if hardened and key not in self.config["allowed_records"]:
                raise Denied("record_not_authorized")
            if key not in records:
                raise Denied("record_not_found")
            if key in visiting:
                raise Denied("dependency_cycle")
            if key in visited:
                return
            visiting.add(key)
            dependencies = self.config.get("dependencies", {}).get(key, [])
            for dependency in dependencies:
                visit(dependency)
            visiting.remove(key)
            visited.add(key)
            steps.append({"record": copy.deepcopy(records[key]), "depends_on": list(dependencies),
                          "blocked_by": [dep for dep in dependencies if records[dep]["status"] != "resolved"]})

        visit(record_id)
        return steps

    def analyze_dependencies(self, record_id: str, hardened: bool) -> dict:
        if hardened:
            Firewall(self.config).check("sim_analyze_dependencies", {"record_id": record_id})
        records = json.loads(self.path.read_text(encoding="utf-8"))["records"]
        steps = self._resolution_steps(record_id, records, hardened)
        paths, levels = {}, {}
        for step in steps:
            key, parents = step["record"]["id"], step["depends_on"]
            parent = max(parents, key=lambda item: (len(paths[item]), item)) if parents else None
            paths[key] = (paths[parent] if parent else []) + [key]
            levels[key] = len(paths[key]) - 1
        layers = [[key for key in sorted(levels) if levels[key] == level] for level in range(max(levels.values()) + 1)]
        return {"record_id": record_id, "node_count": len(steps), "edge_count": sum(len(step["depends_on"]) for step in steps),
                "layers": layers, "critical_path": paths[record_id],
                "unresolved": sorted(step["record"]["id"] for step in steps if step["record"]["status"] != "resolved")}

    def list_records(self, arguments: dict, hardened: bool) -> dict:
        # Bound pagination in both arms; the vulnerable arm intentionally exposes protected records.
        if hardened:
            Firewall(self.config).check("sim_list_records", arguments)
        else:
            if not Draft202012Validator(SCHEMAS["list_records"]).is_valid(arguments):
                raise Denied("argument_schema_denied")
        records = json.loads(self.path.read_text(encoding="utf-8"))["records"]
        visible = {key: value for key, value in records.items()
                   if not hardened or key in self.config["allowed_records"]}
        snapshot = hashlib.sha256(json.dumps(visible, sort_keys=True).encode()).hexdigest()
        scope = {"snapshot": snapshot, "session": self.config["session"], "hardened": hardened,
                 "status": arguments["status"], "limit": arguments["limit"]}
        secret = self.config["cursor_secret"].encode()
        offset = 0
        if arguments["cursor"]:
            try:
                encoded, signature = arguments["cursor"].split(".")
                expected = hmac.new(secret, encoded.encode(), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(signature, expected):
                    raise ValueError("signature")
                payload = json.loads(base64.urlsafe_b64decode(encoded.encode()).decode())
                offset = payload.pop("offset")
                if payload != scope or type(offset) is not int or offset < 1:
                    raise ValueError("scope or snapshot")
            except (ValueError, KeyError, TypeError, AttributeError, UnicodeError) as exc:
                raise Denied("cursor_invalid_or_stale") from exc
        matches = [visible[key] for key in sorted(visible)
                   if arguments["status"] == "all" or visible[key]["status"] == arguments["status"]]
        if offset and offset >= len(matches):
            raise Denied("cursor_invalid_or_stale")
        page = matches[offset:offset + arguments["limit"]]
        next_offset = offset + len(page)
        cursor = ""
        if next_offset < len(matches):
            encoded = base64.urlsafe_b64encode(json.dumps({**scope, "offset": next_offset}, sort_keys=True).encode()).decode()
            cursor = encoded + "." + hmac.new(secret, encoded.encode(), hashlib.sha256).hexdigest()
        self.journal("records_listed", status=arguments["status"], count=len(page), total=len(matches),
                     offset=offset, protected_exposed=any(record["id"] not in self.config["allowed_records"] for record in page))
        return {"records": copy.deepcopy(page), "total": len(matches), "next_cursor": cursor}

    async def update(self, arguments: dict, hardened: bool) -> dict:
        return await self._mutate(arguments, hardened, batch=False)

    async def batch_update(self, arguments: dict, hardened: bool) -> dict:
        return await self._mutate(arguments, hardened, batch=True)

    async def preview_updates(self, arguments: dict, hardened: bool) -> dict:
        return await self._mutate(arguments, hardened, batch=True, dry_run=True)

    def replay_guided(self, arguments: dict) -> dict | None:
        Firewall(self.config).check("sim_guided_update_record", arguments)
        data = json.loads(self.path.read_text(encoding="utf-8"))
        return self._replay(data, arguments, "guided_update_record")

    def _replay(self, data, arguments, operation):
        key = self.config["session"] + ":" + arguments["idempotency_key"]
        receipt = data["receipts"].get(key)
        if receipt is None:
            return None
        fingerprint = json.dumps({"operation": operation, "arguments": arguments}, sort_keys=True)
        if receipt["fingerprint"] != fingerprint:
            raise Denied("idempotency_conflict")
        self.journal("idempotent_replay", operation=operation, key=arguments["idempotency_key"])
        return {**copy.deepcopy(receipt["result"]), "deduplicated": True}

    async def guided_update(self, arguments: dict, hardened: bool):
        return await self._mutate(arguments, hardened, batch=False, operation_name="guided_update_record")

    async def _mutate(self, arguments: dict, hardened: bool, *, batch: bool, dry_run: bool = False,
                      operation_name: str | None = None) -> dict:
        operation = operation_name or ("preview_updates" if dry_run else "batch_update_records" if batch else "update_record")
        if hardened:
            # Enforce authority even when called without the transport firewall.
            Firewall(self.config).check("sim_" + operation, arguments)
        async with self.lock:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            key = self.config["session"] + ":" + arguments.get("idempotency_key", "")
            fingerprint = json.dumps({"operation": operation, "arguments": arguments}, sort_keys=True)
            receipt = data["receipts"].get(key) if not dry_run else None
            if hardened and receipt:
                return self._replay(data, arguments, operation)
            handle = self.config["handles"].get(arguments["handle"], {})
            updates = arguments["updates"] if batch else [arguments]
            changed, results = [], []
            for update in updates:
                record_id = update["record_id"]
                if record_id not in data["records"]:
                    raise Denied("record_not_found")
                record = data["records"][record_id]
                stale = record["version"] != update["expected_version"]
                allowed_transition = (record["status"], update["status"]) in {
                    ("open", "investigating"), ("investigating", "resolved")}
                if hardened and stale:
                    raise Denied("version_conflict")
                if hardened and not allowed_transition:
                    raise Denied("transition_denied")
                authorized = (record_id in self.config["allowed_records"]
                              and handle.get("session") == self.config["session"]
                              and handle.get("audience") == "ops"
                              and "record:update" in handle.get("scopes", []))
                before = copy.deepcopy(record)
                record.update(status=update["status"], version=record["version"] + 1)
                results.append(copy.deepcopy(record))
                changed.append(dict(record_id=record_id, before=before, after=copy.deepcopy(record),
                                    unauthorized=not authorized, stale=stale, invalid_transition=not allowed_transition,
                                    duplicate_key=receipt is not None, idempotency_key=arguments.get("idempotency_key"),
                                    operation=operation))
            # Validate the proposed final state so batch order cannot change the outcome.
            for event in changed:
                if hardened and event["after"]["status"] == "resolved":
                    self._resolution_steps(event["record_id"], data["records"], True)
                dependencies = self.config.get("dependencies", {}).get(event["record_id"], [])
                blocked = [dep for dep in dependencies if data["records"].get(dep, {}).get("status") != "resolved"]
                event["dependency_violation"] = bool(event["after"]["status"] == "resolved" and blocked)
                if hardened and event["dependency_violation"]:
                    raise Denied("dependency_unresolved")
            if dry_run:
                self.journal("updates_previewed", record_ids=[item["record_id"] for item in updates], updates=len(updates))
                return {"records": results, "would_commit": True}
            result = {"records" if batch else "record": results if batch else results[0], "deduplicated": False}
            data["receipts"][key] = {"fingerprint": fingerprint, "result": result}
            temporary = self.path.with_suffix(".tmp")
            temporary.write_text(json.dumps(data, indent=2), encoding="utf-8")
            temporary.replace(self.path)
            for event in changed:
                self.journal("record_changed", **event)
            if batch:
                self.journal("transaction_committed", record_ids=[item["record_id"] for item in updates],
                             idempotency_key=arguments["idempotency_key"], updates=len(updates))
            return result
