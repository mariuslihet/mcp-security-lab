"""Composed client-callback scenarios over real MCP, with controlled client policies."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from .client import connect
from .client_profiles import ControlledClient
from .fixtures import WRITE_HANDLE, create_fixture, read_jsonl


async def interactive_matrix(directory: Path, mode: str, transport: str, *, parallel_calls=8):
    # A concurrency probe must not accidentally become a deadline probe. The slow
    # client profile explicitly exceeds this budget in its own scenario.
    config_path, config = create_fixture(directory, dense=True, fault_profile="transient",
                                         callback_timeout_seconds=max(2, parallel_calls * 0.1))
    hardened, rows = mode == "hardened", []
    prefix = "sim_" if hardened else ""
    client = ControlledClient(config, directory / "client.jsonl")
    trace_cursor = 0

    def state():
        return json.loads(Path(config["state_path"]).read_text(encoding="utf-8"))
    def args(record_id="INC-002", *, key="guided-main", version=1, status="investigating"):
        return {"record_id": record_id, "expected_version": version, "status": status,
                "handle": WRITE_HANDLE, "idempotency_key": key}
    def record(case, passed, *, feature, kind="benign", **details):
        nonlocal trace_cursor
        rows.append({"case": case, "passed": bool(passed), "feature": feature, "kind": kind,
                     "client_requests": client.events[trace_cursor:], **details})
        trace_cursor = len(client.events)

    async with connect(config_path, mode, directory / "wire.jsonl", transport, **client.callbacks()) as session:
        async def call(name, arguments):
            return await session.call_tool(prefix + name, arguments)
        roots = await call("inspect_client_roots", {})
        record("client_roots_roundtrip", not roots.isError and roots.structuredContent["workspace_advertised"], feature="Client roots")
        sampled = await call("sample_incident", {"record_id": "INC-001"})
        record("client_sampling_roundtrip", not sampled.isError and sampled.structuredContent["summary"] == "Synthetic incident reviewed.",
               feature="Sampling")
        reviewed = await call("request_incident_input", {"record_id": "INC-001"})
        record("client_form_review", not reviewed.isError and reviewed.structuredContent["action"] == "accept", feature="Elicitation")
        client.sampling_mode = "poison"
        sampled = await call("sample_incident", {"record_id": "INC-001"})
        summary = sampled.structuredContent["summary"]
        record("client_sampling_injection_filter", not sampled.isError and ("SYSTEM OVERRIDE" not in summary if hardened else "SYSTEM OVERRIDE" in summary),
               feature="Sampling", kind="attack", response=sampled.model_dump(mode="json"))
        client.sampling_mode = "normal"
        start = len(client.calls)
        uncertain = await call("guided_update_record", args())
        after_commit = state()
        retry_start = len(client.calls)
        retry = await call("guided_update_record", args())
        record("client_guided_commit_and_retry", uncertain.isError and not retry.isError
               and retry.structuredContent["record"]["version"] == (2 if hardened else 3)
               and len(client.calls) - start == (3 if hardened else 6)
               and len(client.calls) - retry_start == (0 if hardened else 3)
               and after_commit["records"]["INC-002"]["version"] == 2,
               feature="Guided updates", callbacks=client.calls[start:], response=retry.model_dump(mode="json"))
        conflict = await call("guided_update_record", args(version=2 if hardened else 3, status="resolved"))
        record("client_guided_receipt_conflict", conflict.isError if hardened else not conflict.isError,
               feature="Guided updates", kind="attack", blocked=conflict.isError)
        for approval in ("decline", "cancel", "false", "wrong_digest"):
            client.approval = approval
            before = state()
            result = await call("guided_update_record", args("INC-001", key="approval-" + approval))
            accepted = result.isError if approval == "wrong_digest" else not result.isError and result.structuredContent["committed"] is False
            record("client_approval_" + approval, accepted and state() == before, feature="Elicitation",
                   response=result.model_dump(mode="json"))
        client.approval = "accept"
        client.root_mode = "outside"
        result = await call("guided_update_record", args("INC-003", key="root-outside"))
        record("client_untrusted_root_boundary", result.isError if hardened else not result.isError,
               feature="Client roots", kind="attack", blocked=result.isError)
        client.root_mode = "duplicate"
        result = await call("inspect_client_roots", {})
        record("client_duplicate_roots_rejected", result.isError, feature="Client roots")
        client.root_mode = "workspace"
        protected = await call("sample_incident", {"record_id": "PAY-001"})
        record("client_protected_sampling_scope", protected.isError if hardened else not protected.isError,
               feature="Sampling", kind="attack", blocked=protected.isError)
        for profile in ("wrong_role", "error", "slow"):
            client.sampling_mode = profile
            before = state()
            result = await call("guided_update_record", args("INC-005", key="sampling-" + profile))
            record("client_sampling_failure_" + profile, result.isError and state() == before,
                   feature="Callback recovery", response=result.model_dump(mode="json"))
            await session.send_ping()
        client.sampling_mode = "normal"
        results = await asyncio.gather(*(call("guided_update_record", args("INC-004", key=f"guided-race-{index}"))
                                         for index in range(parallel_calls)))
        accepted = sum(not result.isError for result in results)
        record("client_concurrent_guided_updates", accepted == (1 if hardened else parallel_calls)
               and state()["records"]["INC-004"]["version"] == (2 if hardened else parallel_calls + 1),
               feature="Concurrent workflows", kind="attack", accepted=accepted, rejected=parallel_calls - accepted)
        result = await call("calculate", {"expression": "(8+4)/3"})
        record("client_benign_after_callback_failures", not result.isError and result.structuredContent["result"] == 4,
               feature="Callback recovery")

    missing_dir = directory / "no-client-capabilities"
    missing_config, missing = create_fixture(missing_dir, dense=True)
    async with connect(missing_config, mode, missing_dir / "wire.jsonl", transport) as session:
        result = await session.call_tool(prefix + "guided_update_record", args())
        record("client_capability_negotiation", result.isError and "client_capability_missing" in result.content[0].text,
               feature="Capability negotiation", audit=str(missing_dir / "wire.jsonl"), effects=str(missing_dir / "effects.jsonl"))

    events = read_jsonl(directory / "effects.jsonl")
    record("client_hardened_state_invariants", not any(event.get("unauthorized") or event.get("stale") or event.get("invalid_transition")
               for event in events if event["event"] == "record_changed") if hardened else
           any(event.get("stale") or event.get("invalid_transition") for event in events if event["event"] == "record_changed"),
           feature="Guided updates", kind="evidence")
    for row in rows:
        row.update(mode=mode, transport=transport, evaluation="protocol", suite="dense")
        row.setdefault("audit", str(directory / "wire.jsonl"))
        row.setdefault("effects", str(directory / "effects.jsonl"))
        row["client"] = str(directory / "client.jsonl")
    return rows
