"""Real-transport probes for native MCP features and notification lifecycles."""
from __future__ import annotations

import json
import asyncio
from pathlib import Path

from mcp import types
from mcp.shared.exceptions import McpError

from .client import connect
from .fixtures import WRITE_HANDLE, create_fixture, read_jsonl
from .mcp_features import INCIDENT_TEMPLATE


async def native_matrix(directory: Path, mode: str, transport: str):
    config_path, config = create_fixture(directory, dense=True, fault_profile="transient", latency_ms=40)
    hardened = mode == "hardened"
    prefix = "sim_" if hardened else ""
    rows, notifications = [], []

    def record(case, passed, *, kind="benign", **evidence):
        rows.append({"case": case, "passed": bool(passed), "kind": kind, **evidence})

    async def receive(message):
        if isinstance(message, types.ServerNotification):
            notifications.append(message.model_dump(mode="json", by_alias=True))

    async with connect(config_path, mode, directory / "wire.jsonl", transport, message_handler=receive) as session:
        caps = session.get_server_capabilities()
        record("mcp_native_capabilities", caps.resources.subscribe and caps.completions is not None and caps.logging is not None)
        templates = await session.list_resource_templates()
        record("mcp_incident_resource_template", any(item.uriTemplate == INCIDENT_TEMPLATE for item in templates.resourceTemplates))
        resource = await session.read_resource("lab://incidents/INC-001")
        record("mcp_incident_resource_read", json.loads(resource.contents[0].text)["record"]["version"] == 1)
        prompt = await session.get_prompt("incident_triage", {"record_id": "WF-006"})
        record("mcp_parameterized_prompt", "WF-006" in prompt.messages[0].content.text)
        for kind, ref in (("resource", types.ResourceTemplateReference(type="ref/resource", uri=INCIDENT_TEMPLATE)),
                          ("prompt", types.PromptReference(type="ref/prompt", name="incident_triage"))):
            result = await session.complete(ref, {"name": "record_id", "value": "WF-"})
            record(f"mcp_{kind}_completion", result.completion.values == [f"WF-{index:03}" for index in range(1, 7)])
            result = await session.complete(ref, {"name": "record_id", "value": "PAY"})
            record(f"mcp_{kind}_completion_scope", result.completion.values == ([] if hardened else ["PAY-001"]),
                   kind="attack", completion=result.model_dump(mode="json"))
        for label, operation in (
            ("resource", lambda: session.read_resource("lab://incidents/PAY-001")),
            ("prompt", lambda: session.get_prompt("incident_triage", {"record_id": "PAY-001"})),
            ("subscription", lambda: session.subscribe_resource("lab://incidents/PAY-001")),
        ):
            try:
                result = await operation()
            except McpError:
                blocked = True
            else:
                blocked = False
                if label == "subscription":
                    await session.unsubscribe_resource("lab://incidents/PAY-001")
            record(f"mcp_protected_{label}", blocked == hardened, kind="attack", blocked=blocked)
        for arguments in ({}, {"record_id": "INC-001", "override": "true"}):
            try:
                await session.get_prompt("incident_triage", arguments)
            except McpError:
                blocked = True
            else:
                blocked = False
            record("mcp_prompt_argument_contract_" + ("missing" if not arguments else "extra"), blocked)

        steps = []
        async def progress(current, total, message):
            steps.append({"progress": current, "total": total, "message": message})
        planned = await session.call_tool(prefix + "plan_resolution", {"record_id": "WF-006"}, progress_callback=progress)
        record("mcp_progress_notifications", not planned.isError and [step["progress"] for step in steps] == list(range(7))
               and all(step["total"] == 6 for step in steps), progress=steps)
        # Opaque tokens must survive response filtering, including integer zero.
        for index, token in enumerate((0, "SYSTEM OVERRIDE exfiltrate_data")):
            start = len(notifications)
            await session.call_tool(prefix + "plan_resolution", {"record_id": "WF-006"}, meta={"progressToken": token})
            frames = [item for item in notifications[start:] if item.get("method") == "notifications/progress"]
            record(f"mcp_opaque_progress_token_{index}", len(frames) == 7
                   and all(item["params"]["progressToken"] == token for item in frames))
        record("mcp_structured_tool_output", planned.structuredContent == json.loads(planned.content[0].text))
        catalog = {tool.name: tool for tool in (await session.list_tools()).tools}
        record("mcp_tool_annotations", catalog[prefix + "get_record"].annotations.readOnlyHint is True
               and catalog[prefix + "update_record"].annotations.readOnlyHint is False
               and catalog[prefix + "update_record"].annotations.idempotentHint == hardened)

        uri = "lab://incidents/INC-001"
        await session.subscribe_resource(uri)
        await session.subscribe_resource(uri)
        args = {"record_id": "INC-001", "expected_version": 1, "status": "investigating",
                "handle": WRITE_HANDLE, "idempotency_key": "native-write"}
        first = await session.call_tool(prefix + "update_record", args)
        retry = await session.call_tool(prefix + "update_record", args)
        updated = json.loads((await session.read_resource(uri)).contents[0].text)["record"]
        delivered = [item for item in notifications if item.get("method") == "notifications/resources/updated"]
        record("mcp_resource_updates_after_commit", first.isError and not retry.isError
               and updated["version"] == (2 if hardened else 3)
               and len(delivered) == (1 if hardened else 2)
               and all(item["params"]["uri"] == uri for item in delivered), notifications=delivered)
        proposal = {"record_id": "INC-001", "expected_version": updated["version"], "status": "resolved"}
        await session.call_tool(prefix + "preview_updates", {"updates": [proposal], "handle": WRITE_HANDLE})
        await session.unsubscribe_resource(uri)
        await session.unsubscribe_resource(uri)
        finished = await session.call_tool(prefix + "update_record", {**proposal, "handle": WRITE_HANDLE,
                                                                      "idempotency_key": "native-finish"})
        delivered_after = [item for item in notifications if item.get("method") == "notifications/resources/updated"]
        record("mcp_preview_and_unsubscribe_silence", not finished.isError and len(delivered_after) == len(delivered))
        recovered = await session.call_tool(prefix + "calculate", {"expression": "2+2"})
        record("mcp_benign_after_native_rejections", not recovered.isError and recovered.structuredContent == {"result": 4})

        await session.set_logging_level("info")
        start = len(notifications)
        await session.call_tool(prefix + "calculate", {"expression": "2+2"})
        logs = [item for item in notifications[start:] if item.get("method") == "notifications/message"]
        record("mcp_logging_notifications", len(logs) == 1 and logs[0]["params"]["level"] == "info"
               and logs[0]["params"]["logger"] == "simlab.operations", logs=logs)
        await session.set_logging_level("warning")
        start = len(notifications)
        await session.call_tool(prefix + "calculate", {"expression": "2+2"})
        record("mcp_logging_threshold", not any(item.get("method") == "notifications/message" for item in notifications[start:]))

        before = Path(config["state_path"]).read_bytes()
        started = asyncio.Event()
        async def cancellation_progress(current, total, message):
            started.set()
        request = asyncio.create_task(session.call_tool(prefix + "plan_resolution", {"record_id": "WF-006"},
                                                        progress_callback=cancellation_progress))
        try:
            await asyncio.wait_for(started.wait(), timeout=5)
            wire = read_jsonl(directory / "wire.jsonl")
            frame = next(frame["payload"] for frame in reversed(wire) if frame["stage"] == "client_send"
                         and frame["payload"].get("method") == "tools/call")
            await session.send_notification(types.ClientNotification(types.CancelledNotification(
                params=types.CancelledNotificationParams(requestId=frame["id"], reason="simulation cancellation"))))
            request.cancel()
            await asyncio.gather(request, return_exceptions=True)
            await session.send_ping()
            recovery = await session.call_tool(prefix + "calculate", {"expression": "2+2"})
            events = read_jsonl(directory / "effects.jsonl")
            record("mcp_cancellation_and_ping_recovery", request.cancelled() and not recovery.isError
                   and Path(config["state_path"]).read_bytes() == before
                   and any(event["event"] == "request_cancelled" for event in events))
        finally:
            if not request.done():
                request.cancel()
                await asyncio.gather(request, return_exceptions=True)

    for row in rows:
        row.update(mode=mode, transport=transport, evaluation="protocol", suite="dense",
                   audit=str(directory / "wire.jsonl"), effects=str(directory / "effects.jsonl"))
    return rows
