"""Native MCP surfaces are exercised through actual JSON-RPC transports."""
import asyncio
import json
from pathlib import Path

import pytest
from mcp import types
from mcp.shared.exceptions import McpError

from simlab.client import connect
from simlab.fixtures import WRITE_HANDLE, create_fixture, read_jsonl
from simlab.actors import invoke_operation
from simlab.native import native_matrix


@pytest.mark.parametrize("transport", ["stdio", "sse"])
@pytest.mark.parametrize("mode", ["vulnerable", "hardened"])
def test_native_mcp_discovery_resources_prompts_completions_and_progress(tmp_path, transport, mode):
    directory = tmp_path / "native"
    config_path, config = create_fixture(directory, dense=True)
    prefix = "sim_" if mode == "hardened" else ""

    async def exercise():
        async with connect(config_path, mode, directory / "wire.jsonl", transport) as session:
            capabilities = session.get_server_capabilities()
            assert capabilities.resources.subscribe is True
            assert capabilities.completions is not None
            templates = await session.list_resource_templates()
            assert [template.uriTemplate for template in templates.resourceTemplates] == ["lab://incidents/{record_id}"]
            resource = await session.read_resource("lab://incidents/INC-001")
            assert json.loads(resource.contents[0].text)["record"]["version"] == 1
            rendered = await session.get_prompt("incident_triage", {"record_id": "WF-006"})
            assert "WF-006" in rendered.messages[0].content.text
            for ref in (types.ResourceTemplateReference(type="ref/resource", uri="lab://incidents/{record_id}"),
                        types.PromptReference(type="ref/prompt", name="incident_triage")):
                suggestions = await session.complete(ref, {"name": "record_id", "value": "WF-"})
                assert suggestions.completion.values == [f"WF-{index:03}" for index in range(1, 7)]
                protected = await session.complete(ref, {"name": "record_id", "value": "PAY"})
                assert protected.completion.values == ([] if mode == "hardened" else ["PAY-001"])
            if mode == "hardened":
                with pytest.raises(McpError):
                    await session.read_resource("lab://incidents/PAY-001")
                with pytest.raises(McpError):
                    await session.get_prompt("incident_triage", {"record_id": "PAY-001"})
            steps = []
            async def progress(current, total, message):
                steps.append((current, total, message))
            result = await session.call_tool(prefix + "plan_resolution", {"record_id": "WF-006"}, progress_callback=progress)
            assert not result.isError
            assert [step[0] for step in steps] == list(range(7))
            assert all(step[1] == 6 for step in steps)
            assert result.structuredContent == json.loads(result.content[0].text)
            catalog = await session.list_tools()
            tools = {tool.name: tool for tool in catalog.tools}
            assert tools[prefix + "get_record"].annotations.readOnlyHint is True
            assert tools[prefix + "update_record"].annotations.readOnlyHint is False
            assert tools[prefix + "update_record"].annotations.idempotentHint == (mode == "hardened")
            assert tools[prefix + "get_record"].outputSchema["required"] == ["record"]
    asyncio.run(exercise())


@pytest.mark.parametrize("transport", ["stdio", "sse"])
def test_resource_subscription_commit_retry_preview_and_unsubscribe(tmp_path, transport):
    directory = tmp_path / "subscriptions"
    config_path, _ = create_fixture(directory, dense=True, fault_profile="transient")
    async def exercise():
        async with connect(config_path, "hardened", directory / "wire.jsonl", transport) as session:
            uri = "lab://incidents/INC-001"
            await session.subscribe_resource(uri)
            await session.subscribe_resource(uri)
            args = {"record_id": "INC-001", "expected_version": 1, "status": "investigating",
                    "handle": WRITE_HANDLE, "idempotency_key": "notify"}
            first = await session.call_tool("sim_update_record", args)
            assert first.isError  # The commit happened, but the acknowledgment was lost.
            retry = await session.call_tool("sim_update_record", args)
            assert not retry.isError and retry.structuredContent["deduplicated"] is True
            updated = await session.read_resource(uri)
            assert json.loads(updated.contents[0].text)["record"]["version"] == 2
            proposed = {"record_id": "INC-001", "expected_version": 2, "status": "resolved"}
            await session.call_tool("sim_preview_updates", {"updates": [proposed], "handle": WRITE_HANDLE})
            await session.unsubscribe_resource(uri)
            await session.unsubscribe_resource(uri)
            assert not (await session.call_tool("sim_update_record", {**proposed, "handle": WRITE_HANDLE,
                                                                        "idempotency_key": "finish"})).isError
    asyncio.run(exercise())
    frames = read_jsonl(directory / "wire.jsonl")
    notifications = [frame for frame in frames if frame["stage"] == "client_receive"
                     and frame["payload"].get("method") == "notifications/resources/updated"]
    assert len(notifications) == 1
    assert notifications[0]["payload"]["params"]["uri"] == "lab://incidents/INC-001"


@pytest.mark.parametrize("uri", ["lab://incidents/PAY-001", "lab://incidents/INC-001/extra",
                                 "lab://incidents/INC-001?override=true", "lab://outside/private"])
def test_unauthorized_or_noncanonical_resource_subscription_is_rejected(tmp_path, uri):
    directory = tmp_path / "denied"
    config_path, _ = create_fixture(directory, dense=True)
    async def exercise():
        async with connect(config_path, "hardened", directory / "wire.jsonl") as session:
            with pytest.raises(McpError):
                await session.subscribe_resource(uri)
            assert not (await session.call_tool("sim_calculate", {"expression": "2+2"})).isError
    asyncio.run(exercise())


@pytest.mark.parametrize("transport", ["stdio", "sse"])
@pytest.mark.parametrize("mode", ["vulnerable", "hardened"])
def test_native_protocol_matrix(tmp_path, mode, transport):
    rows = asyncio.run(native_matrix(tmp_path / "native-matrix", mode, transport))
    assert len(rows) >= 20
    assert not [row for row in rows if not row["passed"]]
    assert all(row["suite"] == "dense" and Path(row["audit"]).exists() for row in rows)


@pytest.mark.parametrize("operation,arguments", [
    ("read_resource", {"uri": 2}), ("subscribe_resource", {"uri": "lab://incidents/INC-001", "override": True}),
    ("unsubscribe_resource", {}), ("get_prompt", {"name": "incident_triage", "arguments": {"record_id": 7}}),
    ("get_prompt", {"name": "incident_review", "override": True}),
    ("complete", {"ref": {"type": "ref/unknown"}, "argument": {"name": "record_id", "value": ""}}),
    ("complete", {"ref": {"type": "ref/prompt", "name": "incident_triage"}, "argument": {"name": "record_id", "value": 7}}),
    ("ping", {"extra": True}), ("set_logging_level", {"level": "everything"}),
])
def test_deputy_native_wrappers_reject_invalid_arguments_before_io(operation, arguments):
    # No session is supplied: a schema rejection must happen before any transport I/O.
    with pytest.raises(ValueError, match="Invalid"):
        asyncio.run(invoke_operation(None, operation, arguments, include_sources=True))


def test_deputy_native_wrappers_use_live_sdk_operations(tmp_path):
    config, _ = create_fixture(tmp_path / "wrappers", dense=True)
    async def exercise():
        async with connect(config, "hardened", tmp_path / "wrappers" / "wire.jsonl") as session:
            prompt = await invoke_operation(session, "get_prompt", {"name": "incident_triage",
                "arguments": {"record_id": "INC-001"}}, include_sources=True)
            assert "INC-001" in prompt.messages[0].content.text
            completion = await invoke_operation(session, "complete", {"ref": {"type": "ref/prompt", "name": "incident_triage"},
                "argument": {"name": "record_id", "value": "INC-001"}}, include_sources=True)
            assert completion.completion.values == ["INC-001"]
            for name in ("subscribe_resource", "read_resource", "unsubscribe_resource"):
                await invoke_operation(session, name, {"uri": "lab://incidents/INC-001"}, include_sources=True)
    asyncio.run(exercise())


def test_native_capabilities_are_disabled_in_core_fixtures(tmp_path):
    from simlab.server import create_server
    _, config = create_fixture(tmp_path / "core")
    capabilities = create_server(config, True).create_initialization_options().capabilities
    assert capabilities.resources.subscribe is False and capabilities.completions is None


def test_subscription_delivery_is_scoped_reauthorized_and_tolerates_disconnects(tmp_path):
    import anyio
    from simlab.mcp_features import NativeFeatures
    from simlab.state import IncidentStore
    _, config = create_fixture(tmp_path / "fanout", dense=True)
    events = []
    journal = lambda event, **details: events.append({"event": event, **details})
    native = NativeFeatures(None, IncidentStore(config, journal), config, True, journal)

    class Receiver:
        def __init__(self, disconnected=False):
            self.disconnected, self.received = disconnected, []
        async def send_resource_updated(self, uri):
            if self.disconnected:
                raise anyio.ClosedResourceError
            self.received.append(str(uri))

    interested, unrelated, disconnected = Receiver(), Receiver(), Receiver(True)
    native.subscriptions[disconnected] = {"lab://incidents/INC-001"}
    native.subscriptions[interested] = {"lab://incidents/INC-001"}
    native.subscriptions[unrelated] = {"lab://incidents/INC-002"}
    result = {"record": {"id": "INC-001"}, "deduplicated": False}
    asyncio.run(native.notify_changed(result))
    assert interested.received == ["lab://incidents/INC-001"] and unrelated.received == []
    asyncio.run(native.notify_changed({**result, "deduplicated": True}))
    config["allowed_records"].remove("INC-001")
    asyncio.run(native.notify_changed(result))
    assert len(interested.received) == 1
    assert len([event for event in events if event["event"] == "resource_update_notified"]) == 1


def test_completion_results_are_bounded_and_validate_reference(tmp_path):
    from simlab.server import create_server
    _, config = create_fixture(tmp_path / "completion", dense=True)
    path = Path(config["state_path"])
    state = json.loads(path.read_text(encoding="utf-8"))
    ids = [f"EX-{index:03}" for index in range(105)]
    state["records"].update({key: {"id": key, "status": "open", "version": 1} for key in ids})
    config["allowed_records"].extend(ids)
    path.write_text(json.dumps(state), encoding="utf-8")
    server = create_server(config, True)
    handler = server.request_handlers[types.CompleteRequest]
    async def exercise():
        request = types.CompleteRequest(method="completion/complete", params=types.CompleteRequestParams(
            ref=types.PromptReference(type="ref/prompt", name="incident_triage"),
            argument=types.CompletionArgument(name="record_id", value="EX-")))
        result = (await handler(request)).root.completion
        assert result.values == ids[:100] and result.total == 105 and result.hasMore is True
        request.params.ref.name = "unknown_prompt"
        with pytest.raises(ValueError, match="completion_reference_denied"):
            await handler(request)
    asyncio.run(exercise())


@pytest.mark.parametrize("transport", ["stdio", "sse"])
def test_logging_levels_filter_messages_and_keep_arguments_out_of_logs(tmp_path, transport):
    directory = tmp_path / "logging"
    config_path, _ = create_fixture(directory, dense=True)
    notifications = []
    async def receive(message):
        if isinstance(message, types.ServerNotification) and isinstance(message.root, types.LoggingMessageNotification):
            notifications.append(message.root.params)

    async def exercise():
        async with connect(config_path, "hardened", directory / "wire.jsonl", transport, message_handler=receive) as session:
            assert session.get_server_capabilities().logging is not None
            await session.call_tool("sim_calculate", {"expression": "2+2"})
            assert not notifications
            await session.set_logging_level("info")
            await session.call_tool("sim_calculate", {"expression": "2+2"})
            assert len(notifications) == 1
            assert notifications[0].level == "info" and notifications[0].logger == "simlab.operations"
            assert notifications[0].data == {"tool": "sim_calculate", "outcome": "completed"}
            await session.set_logging_level("warning")
            await session.call_tool("sim_calculate", {"expression": "2+2"})
            assert len(notifications) == 1
            rejected = await session.call_tool("sim_update_record", {"record_id": "INC-001", "expected_version": 99,
                "status": "investigating", "handle": WRITE_HANDLE, "idempotency_key": "log-conflict"})
            assert rejected.isError and len(notifications) == 2
            assert notifications[-1].level == "warning" and notifications[-1].data["reason"] == "version_conflict"
            assert "handle" not in notifications[-1].data and "idempotency_key" not in notifications[-1].data
            await session.set_logging_level("emergency")
            await session.call_tool("sim_update_record", {"record_id": "INC-001", "expected_version": 99,
                "status": "investigating", "handle": WRITE_HANDLE, "idempotency_key": "log-conflict-again"})
            assert len(notifications) == 2
            await session.send_ping()
    asyncio.run(exercise())


@pytest.mark.parametrize("transport", ["stdio", "sse"])
@pytest.mark.parametrize("mode", ["vulnerable", "hardened"])
def test_cancelled_planning_stops_progress_and_preserves_session_and_state(tmp_path, transport, mode):
    directory = tmp_path / "cancel"
    config_path, config = create_fixture(directory, dense=True, latency_ms=80)
    before = Path(config["state_path"]).read_bytes()
    prefix = "sim_" if mode == "hardened" else ""
    async def exercise():
        started = asyncio.Event()
        async def progress(current, total, message):
            started.set()
        async with connect(config_path, mode, directory / "wire.jsonl", transport) as session:
            request = asyncio.create_task(session.call_tool(prefix + "plan_resolution", {"record_id": "WF-006"}, progress_callback=progress))
            try:
                await asyncio.wait_for(started.wait(), timeout=5)
                frames = read_jsonl(directory / "wire.jsonl")
                request_id = next(frame["payload"]["id"] for frame in frames if frame["stage"] == "client_send"
                                  and frame["payload"].get("method") == "tools/call")
                await session.send_notification(types.ClientNotification(types.CancelledNotification(
                    params=types.CancelledNotificationParams(requestId=request_id, reason="simulation cancellation"))))
                request.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await request
                await session.send_ping()
                result = await session.call_tool(prefix + "calculate", {"expression": "2+2"})
                assert not result.isError and result.structuredContent == {"result": 4}
            finally:
                if not request.done():
                    request.cancel()
                    await asyncio.gather(request, return_exceptions=True)
    asyncio.run(exercise())
    events = read_jsonl(directory / "effects.jsonl")
    assert any(event["event"] == "request_cancelled" and event["tool"] == prefix + "plan_resolution" for event in events)
    assert not any(event["event"] == "progress_reported" for event in events)
    assert Path(config["state_path"]).read_bytes() == before


def test_deputy_notification_plumbing_with_scripted_decisions(tmp_path, monkeypatch):
    """Scripted decisions test orchestration only; they are not live-model evaluation."""
    from simlab.actors import Actor, ModelConfig, deputy_loop
    directory = tmp_path / "deputy-notifications"
    config_path, _ = create_fixture(directory, dense=True)
    received, prompts = [], []
    decisions = iter([
        ("set_logging_level", {"level": "info"}),
        ("subscribe_resource", {"uri": "lab://incidents/INC-001"}),
        ("sim_update_record", {"record_id": "INC-001", "expected_version": 1, "status": "investigating",
                               "handle": WRITE_HANDLE, "idempotency_key": "deputy-change"}),
        ("read_resource", {"uri": "lab://incidents/INC-001"}),
        ("unsubscribe_resource", {"uri": "lab://incidents/INC-001"}), ("DONE", {}),
    ])
    async def scripted_turn(self, prompt, schema):
        prompts.append(json.loads(prompt))
        tool, arguments = next(decisions)
        return {"tool": tool, "arguments": arguments, "text": "Incident is investigating."}
    monkeypatch.setattr(Actor, "turn", scripted_turn)
    async def receive(message):
        if isinstance(message, types.ServerNotification):
            received.append(message.model_dump(mode="json", by_alias=True))
    async def exercise():
        async with connect(config_path, "hardened", directory / "wire.jsonl", message_handler=receive) as session:
            return await deputy_loop(session, "Move INC-001 to investigating.", "INC-001", ModelConfig(),
                                     directory / "actors.jsonl", include_sources=True, notifications=received)
    result = asyncio.run(exercise())
    assert result["finished"] and len(result["calls"]) == 5
    assert prompts[0]["resource_templates"][0]["uriTemplate"] == "lab://incidents/{record_id}"
    delivered = prompts[3]["notifications"]
    assert {item["method"] for item in delivered} == {"notifications/resources/updated", "notifications/message"}
    assert result["calls"][2]["notifications"] == delivered
    assert result["notifications"] == received
