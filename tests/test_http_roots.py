import asyncio
import json
from pathlib import Path

import pytest
import httpx
from mcp import ClientSession, types
from mcp.client.streamable_http import streamable_http_client

from simlab.client import connect
from simlab.client_profiles import ControlledClient
from simlab.fixtures import WRITE_HANDLE, create_fixture, read_jsonl


@pytest.mark.parametrize("mode", ["vulnerable", "hardened"])
def test_streamable_http_handles_tools_callbacks_resources_and_notifications(tmp_path, mode):
    directory = tmp_path / "http"
    config_path, config = create_fixture(directory, dense=True)
    client = ControlledClient(config, directory / "client.jsonl")
    prefix = "sim_" if mode == "hardened" else ""
    received = []
    async def notifications(message):
        if isinstance(message, types.ServerNotification):
            received.append(message.root.method)
    async def exercise():
        async with connect(config_path, mode, directory / "wire.jsonl", "streamable-http",
                           message_handler=notifications, **client.callbacks()) as session:
            await session.subscribe_resource("lab://incidents/INC-001")
            result = await session.call_tool(prefix + "guided_update_record", {"record_id": "INC-001", "expected_version": 1,
                "status": "investigating", "handle": WRITE_HANDLE, "idempotency_key": "http-guided"})
            assert not result.isError and result.structuredContent["record"]["version"] == 2
            assert "notifications/resources/updated" in received
            resource = await session.read_resource("lab://incidents/INC-001")
            assert json.loads(resource.contents[0].text)["record"]["status"] == "investigating"
            await session.unsubscribe_resource("lab://incidents/INC-001")
            await session.send_ping()
    asyncio.run(exercise())
    frames = read_jsonl(directory / "wire.jsonl")
    assert next(frame["payload"]["kind"] for frame in frames if frame["stage"] == "transport") == "streamable-http"
    assert any(frame["payload"].get("method") == "sampling/createMessage" for frame in frames if frame["stage"] == "client_receive")


def test_http_sessions_isolate_root_notifications_and_survive_peer_disconnect(tmp_path):
    directory = tmp_path / "sessions"
    config_path, config = create_fixture(directory, dense=True)
    first = ControlledClient(config, directory / "first.jsonl")
    second = ControlledClient(config, directory / "second.jsonl")
    audit = directory / "wire.jsonl"
    async def exercise():
        async with connect(config_path, "hardened", audit, "streamable-http", **first.callbacks()) as a:
            endpoint = next(row["payload"]["endpoint"] for row in read_jsonl(audit) if row["stage"] == "transport")
            async with httpx.AsyncClient(trust_env=False) as http:
                headers = {"Accept": "application/json, text/event-stream", "Mcp-Session-Id": "unknown-session"}
                response = await http.post(endpoint, headers=headers, json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
                assert response.status_code == 404
                async with streamable_http_client(endpoint, http_client=http) as (reader, writer, session_id):
                    async with ClientSession(reader, writer, **second.callbacks()) as b:
                        await b.initialize()
                        identifier = session_id()
                        assert identifier
                        response = await http.post(endpoint, headers={**headers, "Mcp-Session-Id": identifier,
                            "Origin": "https://outside.invalid"}, json={"jsonrpc": "2.0", "id": 900, "method": "ping"})
                        assert response.status_code == 403
                        await a.call_tool("sim_inspect_client_roots", {})
                        await b.call_tool("sim_inspect_client_roots", {})
                        second.root_mode = "empty"
                        await b.send_roots_list_changed()
                        await b.send_ping()
                        a_status = (await a.call_tool("sim_get_client_root_status", {})).structuredContent
                        b_status = (await b.call_tool("sim_get_client_root_status", {})).structuredContent
                        assert a_status == {"generation": 0, "dirty": False, "has_snapshot": True, "last_workspace_advertised": True}
                        assert b_status == {"generation": 1, "dirty": True, "has_snapshot": True, "last_workspace_advertised": True}
                        refreshed = await b.call_tool("sim_inspect_client_roots", {})
                        assert refreshed.structuredContent["workspace_advertised"] is False
                        assert refreshed.structuredContent["dirty"] is False
                response = await http.post(endpoint, headers={**headers, "Mcp-Session-Id": identifier}, json={"jsonrpc": "2.0", "id": 2, "method": "ping"})
                assert response.status_code == 404
                await a.send_ping()
                assert (await a.call_tool("sim_get_client_root_status", {})).structuredContent == a_status
    asyncio.run(exercise())


@pytest.mark.parametrize("transport", ["stdio", "sse", "streamable-http"])
@pytest.mark.parametrize("notify", [True, False])
def test_root_change_during_approval_prevents_hardened_commit(tmp_path, transport, notify):
    directory = tmp_path / "root-drift"
    config_path, config = create_fixture(directory, dense=True)
    client = ControlledClient(config, directory / "client.jsonl")
    original = client.elicit
    async def drift(context, params):
        client.root_mode = "outside"
        if notify:
            await context.session.send_roots_list_changed()
        return await original(context, params)
    callbacks = client.callbacks()
    callbacks["elicitation_callback"] = drift
    before = Path(config["state_path"]).read_bytes()
    async def exercise():
        async with connect(config_path, "hardened", directory / "wire.jsonl", transport, **callbacks) as session:
            result = await session.call_tool("sim_guided_update_record", {"record_id": "INC-001", "expected_version": 1,
                "status": "investigating", "handle": WRITE_HANDLE, "idempotency_key": "drift"})
            assert result.isError and ("roots_changed" in result.content[0].text or "workspace_root_not_advertised" in result.content[0].text)
            assert Path(config["state_path"]).read_bytes() == before
            client.root_mode = "workspace"
            await session.send_roots_list_changed()
            refreshed = await session.call_tool("sim_inspect_client_roots", {})
            assert not refreshed.isError and refreshed.structuredContent["workspace_advertised"]
            assert refreshed.structuredContent["generation"] >= 1 and refreshed.structuredContent["dirty"] is False
            await session.send_ping()
    asyncio.run(exercise())
