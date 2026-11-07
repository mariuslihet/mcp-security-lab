import asyncio
import sys
from datetime import timedelta

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from simlab.evaluation import protocol_matrix
from simlab.fixtures import CANARY, HANDLE, create_fixture, read_jsonl
from simlab.client import connect


@pytest.mark.parametrize("transport", ["stdio", "sse"])
@pytest.mark.parametrize("mode", ["vulnerable", "hardened"])
def test_real_transport_matrix(tmp_path, transport, mode):
    rows = asyncio.run(protocol_matrix(tmp_path / "case", mode, transport))
    failures = [r for r in rows if not r["passed"]]
    assert not failures, failures
    frames = read_jsonl(tmp_path / "case" / "wire.jsonl")
    methods = {r["payload"].get("method") for r in frames if r["stage"] == "server_send"}
    assert {"initialize", "notifications/initialized", "tools/list", "tools/call"} <= methods
    assert any("result" in r["payload"] for r in frames if r["stage"] == "server_receive")


def test_hardened_server_without_proxy(tmp_path):
    """The server still enforces controls when the intermediary is bypassed."""
    config, _ = create_fixture(tmp_path / "direct")

    async def exercise():
        parameters = StdioServerParameters(command=sys.executable,
            args=["-m", "hardened_mcp", "--config", str(config)])
        async with stdio_client(parameters) as (read, write):
            async with ClientSession(read, write, read_timeout_seconds=timedelta(seconds=15)) as session:
                await session.initialize()
                for tool, arguments in [
                    ("sim_read_file", {"path": "../outside/secret.txt"}),
                    ("sim_exfiltrate_data", {"data": CANARY}),
                    ("execute_command", {"command": "2+2"}),
                    ("sim_forward_state", {"handle": HANDLE, "audience": "capture", "action": "export"}),
                    ("sim_read_file", {"path": "public.txt", "override": True}),
                ]:
                    assert (await session.call_tool(tool, arguments)).isError
                assert not (await session.call_tool("sim_read_file", {"path": "public.txt"})).isError
    asyncio.run(exercise())
    events = read_jsonl(tmp_path / "direct" / "effects.jsonl")
    assert sum(e["event"] == "blocked" for e in events) == 5
    assert not any(e.get("outside") or e["event"] == "sink_capture" for e in events)


@pytest.mark.parametrize("mode", ["vulnerable", "hardened"])
def test_attacker_shadow_payload_reaches_only_vulnerable_catalog(tmp_path, mode):
    directory = tmp_path / mode
    config, _ = create_fixture(directory, metadata_poison=True, poison_tool="execute_command")
    marker = "ATTACKER_SHADOW_CATALOG_MARKER"
    (directory / "workspace" / "poison.md").write_text(marker, encoding="utf-8")

    async def exercise():
        async with connect(config, mode, directory / "wire.jsonl") as session:
            catalog = await session.list_tools()
            poisoned = [t for t in catalog.tools if marker in (t.description or "")]
            assert [t.name for t in poisoned] == (["execute_command"] if mode == "vulnerable" else [])
    asyncio.run(exercise())


@pytest.mark.parametrize("transport", ["stdio", "sse"])
def test_arithmetic_rejections_preserve_live_session(tmp_path, transport):
    directory = tmp_path / "arithmetic"
    config, _ = create_fixture(directory)

    async def exercise():
        async with connect(config, "hardened", directory / "wire.jsonl", transport) as session:
            for expression in ("1/0", "2+"):
                assert (await session.call_tool("sim_calculate", {"expression": expression})).isError
            result = await session.call_tool("sim_calculate", {"expression": "2+2"})
            assert not result.isError and '4' in result.content[0].text
    asyncio.run(exercise())
    events = read_jsonl(directory / "effects.jsonl")
    assert [e["arguments"] for e in events if e["event"] == "received"] == [{"expression": "2+2"}]
