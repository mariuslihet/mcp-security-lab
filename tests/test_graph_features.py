import asyncio
import json
from pathlib import Path

import pytest
from mcp import types

from simlab.client import connect
from simlab.dependency_graph import generate_graph, validate_graph
from simlab.fixtures import WRITE_HANDLE, create_fixture


@pytest.mark.parametrize("nodes,width", [(8, 2), (32, 4), (64, 8), (128, 4)])
def test_generated_graphs_are_deterministic_layered_and_reconvergent(nodes, width):
    graph = generate_graph(11, nodes, width)
    assert graph == generate_graph(11, nodes, width)
    layers = validate_graph(graph)
    assert len(graph) == nodes and len(layers[0]) == width
    assert max(map(len, layers)) <= width
    assert len(layers) == (nodes + width - 1) // width
    assert all(len(parents) >= width for parents in list(graph.values())[width:])


@pytest.mark.parametrize("problem", ["cycle", "missing", "self", "duplicate", "identifier"])
def test_invalid_graphs_are_rejected_before_fixture_creation(tmp_path, problem):
    graph = generate_graph(7, 8, 2)
    if problem == "cycle":
        graph["GR-000"] = ["GR-007"]
    elif problem == "missing":
        graph["GR-007"] = ["PAY-001"]
    elif problem == "self":
        graph["GR-007"] = ["GR-007"]
    elif problem == "duplicate":
        graph["GR-007"] = ["GR-000", "GR-000"]
    else:
        graph["../../outside"] = []
    with pytest.raises(ValueError):
        create_fixture(tmp_path / "invalid", dense=True, dependency_graph=graph)
    assert not (tmp_path / "invalid").exists()


@pytest.mark.parametrize("transport", ["stdio", "sse"])
def test_dependency_analysis_and_resource_links_over_real_mcp(tmp_path, transport):
    directory = tmp_path / "graph"
    graph = generate_graph(11, 32, 4)
    config_path, _ = create_fixture(directory, dense=True, dependency_graph=graph)
    async def exercise():
        async with connect(config_path, "hardened", directory / "wire.jsonl", transport) as session:
            result = await session.call_tool("sim_analyze_dependencies", {"record_id": "GR-031"})
            assert not result.isError
            summary = result.structuredContent
            assert summary["node_count"] >= 29 and summary["edge_count"] > 60
            assert len(summary["layers"]) == 8 and len(summary["critical_path"]) == 8
            assert summary["critical_path"][-1] == "GR-031"
            bundle = await session.call_tool("sim_incident_bundle", {"record_id": "GR-031"})
            assert not bundle.isError
            links = [block for block in bundle.content if isinstance(block, types.ResourceLink)]
            assert len(links) == summary["node_count"]
            assert {str(link.uri) for link in links} == set(bundle.structuredContent["resources"])
            resource = await session.read_resource(str(links[-1].uri))
            assert json.loads(resource.contents[0].text)["record"]["id"] == "GR-031"
    asyncio.run(exercise())


@pytest.mark.parametrize("transport", ["stdio", "sse"])
def test_catalog_list_change_notifications_and_disabled_tool_recovery(tmp_path, transport):
    from simlab.fixtures import CATALOG_HANDLE
    directory = tmp_path / "catalog"
    config_path, _ = create_fixture(directory, dense=True)
    notifications = []
    async def receive(message):
        if isinstance(message, types.ServerNotification):
            notifications.append(message.root.method)
    async def exercise():
        async with connect(config_path, "hardened", directory / "wire.jsonl", transport, message_handler=receive) as session:
            caps = session.get_server_capabilities()
            assert caps.tools.listChanged and caps.prompts.listChanged and caps.resources.listChanged
            initial = {tool.name for tool in (await session.list_tools()).tools}
            await session.list_resources()
            await session.list_prompts()
            args = {"profile": "compact", "handle": CATALOG_HANDLE}
            changed = await session.call_tool("sim_set_catalog_profile", args)
            assert changed.structuredContent == {"profile": "compact", "changed": True}
            assert set(notifications) >= {"notifications/tools/list_changed", "notifications/resources/list_changed", "notifications/prompts/list_changed"}
            count = len(notifications)
            assert not (await session.call_tool("sim_set_catalog_profile", args)).structuredContent["changed"]
            assert len(notifications) == count
            compact = {tool.name for tool in (await session.list_tools()).tools}
            assert "sim_guided_update_record" not in compact and len(compact) < len(initial)
            assert (await session.call_tool("sim_update_record", {"record_id": "INC-001", "expected_version": 1,
                "status": "investigating", "idempotency_key": "hidden", "handle": WRITE_HANDLE})).isError
            restored = await session.call_tool("sim_set_catalog_profile", {"profile": "standard", "handle": CATALOG_HANDLE})
            assert not restored.isError and {tool.name for tool in (await session.list_tools()).tools} == initial
            assert not (await session.call_tool("sim_calculate", {"expression": "2+2"})).isError
    asyncio.run(exercise())


@pytest.mark.parametrize("transport", ["stdio", "sse"])
def test_graph_approval_is_invalidated_by_a_real_concurrent_writer(tmp_path, transport):
    from simlab.client_profiles import ControlledClient
    directory = tmp_path / "approval-race"
    config_path, config = create_fixture(directory, dense=True, dependency_graph=generate_graph(7, 16, 4))
    client = ControlledClient(config, directory / "client.jsonl")
    competing = []
    original = client.elicit
    async def approve_after_other_writer(context, params):
        competing.append(asyncio.create_task(context.session.call_tool("sim_update_record", {
            "record_id": "GR-000", "expected_version": 2, "status": "resolved",
            "handle": WRITE_HANDLE, "idempotency_key": "other-writer"})))
        # The SDK receive loop is inside this callback. Observe the server-side commit,
        # then return approval so the receive loop can deliver the competing response.
        for _ in range(200):
            state = json.loads(Path(config["state_path"]).read_text(encoding="utf-8"))
            if state["records"]["GR-000"]["version"] == 3:
                break
            await asyncio.sleep(0.01)
        else:
            raise AssertionError("competing server mutation did not commit")
        return await original(context, params)
    callbacks = client.callbacks()
    callbacks["elicitation_callback"] = approve_after_other_writer
    async def exercise():
        async with connect(config_path, "hardened", directory / "wire.jsonl", transport, **callbacks) as session:
            start = await session.call_tool("sim_update_record", {"record_id": "GR-000", "expected_version": 1,
                "status": "investigating", "handle": WRITE_HANDLE, "idempotency_key": "start"})
            assert not start.isError
            result = await session.call_tool("sim_guided_update_record", {"record_id": "GR-000", "expected_version": 2,
                "status": "resolved", "handle": WRITE_HANDLE, "idempotency_key": "stale-approved"})
            assert result.isError and "version_conflict" in result.content[0].text
            assert not (await asyncio.wait_for(competing[0], 5)).isError
            state = json.loads(Path(config["state_path"]).read_text(encoding="utf-8"))
            assert state["records"]["GR-000"]["version"] == 3
            assert len(state["receipts"]) == 2  # Start and competing write; no guided receipt.
            await session.send_ping()
    asyncio.run(exercise())


@pytest.mark.parametrize("handle", [WRITE_HANDLE, "other-session-handle", "missing"])
def test_catalog_control_requires_its_own_scope(tmp_path, handle):
    from simlab.controls import Denied, Firewall
    _, config = create_fixture(tmp_path / "catalog-auth", dense=True)
    with pytest.raises(Denied, match="catalog_scope_denied"):
        Firewall(config).check("sim_set_catalog_profile", {"profile": "compact", "handle": handle})


@pytest.mark.parametrize("transport", ["stdio", "sse"])
def test_concurrent_catalog_changes_keep_results_and_notifications_consistent(tmp_path, transport):
    from simlab.fixtures import CATALOG_HANDLE
    from simlab.actors import invoke_operation
    directory = tmp_path / "catalog-race"
    config_path, _ = create_fixture(directory, dense=True)
    notifications = []
    async def receive(message):
        if isinstance(message, types.ServerNotification):
            notifications.append(message.root.method)
    async def exercise():
        async with connect(config_path, "hardened", directory / "wire.jsonl", transport, message_handler=receive) as session:
            await session.list_tools()
            profiles = ["compact", "standard"] * 4
            results = await asyncio.gather(*(session.call_tool("sim_set_catalog_profile", {"profile": profile,
                                             "handle": CATALOG_HANDLE}) for profile in profiles))
            assert all(not result.isError and result.structuredContent["profile"] == profile for profile, result in zip(profiles, results))
            changed = sum(result.structuredContent["changed"] for result in results)
            for method in ("notifications/tools/list_changed", "notifications/resources/list_changed", "notifications/prompts/list_changed"):
                assert notifications.count(method) == changed
            await session.call_tool("sim_set_catalog_profile", {"profile": "standard", "handle": CATALOG_HANDLE})
            for name in ("list_tools", "list_resources", "list_prompts", "list_resource_templates"):
                assert await invoke_operation(session, name, {}, include_sources=True) is not None
    asyncio.run(exercise())
