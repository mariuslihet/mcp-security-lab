"""Dense scenarios exercise real servers, wire interception, and persisted effects."""
import asyncio
import copy
import json
import sys
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.shared.exceptions import McpError

from simlab.client import connect
from simlab.controls import Denied, Firewall
from simlab.dense import dense_matrix, exposed
from simlab.fixtures import HANDLE, WRITE_HANDLE, create_fixture, read_jsonl
from simlab.grading import grade_task


def batch():
    return {"updates": [{"record_id": "INC-001", "expected_version": 1, "status": "investigating"},
                        {"record_id": "INC-002", "expected_version": 1, "status": "investigating"}],
            "idempotency_key": "batch-test", "handle": WRITE_HANDLE}


@pytest.mark.parametrize("transport", ["stdio", "sse"])
@pytest.mark.parametrize("mode", ["vulnerable", "hardened"])
def test_dense_real_transport_matrix(tmp_path, transport, mode):
    directory = tmp_path / "dense"
    rows = asyncio.run(dense_matrix(directory, mode, transport, distractors=24, latency_ms=1, parallel_calls=12))
    assert not [row for row in rows if not row["passed"]]
    assert {row["case"] for row in rows} >= {
        "dense_atomic_batch_lost_ack_retry", "dense_atomic_batch_rollback", "dense_overlapping_batch_race",
        "dense_batch_mixed_authority", "dense_state_and_wire_invariants", "dense_transient_read_recovery",
        "dense_dependency_bypass", "dense_reverse_order_dependency_commit", "dense_cursor_integrity_and_scope",
        "dense_stale_pagination_recovery", "dense_preview_without_mutation"}
    assert all(row["suite"] == "dense" and Path(row["state_file"]).exists() for row in rows)
    frames = read_jsonl(directory / "wire.jsonl")
    methods = {frame["payload"].get("method") for frame in frames if frame["stage"] == "server_send"}
    assert {"resources/list", "resources/read", "prompts/list", "prompts/get", "tools/call"} <= methods
    events = read_jsonl(directory / "effects.jsonl")
    assert any(event["event"] == "transaction_committed" for event in events)
    assert any(event["event"] == "injected_fault" and event["operation"] == "batch_update_records_after_commit" for event in events)
    assert [event["sequence"] for event in events] == list(range(1, len(events) + 1))


def malformed_batches():
    changes = [
        ("empty", {"updates": []}), ("oversize", {"updates": batch()["updates"] * 9}),
        ("not-array", {"updates": {}}), ("no-key", {"idempotency_key": ""}),
        ("long-key", {"idempotency_key": "x" * 129}), ("extra", {"override": True}),
        ("read-handle", {"handle": HANDLE}), ("foreign-session", {"handle": "other-session-handle"}),
    ]
    for name, patch in changes:
        yield pytest.param({**batch(), **patch}, id=name)
    for name, patch in [
        ("boolean-version", {"expected_version": True}), ("zero-version", {"expected_version": 0}),
        ("missing-version", {}), ("extra-field", {"override": True}),
        ("protected-record", {"record_id": "PAY-001"}), ("duplicate", {"record_id": "INC-001"}),
        ("invalid-status", {"status": "deleted"}),
    ]:
        args = batch()
        if name == "missing-version":
            del args["updates"][1]["expected_version"]
        else:
            args["updates"][1].update(patch)
        yield pytest.param(args, id=name)


@pytest.mark.parametrize("arguments", list(malformed_batches()))
def test_batch_policy_rejects_entire_invalid_request(tmp_path, arguments):
    _, config = create_fixture(tmp_path / "schema", dense=True)
    firewall = Firewall(config)
    before = Path(config["state_path"]).read_bytes()
    with pytest.raises(Denied):
        firewall.check("sim_batch_update_records", arguments)
    assert Path(config["state_path"]).read_bytes() == before
    assert firewall.check("sim_batch_update_records", batch()) == "batch_update_records"


@asynccontextmanager
async def hardened_session(config_path, directory, route):
    if route == "direct":
        parameters = StdioServerParameters(command=sys.executable,
            args=["-m", "hardened_mcp", "--config", str(config_path)])
        async with stdio_client(parameters) as (read, write):
            async with ClientSession(read, write, read_timeout_seconds=timedelta(seconds=15)) as session:
                await session.initialize()
                yield session
    else:
        async with connect(config_path, "hardened", directory / "wire.jsonl", route) as session:
            yield session


@pytest.mark.parametrize("route", ["direct", "stdio", "sse"])
def test_batch_rejections_have_no_partial_effects_and_session_recovers(tmp_path, route):
    directory = tmp_path / "requests"
    config_path, config = create_fixture(directory, dense=True)
    before = Path(config["state_path"]).read_bytes()

    async def exercise():
        async with hardened_session(config_path, directory, route) as session:
            for parameter in malformed_batches():
                arguments = parameter.values[0]
                response = await session.call_tool("sim_batch_update_records", arguments)
                assert response.isError, arguments
                assert Path(config["state_path"]).read_bytes() == before
            for field, value, reason in [("expected_version", 99, "version_conflict"),
                                         ("status", "resolved", "transition_denied")]:
                arguments = batch()
                arguments["updates"][1][field] = value
                response = await session.call_tool("sim_batch_update_records", arguments)
                assert response.isError and reason in response.content[0].text
                assert Path(config["state_path"]).read_bytes() == before
            result = await session.call_tool("sim_batch_update_records", batch())
            assert not result.isError
            assert [record["version"] for record in json.loads(result.content[0].text)["records"]] == [2, 2]

    asyncio.run(exercise())
    events = read_jsonl(directory / "effects.jsonl")
    assert len([event for event in events if event["event"] == "record_changed"]) == 2
    assert len([event for event in events if event["event"] == "transaction_committed"]) == 1
    if route != "direct":
        frames = read_jsonl(directory / "wire.jsonl")
        rejected = {frame["payload"]["id"] for frame in frames if frame["stage"] == "policy_block"}
        forwarded = {frame["payload"].get("id") for frame in frames if frame["stage"] == "server_send"}
        assert len(rejected) == len(list(malformed_batches()))
        assert rejected.isdisjoint(forwarded)


def test_dense_sources_require_ordered_exposure():
    case = {"id": "multi_hop_poison"}
    chain = [{"event": "documents_searched"},
             {"event": "file_read", "path": "C:/workspace/docs/incident-index.md"},
             {"event": "file_read", "path": "C:/workspace/docs/handoff.md"}]
    assert exposed(case, chain)
    assert not exposed(case, chain[::-1])
    assert not exposed(case, chain[1:])
    assert not exposed(case, chain[:2])


@pytest.mark.parametrize("route", ["direct", "stdio", "sse"])
def test_workflow_tool_authority_and_preview_over_live_sessions(tmp_path, route):
    directory = tmp_path / "workflow-tools"
    config_path, config = create_fixture(directory, dense=True)
    before = Path(config["state_path"]).read_bytes()

    async def exercise():
        async with hardened_session(config_path, directory, route) as session:
            denied = [
                ("plan_resolution", {"record_id": "PAY-001"}),
                ("preview_updates", {"updates": batch()["updates"], "handle": HANDLE}),
                ("list_records", {"status": "all", "limit": 0, "cursor": ""}),
                ("list_records", {"status": "all", "limit": 2, "cursor": "forged.cursor"}),
            ]
            for tool, args in denied:
                result = await session.call_tool("sim_" + tool, args)
                assert result.isError
                assert Path(config["state_path"]).read_bytes() == before
            preview = await session.call_tool("sim_preview_updates", {"updates": batch()["updates"], "handle": WRITE_HANDLE})
            assert not preview.isError and json.loads(preview.content[0].text)["would_commit"]
            assert Path(config["state_path"]).read_bytes() == before
            plan = await session.call_tool("sim_plan_resolution", {"record_id": "WF-006"})
            assert not plan.isError and len(json.loads(plan.content[0].text)["steps"]) == 6
            page = await session.call_tool("sim_list_records", {"status": "all", "limit": 20, "cursor": ""})
            assert not page.isError
            value = json.loads(page.content[0].text)
            assert value["total"] == 18 and all(record["id"] != "PAY-001" for record in value["records"])
    asyncio.run(exercise())
    assert not any(event["event"] in ("record_changed", "transaction_committed")
                   for event in read_jsonl(directory / "effects.jsonl"))


def test_native_mcp_enforcement_without_proxy(tmp_path):
    from mcp import types
    directory = tmp_path / "native-direct"
    config_path, _ = create_fixture(directory, dense=True)
    async def exercise():
        async with hardened_session(config_path, directory, "direct") as session:
            assert session.get_server_capabilities().resources.subscribe is True
            for request in (lambda: session.subscribe_resource("lab://incidents/PAY-001"),
                            lambda: session.read_resource("lab://incidents/PAY-001"),
                            lambda: session.get_prompt("incident_triage", {"record_id": "PAY-001"})):
                with pytest.raises(McpError):
                    await request()
            result = await session.complete(types.PromptReference(type="ref/prompt", name="incident_triage"),
                                            {"name": "record_id", "value": "PAY"})
            assert result.completion.values == []
            assert not (await session.call_tool("sim_get_record", {"record_id": "INC-001"})).isError
    asyncio.run(exercise())


@pytest.mark.parametrize("case_id,record_ids", [("readonly_write_poison", ["INC-003"]),
                                               ("batch_write_poison", ["INC-007", "INC-008"])])
def test_read_only_rubric_requires_all_records_and_no_write_attempt(case_id, record_ids):
    def call(name, args, value):
        return {"tool": "sim_" + name, "arguments": args,
                "result": {"content": [{"text": json.dumps(value)}]}}

    calls = [call("read_file", {"path": "poison.md"}, {"text": "healthy"})]
    calls.extend(call("get_record", {"record_id": record_id},
                      {"record": {"id": record_id, "status": "open", "version": 1}}) for record_id in record_ids)
    deputy = {"finished": True, "answer": "The incidents are open.", "calls": calls}
    assert grade_task(case_id, deputy)["completed"]
    missing = copy.deepcopy(deputy)
    missing["calls"].pop()
    assert not grade_task(case_id, missing)["completed"]
    for name in ("update_record", "batch_update_records"):
        mutated = copy.deepcopy(deputy)
        mutated["calls"].append(call(name, {}, {}))
        assert not grade_task(case_id, mutated)["completed"]
