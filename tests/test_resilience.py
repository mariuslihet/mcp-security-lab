import copy
import json
import asyncio
import random
import hashlib
from pathlib import Path

import pytest

from simlab.resilience import simulate, audit
from simlab.client import connect
from simlab.fixtures import WRITE_HANDLE
from simlab.controls import Denied
from simlab.dependency_graph import generate_graph
from simlab.graph_campaign import generate_graph_manifest, graph_campaign_matrix
from simlab.checkpoint import canonical
from jsonschema import Draft202012Validator
from test_outage_recovery import DIAMOND, operations


def scenario():
    return {"record_id": "GR-003", "max_parallel": 2, "durations": [], "worker_outages": [],
            "faults": [], "max_attempts": 3, "retry_backoff_ms": 2}


def inputs(tmp_path):
    _, config, _, _ = operations(tmp_path)
    records = json.loads(Path(config["state_path"]).read_text())["records"]
    return records


def test_resilience_retries_do_not_advance_versions_until_success(tmp_path):
    records = inputs(tmp_path)
    args = scenario()
    args["faults"] = [{"record_id": "GR-000", "status": "investigating", "failed_attempts": 2}]
    result = simulate(args, DIAMOND, records)
    assert result["completed"] and result["retry_count"] == 2
    attempts = [event for event in result["attempts"] if event["record_id"] == "GR-000" and event["status"] == "investigating"]
    assert [event["start_ms"] for event in attempts] == [0, 3, 8]
    assert [event["expected_version"] for event in attempts] == [1, 1, 1]
    assert [event["outcome"] for event in attempts] == ["retry", "retry", "succeeded"]
    assert audit(args, DIAMOND, records, result) == {"valid": True, "violations": []}


def test_worker_outage_aborts_work_and_exhaustion_blocks_dependents(tmp_path):
    records = inputs(tmp_path)
    args = scenario()
    args.update(max_parallel=1, max_attempts=1, worker_outages=[{"worker": 0, "start_ms": 1, "end_ms": 5}])
    args["durations"] = [{"record_id": "GR-000", "investigate_ms": 3, "resolve_ms": 1}]
    result = simulate(args, DIAMOND, records)
    assert not result["completed"]
    assert result["attempts"][0]["reason"] == "worker_outage"
    assert result["attempts"][0]["end_ms"] == 1
    assert result["failed_tasks"] == [{"record_id": "GR-000", "status": "investigating"}]
    assert set(result["unfinished_records"]) == set(DIAMOND)
    assert len(result["blocked_tasks"]) == 4
    assert audit(args, DIAMOND, records, result)["valid"]


@pytest.mark.parametrize("corruption", ["version", "worker", "overlap", "missing", "summary", "snapshot"])
def test_independent_auditor_rejects_corrupted_traces(tmp_path, corruption):
    records = inputs(tmp_path)
    args = scenario()
    trace = simulate(args, DIAMOND, records)
    if corruption == "version":
        trace["attempts"][0]["expected_version"] += 1
    elif corruption == "worker":
        trace["attempts"][0]["worker"] = 99
    elif corruption == "overlap":
        trace["attempts"][1]["worker"] = trace["attempts"][0]["worker"]
    elif corruption == "missing":
        trace["attempts"].pop()
    elif corruption == "summary":
        trace["completed"] = False
    else:
        trace["snapshot"][0]["version"] += 1
    checked = audit(args, DIAMOND, records, trace)
    assert not checked["valid"] and checked["violations"]


def test_auditor_accepts_a_legal_delayed_schedule_without_resimulation(tmp_path):
    records, args = inputs(tmp_path), scenario()
    trace = simulate(args, DIAMOND, records)
    for event in trace["attempts"]:
        event["start_ms"] += 10
        event["end_ms"] += 10
    trace["elapsed_ms"] += 10
    assert audit(args, DIAMOND, records, trace)["valid"]


def test_completion_at_outage_boundary_succeeds_and_overlapping_outages_delay_dispatch(tmp_path):
    records, args = inputs(tmp_path), scenario()
    args.update(max_parallel=1, worker_outages=[{"worker": 0, "start_ms": 1, "end_ms": 4},
                                              {"worker": 0, "start_ms": 2, "end_ms": 6}])
    trace = simulate(args, DIAMOND, records)
    assert trace["attempts"][0]["outcome"] == "succeeded"
    assert trace["attempts"][1]["start_ms"] == 6
    assert trace["retry_count"] == 0 and audit(args, DIAMOND, records, trace)["valid"]


@pytest.mark.parametrize("nodes,workers", [(8, 1), (32, 3), (128, 16)])
@pytest.mark.parametrize("seed", range(6))
def test_randomized_resilience_attempts_audit_and_leave_state_unchanged(tmp_path, nodes, workers, seed):
    graph_data = generate_graph(seed, nodes, 4)
    _, config, store, graph = operations(tmp_path, graph_data)
    rng = random.Random(seed)
    target = sorted(graph_data)[-1]
    from simlab.resilience import closure
    selected = closure(target, graph_data)
    args = {**scenario(), "record_id": target, "max_parallel": workers, "max_attempts": rng.randint(1, 4),
        "retry_backoff_ms": rng.randint(0, 10),
        "durations": [{"record_id": key, "investigate_ms": rng.randint(1, 20), "resolve_ms": rng.randint(1, 20)} for key in selected],
        "faults": [{"record_id": key, "status": rng.choice(["investigating", "resolved"]), "failed_attempts": rng.randint(0, 3)}
                   for key in rng.sample(selected, min(16, len(selected)))],
        "worker_outages": [{"worker": rng.randrange(workers), "start_ms": start, "end_ms": start + rng.randint(1, 15)}
                           for start in range(0, 100, 10)]}
    before = Path(config["state_path"]).read_bytes()
    trace = graph.recovery_resilience(args)
    assert trace == graph.recovery_resilience(copy.deepcopy(args))
    assert len(trace["attempts"]) <= 2 * len(selected) * args["max_attempts"]
    checked = graph.validate_trace({"scenario": args, "trace": trace})
    assert checked == {"valid": True, "violations": []}
    assert Path(config["state_path"]).read_bytes() == before
    async def execute_successes():
        successes = sorted((event for event in trace["attempts"] if event["outcome"] == "succeeded"),
                           key=lambda event: (event["end_ms"], event["start_ms"], event["record_id"]))
        for index, event in enumerate(successes):
            await store.update({key: event[key] for key in ("record_id", "status", "expected_version")} |
                               {"handle": WRITE_HANDLE, "idempotency_key": f"verified-{index}"}, True)
    asyncio.run(execute_successes())
    assert [store.read(key) for key in selected] == trace["final_records"]


@pytest.mark.parametrize("transport", ["stdio", "sse", "streamable-http"])
@pytest.mark.parametrize("mode", ["hardened", "vulnerable"])
def test_resilience_tools_live_contracts_authority_and_large_trace_roundtrip(tmp_path, mode, transport):
    graph_data = generate_graph(7, 128, 8)
    config_path, config, _, _ = operations(tmp_path, graph_data)
    before = Path(config["state_path"]).read_bytes()
    args = {**scenario(), "record_id": "GR-127", "max_parallel": 16}
    args["faults"] = [{"record_id": key, "status": "investigating", "failed_attempts": 2} for key in sorted(graph_data)[:-7]]
    # The last layer's siblings are outside the requested closure.
    args["faults"] = [row for row in args["faults"] if row["record_id"] != "GR-120"]
    async def run():
        prefix = "sim_" if mode == "hardened" else ""
        async with connect(config_path, mode, tmp_path / "wire.jsonl", transport) as session:
            tools = {tool.name: tool for tool in (await session.list_tools()).tools}
            assert tools[prefix + "simulate_recovery_resilience"].annotations.readOnlyHint
            result = await session.call_tool(prefix + "simulate_recovery_resilience", args)
            assert not result.isError and result.structuredContent["completed"]
            assert len(result.structuredContent["attempts"]) > 400
            Draft202012Validator(tools[prefix + "simulate_recovery_resilience"].outputSchema).validate(result.structuredContent)
            audited = await session.call_tool(prefix + "validate_recovery_trace", {"scenario": args, "trace": result.structuredContent})
            assert not audited.isError and audited.structuredContent == {"valid": True, "violations": []}
            forged = copy.deepcopy(result.structuredContent)
            forged["attempts"][0]["expected_version"] += 1
            rejected = await session.call_tool(prefix + "validate_recovery_trace", {"scenario": args, "trace": forged})
            assert not rejected.isError and not rejected.structuredContent["valid"]
            protected = {**args, "record_id": "PAY-001", "faults": []}
            denied = await session.call_tool(prefix + "validate_recovery_trace", {"scenario": protected, "trace": {}})
            assert bool(denied.isError) == (mode == "hardened")
            await session.send_ping()
    asyncio.run(run())
    assert Path(config["state_path"]).read_bytes() == before


@pytest.mark.parametrize("problem", ["fault_duplicate", "fault_outside", "duration_duplicate", "outage_order", "outage_worker", "attempts", "backoff"])
def test_resilience_profiles_are_bounded_and_scoped(tmp_path, problem):
    _, _, _, graph = operations(tmp_path)
    args = scenario()
    if problem == "fault_duplicate":
        args["faults"] = [{"record_id": "GR-000", "status": "resolved", "failed_attempts": 1}] * 2
    elif problem == "fault_outside":
        args["faults"] = [{"record_id": "INC-001", "status": "resolved", "failed_attempts": 1}]
    elif problem == "duration_duplicate":
        args["durations"] = [{"record_id": "GR-000", "investigate_ms": 1, "resolve_ms": 1}] * 2
    elif problem.startswith("outage"):
        args["worker_outages"] = [{"worker": 5 if problem == "outage_worker" else 0, "start_ms": 3, "end_ms": 2 if problem == "outage_order" else 4}]
    elif problem == "attempts":
        args["max_attempts"] = 0
    else:
        args["retry_backoff_ms"] = 1001
    with pytest.raises(Denied):
        graph.recovery_resilience(args)


@pytest.mark.parametrize("mode,transport", [("hardened", "stdio"), ("vulnerable", "sse"), ("hardened", "streamable-http")])
def test_resilience_campaigns_resume_verified_and_corrupted_trace_probes(tmp_path, mode, transport):
    manifest = generate_graph_manifest(11, 80, nodes=16, width=4, parallel_calls=8, race_topology="mixed",
        root_churn=True, outage_stress=True, timeline_stress=True, resilience_stress=True)
    stop = next(index + 1 for index, action in enumerate(manifest["actions"]) if action["label"] == "tampered_recovery_version")
    source = tmp_path / "source"
    rows = asyncio.run(graph_campaign_matrix(source, mode, transport, manifest, stop_after=stop))
    assert all(row["passed"] for row in rows)
    continued = asyncio.run(graph_campaign_matrix(tmp_path / "continued", mode, transport, manifest,
                                                   resume_checkpoint=source / "checkpoint.json"))
    assert len(continued) == 80 and all(row["passed"] for row in continued)
    assert {row["action"]["corruption"] for row in continued if row["action"]["kind"] == "resilience"} == {"none", "version", "missing", "summary"}


def test_rehashed_checkpoint_with_forged_resilience_attempt_is_rejected(tmp_path):
    manifest = generate_graph_manifest(11, 60, nodes=8, width=2, parallel_calls=4, resilience_stress=True)
    source = tmp_path / "source"
    rows = asyncio.run(graph_campaign_matrix(source, "hardened", "stdio", manifest, stop_after=3))
    assert all(row["passed"] for row in rows)
    path = source / "checkpoint.json"
    envelope = json.loads(path.read_text())
    envelope["payload"]["rows"][-1]["responses"][0]["structuredContent"]["attempts"][0]["expected_version"] += 1
    envelope["sha256"] = hashlib.sha256(canonical(envelope["payload"])).hexdigest()
    path.write_text(json.dumps(envelope))
    with pytest.raises(ValueError, match="resilience trace fails reference audit"):
        asyncio.run(graph_campaign_matrix(tmp_path / "rejected", "hardened", "stdio", manifest, resume_checkpoint=path))
