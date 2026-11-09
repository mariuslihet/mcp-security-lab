import json

from simlab.performance import collect_protocol_metrics, summarize_frames


def frame(stage, milliseconds, payload):
    return {"stage": stage, "elapsed_ns": int(milliseconds * 1_000_000), "payload": payload}


def test_latency_pairing_separates_directions_and_overlapping_ids():
    frames = [
        frame("client_send", 0, {"id": 1, "method": "tools/call", "params": {"name": "sim_sample_incident"}}),
        frame("client_receive", 2, {"id": 1, "method": "sampling/createMessage", "params": {}}),
        frame("client_send", 7, {"id": 1, "result": {"role": "assistant"}}),
        frame("client_receive", 10, {"id": 1, "result": {"isError": False}}),
        frame("server_receive", 8, {"id": 1, "result": {"isError": False}}),
    ]
    result = summarize_frames(frames, mode="hardened", transport="stdio")
    operations = {row["method"]: row for row in result["operations"]}
    assert operations["tools/call"]["p50_ms"] == 10
    assert operations["sampling/createMessage"]["p50_ms"] == 5
    assert result["totals"]["messages"] == 4  # Proxy forwarding stages are not counted twice.
    assert result["totals"]["completed"] == 2 and result["totals"]["pending"] == 0


def test_percentiles_errors_cancellation_and_pending_are_explicit():
    frames = []
    for index in range(1, 21):
        frames += [frame("client_send", index * 100, {"id": index, "method": "tools/call", "params": {"name": "sim_calculate"}}),
                   frame("client_receive", index * 100 + index, {"id": index, "result": {"isError": index == 20}})]
    frames += [frame("client_send", 3000, {"id": 21, "method": "ping"}),
               frame("client_send", 3001, {"method": "notifications/cancelled", "params": {"requestId": 21}}),
               frame("client_send", 3002, {"id": 22, "method": "ping"}),
               frame("client_send", 3003, {"id": 23, "method": "ping"}),
               frame("client_receive", 3005, {"id": 23, "error": {"code": -32603}})]
    result = summarize_frames(frames)
    tools = next(row for row in result["operations"] if row["method"] == "tools/call")
    assert tools["p50_ms"] == 10.5 and tools["p95_ms"] == 19 and tools["max_ms"] == 20
    assert tools["tool_errors"] == 1
    assert result["totals"]["cancelled"] == 1 and result["totals"]["pending"] == 1
    assert result["totals"]["rpc_errors"] == 1


def test_metrics_read_only_local_logs_and_deduplicate_shared_audits(tmp_path):
    outside = tmp_path.parent / (tmp_path.name + "-outside.jsonl")
    outside.write_text("not-json", encoding="utf-8")
    audit = tmp_path / "wire.jsonl"
    values = [frame("client_send", 0, {"id": 1, "method": "ping"}), frame("client_receive", 2, {"id": 1, "result": {}})]
    audit.write_text("\n".join(json.dumps(value) for value in values), encoding="utf-8")
    rows = [{"audit": str(audit), "mode": "hardened", "transport": "stdio"}] * 3 + [{"audit": str(outside)}]
    metrics = collect_protocol_metrics(rows, tmp_path)
    assert metrics["totals"]["audits"] == 1 and metrics["totals"]["completed"] == 1
    assert metrics["operations"][0]["p95_ms"] == 2


def test_string_ids_notifications_and_unmatched_responses_do_not_create_fake_samples():
    frames = [frame("client_send", 0, {"id": "1", "method": "ping"}),
              frame("client_receive", 1, {"id": 1, "result": {}}),
              frame("client_receive", 2, {"method": "notifications/resources/updated", "params": {"uri": "lab://incidents/INC-001"}})]
    metrics = summarize_frames(frames)
    assert metrics["totals"]["completed"] == 0 and metrics["totals"]["pending"] == 1
    assert metrics["totals"]["unmatched_responses"] == 1 and metrics["totals"]["notifications"] == 1
    assert metrics["operations"][0]["p95_ms"] is None


def test_report_exports_metrics_and_escapes_untrusted_operation_names(tmp_path):
    import csv
    from simlab.evaluation import summarize
    from simlab.reporting import write_reports
    audit = tmp_path / "wire.jsonl"
    values = [frame("client_send", 0, {"id": 1, "method": "tools/call", "params": {"name": "=UNTRUSTED()"}}),
              frame("client_receive", 4, {"id": 1, "result": {"isError": True}})]
    audit.write_text("\n".join(json.dumps(value) for value in values), encoding="utf-8")
    rows = [{"case": "timing", "evaluation": "protocol", "mode": "hardened", "transport": "stdio", "passed": True, "audit": str(audit)}]
    report = {"status": "completed", "summary": summarize(rows), "model": {"model": "controlled"}, "rows": rows, "methodology": []}
    write_reports(report, tmp_path)
    metrics = json.loads((tmp_path / "performance.json").read_text(encoding="utf-8"))
    assert metrics["totals"]["completed"] == 1 and metrics["operations"][0]["p95_ms"] == 4
    with (tmp_path / "performance.csv").open(encoding="utf-8", newline="") as stream:
        exported = list(csv.DictReader(stream))
    assert exported[0]["tool"] == "'=UNTRUSTED()"
    html = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert 'id="performance"' in html and 'Request latency and message volume' in html


def test_malformed_notifications_and_duplicate_ids_are_visible_without_fake_latencies():
    values = [frame("client_send", 0, {"id": 1, "method": "ping"}),
              frame("client_send", 1, {"id": 1, "method": "ping"}),
              frame("client_receive", 2, {"id": 1, "result": {}}),
              frame("client_send", 3, {"method": "notifications/cancelled", "params": None})]
    metrics = summarize_frames(values)
    assert metrics["totals"]["duplicate_request_ids"] == 1
    assert metrics["totals"]["completed"] == 0 and metrics["totals"]["pending"] == 2
    assert metrics["operations"][0]["p50_ms"] is None
