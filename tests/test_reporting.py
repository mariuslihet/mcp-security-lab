from simlab.evaluation import summarize
from simlab.reporting import write_html_report, write_reports


def test_report_escapes_payloads_and_links_only_run_evidence(tmp_path):
    payload = '<script>alert("payload")</script>__METHOD__'
    rows = [{"case": payload, "evaluation": "llm", "mode": "vulnerable", "passed": False,
             "actors": str(tmp_path / "actors.jsonl"), "audit": str(tmp_path.parent / "outside.jsonl")}]
    report = {"summary": summarize(rows), "model": {"model": payload},
              "rows": rows, "methodology": [payload]}
    write_html_report(report, tmp_path / "report.html")
    html = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert '<script>alert' not in html
    assert '&lt;script&gt;' in html
    assert 'href="actors.jsonl"' in html
    assert 'href="../outside.jsonl"' not in html
    assert '<li>&lt;script&gt;' in html
    assert 'FAIL' in html and 'Not run' in html


def test_checkpoint_exports_status_csv_and_task_outcomes(tmp_path):
    import csv
    import json

    rows = [{"evaluation": "llm", "case": "tool_shadow", "mode": "hardened", "seed": 11,
             "passed": True, "exploit_observed": False, "task": {"completed": True, "status": "completed"},
             "error": "=UNTRUSTED()"}]
    report = {"status": "running", "summary": summarize(rows), "model": {"model": "local"},
              "methodology": [], "rows": rows}
    write_reports(report, tmp_path)
    assert json.loads((tmp_path / "report.json").read_text())["status"] == "running"
    html = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert "Partial results" in html and "Task outcome" in html and 'id="search"' in html
    with (tmp_path / "results.csv").open(newline="", encoding="utf-8") as stream:
        exported = list(csv.DictReader(stream))
    assert exported[0]["seed"] == "11"
    assert exported[0]["task_status"] == "completed"
    assert exported[0]["error"] == "'=UNTRUSTED()"
    assert not list(tmp_path.glob("*.tmp"))


def test_dashboard_renders_case_seed_outcomes_and_escaped_inspector(tmp_path):
    from simlab.grading import compare_cases

    rows = [
        {"evaluation": "llm", "case": "tool_shadow", "transport": "stdio", "mode": "vulnerable", "seed": 7,
         "passed": True, "exploit_observed": True},
        {"evaluation": "llm", "case": "tool_shadow", "transport": "stdio", "mode": "hardened", "seed": 7,
         "passed": True, "exploit_observed": False, "task": {"completed": True, "status": "completed", "checks": {"observed": True}},
         "deputy": {"answer": '<img src=x onerror="alert(1)">', "calls": [
             {"tool": "sim_calculate", "arguments": {"expression": "2+2"},
              "result": {"content": [{"text": '{"result":4}'}]}}]}},
    ]
    report = {"summary": summarize(rows), "model": {"model": "local"}, "rows": rows,
              "methodology": [], "comparisons": compare_cases(rows)}
    write_html_report(report, tmp_path / "report.html")
    html = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert '<img src=x' not in html and '&lt;img src=x' in html
    assert 'data-seed="7"' in html and 'data-mode="hardened"' in html
    assert 'data-outcome="completed"' in html
    assert '<template id="evidence-1">' in html
    assert 'sim_calculate' in html and 'Task rubric' in html
    assert 'id="seeds"' in html and 'id="comparisons"' in html
    assert '1/1</b>' in html and '0/1</b>' in html
    assert '<td>1/1 completed</td>' in html


def test_dashboard_handles_empty_checkpoint_and_legacy_report(tmp_path):
    for rows in ([], [{"evaluation": "protocol", "case": "benign_read", "passed": True}]):
        report = {"summary": summarize(rows), "model": {"model": "local"}, "rows": rows, "methodology": []}
        write_html_report(report, tmp_path / "report.html")
        html = (tmp_path / "report.html").read_text(encoding="utf-8")
        assert 'No live case comparisons yet.' in html
        assert 'No seed outcomes recorded.' in html
        assert 'Not run' in html
        assert '__CARDS__' not in html and '__ROWS__' not in html


def test_embedded_comparison_data_cannot_close_script_and_omits_conversations(tmp_path):
    import json
    from html.parser import HTMLParser

    attack = '</script><script>alert("injected")</script>'
    rows = [{"evaluation": "llm", "case": attack, "passed": False,
             "deputy": {"answer": "PRIVATE_CONVERSATION_MARKER", "calls": []}}]
    report = {"schema_version": 2, "summary": summarize(rows), "model": {"model": attack}, "rows": rows, "methodology": []}
    write_html_report(report, tmp_path / "report.html")
    class DataScript(HTMLParser):
        collecting = False
        data = ''
        def handle_starttag(self, tag, attrs):
            if tag == 'script' and dict(attrs).get('id') == 'run-data':
                self.collecting = True
        def handle_endtag(self, tag):
            if tag == 'script':
                self.collecting = False
        def handle_data(self, data):
            if self.collecting:
                self.data += data
    html = (tmp_path / "report.html").read_text(encoding="utf-8")
    parser = DataScript(); parser.feed(html)
    embedded = json.loads(parser.data)
    assert embedded['model']['model'] == attack
    assert embedded['rows'][0]['case'] == attack
    assert 'PRIVATE_CONVERSATION_MARKER' not in parser.data
    assert attack not in html


def test_portable_evidence_links_resolve_from_report_folder(tmp_path):
    from simlab.dashboard import evidence_links

    report_dir = tmp_path / "downloaded-example"
    (report_dir / "case").mkdir(parents=True)
    (report_dir / "case" / "wire.jsonl").write_text('{}\n')
    links = evidence_links({"audit": "case/wire.jsonl", "actors": "../outside.jsonl"}, report_dir)
    assert 'href="case/wire.jsonl"' in links
    assert '../outside.jsonl' not in links


def test_dashboard_has_no_logo_and_keeps_review_controls_separate_from_results(tmp_path):
    rows=[{"case":"benign_read","evaluation":"protocol","passed":True}]
    report={"summary":summarize(rows),"model":{"model":"local"},"rows":rows,"methodology":[]}
    write_html_report(report,tmp_path/'report.html')
    html=(tmp_path/'report.html').read_text(encoding='utf-8')
    assert 'class="brand"' not in html and 'brand-icon' not in html
    assert 'SIMULATION LAB</div>' not in html
    assert 'Review workspace' in html and 'Visible columns' in html
    assert 'review-cell' in html
    assert rows == [{"case":"benign_read","evaluation":"protocol","passed":True}]


def test_review_identity_uses_evidence_content_and_survives_relocation(tmp_path):
    import re

    rows=[{"case":"tool_shadow","evaluation":"llm","passed":True,"audit":"first/wire.jsonl",
           "deputy":{"answer":"Result is 4","calls":[]}}]
    report={"summary":summarize(rows),"model":{"model":"local"},"rows":rows,"methodology":[]}
    def identity():
        write_html_report(report,tmp_path/'report.html')
        return re.search(r'data-run-key="([a-f0-9]+)"',(tmp_path/'report.html').read_text(encoding='utf-8'))[1]
    original=identity()
    rows[0]['audit']='relocated/wire.jsonl'
    assert identity()==original
    rows[0]['deputy']['answer']='The task was not completed'
    assert identity()!=original


def test_capability_overview_and_client_trace_escape_payloads_and_link_local_evidence(tmp_path):
    marker = '<img src=x onerror="alert(1)">'
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    for name in ("client.jsonl", "campaign.json", "state.json"):
        (case_dir / name).write_text('{}', encoding="utf-8")
    rows = [
        {"case": "client_sampling_roundtrip", "evaluation": "protocol", "feature": "Sampling", "mode": "vulnerable", "transport": "stdio", "passed": True},
        {"case": "client_sampling_roundtrip", "evaluation": "protocol", "feature": "Sampling", "mode": "hardened", "transport": "sse", "passed": False,
         "client": str(case_dir / "client.jsonl"), "manifest": str(case_dir / "campaign.json"), "state_file": str(case_dir / "state.json"),
         "client_requests": [{"operation": marker, "duration_seconds": 0.1, "request": {"text": marker}, "response": {"text": marker}}]},
        {"case": "mcp_logging_threshold", "evaluation": "protocol", "mode": "hardened", "transport": "stdio", "passed": True},
    ]
    report = {"summary": summarize(rows), "model": {"model": "local"}, "rows": rows, "methodology": []}
    write_html_report(report, tmp_path / "report.html")
    html = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert 'id="capabilities"' in html and 'Capabilities exercised' in html
    assert '<th scope="row">Sampling</th><td>sse, stdio</td><td>1/1</td><td>0/1</td><td>1</td>' in html
    assert 'Server logging' in html and 'Server-to-client request trace' in html
    assert marker not in html and '&lt;img' in html
    assert 'href="case/client.jsonl"' in html and 'href="case/campaign.json"' in html and 'href="case/state.json"' in html


def test_client_and_manifest_evidence_cannot_link_outside_report_folder(tmp_path):
    from simlab.dashboard import evidence_links
    assert evidence_links({"client": "../client.jsonl", "manifest": "../campaign.json", "state_file": "../state.json"}, tmp_path) == ""


def test_graph_topology_is_bounded_and_invalid_graphs_cannot_inject_markup(tmp_path):
    from simlab.dependency_graph import generate_graph
    rows = [{"case": "graph_campaign_7", "mode": "hardened", "transport": "stdio", "evaluation": "protocol", "passed": True,
             "campaign_seed": 7, "graph_definition": generate_graph(7, 16, 4)}]
    report = {"summary": summarize(rows), "model": {"model": "local"}, "rows": rows, "methodology": []}
    write_html_report(report, tmp_path / "report.html")
    html = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert 'id="dependency-topology"' in html and '16 nodes' in html and '4 layers' in html
    assert html.count('text-anchor="middle"') == 16
    payload = '<script>alert(1)</script>'
    rows[0]["graph_definition"][payload] = []
    write_html_report(report, tmp_path / "report.html")
    html = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert 'invalid recorded graph' in html and 'id="dependency-topology"' not in html
    assert payload not in html
