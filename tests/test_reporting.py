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
