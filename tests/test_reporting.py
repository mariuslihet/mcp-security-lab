from simlab.evaluation import summarize
from simlab.reporting import write_html_report, write_reports


def test_resource_diagnostics_and_timeline_assets_are_portable_and_escaped(tmp_path):
    from simlab.resilience import simulate
    from simlab.trace_diagnostics import utilization
    from test_outage_recovery import DIAMOND, operations
    from test_resilience import scenario
    import json
    _, config, _, _ = operations(tmp_path / "fixture")
    records = json.loads(open(config["state_path"], encoding="utf-8").read())['records']
    args = scenario()
    trace = simulate(args, DIAMOND, records)
    value = utilization(args, trace)
    value['record_id'] = '<img src=x onerror=alert(1)>'
    rows = [{'case':'resource-diagnostics','evaluation':'protocol','passed':True,
             'response':{'structuredContent':value},'recovery_trace':trace}]
    report = {'schema_version':2,'model':{'model':'controlled'},'rows':rows,'summary':summarize(rows),'methodology':[]}
    write_html_report(report, tmp_path / 'report.html')
    html = (tmp_path / 'report.html').read_text(encoding='utf-8')
    assert 'Recorded worker capacity' in html and '80.00%' in html
    assert 'recovery-resource-summary' in html and 'class="recorded-result"' in html
    assert 'globalThis.SimlabRecovery' in html and 'SimlabRecovery.mount' in html
    assert '<img src=x onerror=alert(1)>' not in html and '&lt;img src=x' in html
    assert '__RECOVERY_SCRIPT__' not in html and 'src="dashboard-recovery.js"' not in html


def test_malformed_resource_diagnostics_keep_raw_evidence_without_misleading_table(tmp_path):
    rows = [{'case':'malformed-resources','evaluation':'protocol','passed':False,
             'response':{'structuredContent':{'record_id':'GR-000','totals':{},'retry_wait':{}}}}]
    report = {'schema_version':2,'model':{'model':'controlled'},'rows':rows,'summary':summarize(rows),'methodology':[]}
    write_html_report(report,tmp_path/'report.html')
    html = (tmp_path/'report.html').read_text(encoding='utf-8')
    assert 'Recorded worker capacity ·' not in html and 'Full recorded evidence' in html


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


def test_recovery_policy_matrix_and_trace_changes_render_escaped_recorded_results(tmp_path):
    from test_recovery_portfolio import arguments, pair
    from test_outage_recovery import operations
    from simlab.dashboard import recovery_decision_summaries
    _, _, _, graph = operations(tmp_path)
    portfolio = graph.recovery_portfolio(arguments())
    compared = graph.compare_recovery_traces(pair(graph))
    marker = '<img src=x onerror="alert(1)">'
    portfolio["robust_strategy"] = marker
    compared["targets"][0]["record_id"] = marker
    row = {"case": "matrix", "evaluation": "protocol", "passed": True, "responses": [
        {"structuredContent": portfolio}, {"structuredContent": compared}, {"structuredContent": portfolio}]}
    summary = recovery_decision_summaries(row)
    assert summary.count('<h3>Recorded recovery policy matrix') == 1
    assert 'Recorded recovery changes' in summary and 'Pareto tradeoffs' in summary
    assert '<td>fault</td>' in summary and '<td>unchanged</td>' in summary
    assert marker not in summary and '&lt;img' in summary
    report = {"summary": summarize([row]), "model": {"model": "local"}, "rows": [row], "methodology": []}
    write_html_report(report, tmp_path / "report.html")
    html = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert 'Recorded recovery policy matrix' in html and marker not in html
    portfolio["cells"][0]["completed"] = "invalid"
    compared["delta"]["elapsed_ms"] = "invalid"
    assert recovery_decision_summaries(row) == ""


def test_recovery_trace_change_report_never_formats_unfinished_work_as_speedup(tmp_path):
    from test_recovery_portfolio import pair
    from test_outage_recovery import operations
    from test_resilience import scenario
    from simlab.dashboard import recovery_decision_summaries
    _, _, _, graph = operations(tmp_path)
    bad = scenario();bad["max_attempts"] = 1
    bad["faults"] = [{"record_id": "GR-000", "status": "investigating", "failed_attempts": 1}]
    value = graph.compare_recovery_traces(pair(graph, scenario(), bad))
    summary = recovery_decision_summaries({"response": {"structuredContent": value}})
    assert 'Not comparable' in summary and '<td>Unfinished</td><td>lost</td>' in summary


def test_recorded_wait_and_failure_summaries_escape_paths_and_preserve_evidence(tmp_path):
    from test_outage_recovery import operations
    from test_recovery_explanations import request,analyze,explain
    from test_resilience import scenario
    from simlab.explanation_reporting import render_explanation_summaries
    _, _, _, graph = operations(tmp_path)
    base = scenario();base["max_attempts"] = 1
    base["faults"] = [{"record_id":"GR-000","status":"investigating","failed_attempts":1}]
    args = request(graph,base)
    waits, failures = analyze(graph,args),explain(graph,args)
    marker = '<img src=x onerror="alert(1)">'
    waits["attempts"][0]["record_id"] = marker
    failures["targets"][0]["causes"][0]["path"][0]["record_id"] = marker
    row = {"case":"explanations","evaluation":"protocol","passed":True,"responses":[
        {"structuredContent":waits},{"structuredContent":failures},{"structuredContent":waits}]}
    summary = render_explanation_summaries(row)
    assert summary.count('<h3>Recorded ready-to-dispatch waits') == 1
    assert 'Recorded failure propagation' in summary and 'GR-003 / resolved' in summary
    assert marker not in summary and '&lt;img' in summary
    assert 'not worker-capacity totals' in summary
    report = {"summary":summarize([row]),"model":{"model":"local"},"rows":[row],"methodology":[]}
    write_html_report(report,tmp_path/'report.html')
    html = (tmp_path/'report.html').read_text(encoding='utf-8')
    assert 'Recorded failure propagation' in html and marker not in html
    assert marker in row["responses"][0]["structuredContent"]["attempts"][0]["record_id"]
    waits["totals"]["dispatch_gap_ms"] = False
    failures["roots"][0]["affected_record_count"] = False
    assert render_explanation_summaries(row) == ''


def test_explanation_summaries_bound_large_tables_and_skip_error_results(tmp_path):
    import copy
    from test_outage_recovery import operations
    from test_recovery_explanations import request,analyze,explain
    from test_resilience import scenario
    from simlab.explanation_reporting import render_explanation_summaries
    _, _, _, graph = operations(tmp_path)
    base = scenario();base["max_attempts"] = 1
    base["faults"] = [{"record_id":"GR-000","status":"investigating","failed_attempts":1}]
    args = request(graph,base)
    waits, failures = analyze(graph,args),explain(graph,args)
    waits["attempts"] = [copy.deepcopy(waits["attempts"][0]) for _ in range(101)]
    failures["targets"] = [copy.deepcopy(failures["targets"][0]) for _ in range(21)]
    failures["targets"][0]["truncated"] = True
    sources = [{"structuredContent":waits},{"structuredContent":failures}]
    summary = render_explanation_summaries({"responses":sources})
    assert 'first 100 of 101' in summary and 'first 20 of 21 incident explanations' in summary
    assert 'causes truncated' in summary and 'full evidence' in summary
    assert summary.count('<tr>') == 103  # 100 attempts, one root, two headers.
    assert render_explanation_summaries({"responses":[{**source,"isError":True} for source in sources]}) == ''


def test_compact_comparison_export_omits_evidence_without_changing_scope_or_grades(tmp_path):
    import copy
    import json
    from simlab.reporting import comparison_snapshot,write_reports
    marker = 'large-recorded-evidence-' * 10000
    rows = [{"case":"dense","evaluation":"protocol","mode":"hardened","transport":"stdio","passed":True,
        "responses":[{"structuredContent":{"evidence":marker}}]},
        {"case":"actor","evaluation":"llm","mode":"vulnerable","transport":"sse","passed":True,"seed":7,
         "exploit_observed":True,"task":{"completed":False,"status":"incomplete","checks":{"recorded":True},"detail":marker},"deputy":{"answer":marker}},
        {"case":"actor","evaluation":"llm","mode":"hardened","transport":"sse","passed":False,"error":marker}]
    report = {"schema_version":2,"status":"completed","summary":summarize(rows),"model":{"model":"local"},
        "experiment":{"require_task_success":False},"rows":rows,"methodology":[]}
    before = copy.deepcopy(report)
    compact = comparison_snapshot(report)
    assert report == before and compact["experiment"] == report["experiment"]
    assert compact["rows"][1]["task"] == {"completed":False}
    assert 'task' not in compact["rows"][2] and 'seed' not in compact["rows"][2]
    assert 'error' in compact["rows"][2] and 'exploit_observed' not in compact["rows"][2]
    assert marker not in json.dumps(compact) and len(json.dumps(compact)) < len(json.dumps(report))//20
    write_reports(report,tmp_path)
    assert json.loads((tmp_path/'comparison.json').read_text()) == compact
    assert 'href="comparison.json"' in (tmp_path/'report.html').read_text(encoding='utf-8')
    assert json.loads((tmp_path/'report.json').read_text())["rows"][0]["responses"][0]["structuredContent"]["evidence"] == marker


def test_compact_and_full_exports_produce_identical_javascript_comparisons(tmp_path):
    import json
    from pathlib import Path
    import shutil
    import subprocess
    import pytest
    from simlab.reporting import comparison_snapshot
    if not shutil.which('node'): pytest.skip('Node is required for cross-language comparison parity')
    rows = [{"case":"protocol","evaluation":"protocol","passed":True,"responses":[{"heavy":"discard"}]},
        {"case":"actor","evaluation":"llm","mode":"vulnerable","transport":"sse","seed":7,"passed":True,
         "exploit_observed":True,"task":{"completed":False}},
        {"case":"actor","evaluation":"llm","mode":"hardened","transport":"sse","seed":7,"passed":True,
         "exploit_observed":False,"task":{"completed":True}},
        {"case":"actor","evaluation":"llm","mode":"hardened","transport":"sse","seed":8,"passed":False,"error":"details"},
        {"case":"other","evaluation":"llm","mode":"vulnerable","transport":"stdio","passed":True,"exploit_observed":True}]
    full = {"schema_version":2,"model":{"model":"local"},"experiment":{"require_task_success":True},"rows":rows}
    compact = comparison_snapshot(full)
    for name,value in [('full',full),('compact',compact)]: (tmp_path/(name+'.json')).write_text(json.dumps(value))
    helper = Path(__file__).resolve().parents[1]/'simlab'/'dashboard-data.js'
    script = """const assert=require('node:assert/strict'),fs=require('node:fs');
const data=require(process.argv[1]),full=JSON.parse(fs.readFileSync(process.argv[2],'utf8')),compact=JSON.parse(fs.readFileSync(process.argv[3],'utf8'));
data.validateReport(compact);
assert.deepEqual(data.stats(compact.rows),data.stats(full.rows));assert.deepEqual(data.scope(compact),data.scope(full));
assert.deepEqual(data.compare(full,compact),data.compare(full,full));assert.deepEqual(data.compare(compact,full),data.compare(full,full));
const other={schema_version:1,model:{model:'different'},rows:full.rows.slice(1,3)};
assert.deepEqual(data.compare(other,compact),data.compare(other,full));
"""
    result = subprocess.run(['node','-e',script,str(helper),str(tmp_path/'full.json'),str(tmp_path/'compact.json')],capture_output=True,text=True)
    assert result.returncode == 0,result.stderr


def test_weighted_objectives_and_capacity_summaries_distinguish_partial_recovery(tmp_path):
    from test_outage_recovery import operations
    from test_recovery_objectives import search_args,evaluated
    from simlab.objective_reporting import render_objective_summaries
    _,_,_,graph = operations(tmp_path)
    args = search_args()
    args['scenario'].update(max_attempts=1,faults=[{'record_id':'GR-001','status':'investigating','failed_attempts':1}])
    args.update(weights=[{'record_id':'GR-002','weight':10}],horizon_ms=100,
        milestones=[{'at_ms':100,'required_basis_points':10000}],require_complete=False)
    objectives = evaluated(graph,args);capacity = graph.search_recovery_capacity(args)
    row = {'case':'weighted','evaluation':'protocol','passed':True,'responses':[
        {'structuredContent':objectives},{'structuredContent':capacity},{'structuredContent':objectives}]}
    summary = render_objective_summaries(row)
    assert summary.count('<h3>Recorded weighted recovery objectives') == 1
    assert 'All targets eventually completed: Yes' in summary and 'Whole recovery completed: No' in summary
    assert 'Whole recovery required: No' in summary and 'Smallest qualifying tested pool: <b>1</b>' in summary
    assert '<td>100.00%</td>' in summary and 'not probabilities' in summary
    marker = '<img src=x onerror="alert(1)">'
    objectives['snapshot'][0]['id'] = marker
    report = {'summary':summarize([row]),'model':{'model':'local'},'rows':[row],'methodology':[]}
    write_html_report(report,tmp_path/'report.html')
    html = (tmp_path/'report.html').read_text(encoding='utf-8')
    assert marker not in html and '&lt;img' in html and 'Recorded worker capacity search' in html
    objectives['unresolved_weight_ms'] = False;capacity['recommended_workers'] = False
    assert render_objective_summaries(row) == ''


def test_weighted_summary_zero_horizon_and_all_capacity_candidates_are_visible(tmp_path):
    import json
    from test_outage_recovery import operations,DIAMOND
    from test_recovery_objectives import search_args,evaluated
    from simlab.objective_reporting import render_objective_summaries
    _,config,_,graph = operations(tmp_path)
    from pathlib import Path
    path = Path(config['state_path']);data = json.loads(path.read_text())
    for key in DIAMOND: data['records'][key]['status'] = 'resolved'
    path.write_text(json.dumps(data))
    args = search_args();args.update(horizon_ms=0,milestones=[{'at_ms':0,'required_basis_points':10000}],worker_options=list(range(1,17)))
    sources = [{'structuredContent':evaluated(graph,args)},{'structuredContent':graph.search_recovery_capacity(args)}]
    summary = render_objective_summaries({'responses':sources})
    assert 'No observation interval' in summary
    assert summary.count('<tr>') == 19  # One milestone, sixteen candidates, two headers.
    assert '<td>16</td>' in summary
    assert render_objective_summaries({'responses':[{**source,'isError':True} for source in sources]}) == ''
