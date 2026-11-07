"""Render a dependency-free dashboard from saved evidence, without rerunning actors."""
from __future__ import annotations

import json
import re
import hashlib
from collections import Counter
from html import escape
from pathlib import Path
from urllib.parse import quote

from .grading import compare_cases


def safe(value) -> str:
    return escape(str(value), quote=True)


def percent(value) -> str:
    return "Not run" if value is None else f"{value * 100:.1f}".rstrip("0").rstrip(".") + "%"


def evidence_links(row: dict, directory: Path) -> str:
    links = []
    for key in ("audit", "actors", "effects"):
        if row.get(key):
            try:
                relative = Path(row[key]).resolve().relative_to(directory.resolve()).as_posix()
            except ValueError:
                continue
            links.append(f'<a href="{safe(quote(relative))}">{safe(key)} ↗</a>')
    return "".join(links)


def render_dashboard(report: dict, destination: Path) -> None:
    summary, rows = report["summary"], report["rows"]
    live = [row for row in rows if row.get("evaluation") == "llm"]
    protocol = [row for row in rows if row.get("evaluation") == "protocol"]
    passed = sum(bool(row["passed"]) for row in rows)
    failed = len(rows) - passed
    baseline = [row for row in live if row.get("mode") == "vulnerable" and "exploit_observed" in row]
    hardened = [row for row in live if row.get("mode") == "hardened" and "exploit_observed" in row]
    experiment = report.get("experiment", {})
    comparisons = report.get("comparisons", compare_cases(rows))
    seeds = sorted({row["seed"] for row in live if "seed" in row})
    cards = [
        ("Checks passed", f"{passed}<small> / {len(rows)}</small>", f"{failed} assertions need attention", "mint"),
        ("Baseline exploit effects", percent(summary.get("llm_baseline_exploit_rate")),
         f'{sum(r["exploit_observed"] for r in baseline)} effects / {len(baseline)} evaluated', "amber"),
        ("Hardened bypasses", percent(summary.get("llm_hardened_bypass_rate")),
         f'{sum(r["exploit_observed"] for r in hardened)} effects / {len(hardened)} evaluated', "blue"),
        ("Hardened task completion", percent(summary.get("llm_hardened_task_completion_rate")),
         f'{sum(r.get("task", {}).get("completed", False) for r in hardened)} completed / {sum("task" in r for r in hardened)} graded', "violet"),
    ]
    tiles = "".join(f'<article class="metric {color}"><span>{safe(label)}</span><strong>{value}</strong><p>{safe(note)}</p></article>'
                    for label, value, note, color in cards)
    chart_rows, comparison_rows = [], []
    for group in comparisons:
        bars, arm_text = [], []
        for mode, label in (("vulnerable", "Baseline"), ("hardened", "Hardened")):
            arm = group[mode]
            rate = arm["exploit_rate"]
            width = max(0, min(100, (rate or 0) * 100))
            bars.append(f'<div class="bar-row"><span>{label}</span><div class="track" aria-hidden="true">'
                        f'<i class="{mode}" style="width:{width:.2f}%"></i></div>'
                        f'<b>{arm["exploits"]}/{arm["evaluated"]}</b></div>')
            arm_text.append(f'{arm["exploits"]}/{arm["evaluated"]} · {percent(rate)}'
                            f' · {arm["errors"]} errors · {arm["tasks_completed"]} completed tasks')
        chart_rows.append(f'<article class="case-chart"><div class="case-heading"><h3>{safe(group["case"].replace("_", " "))}</h3>'
                          f'<span class="tag">{safe(group["transport"])}</span></div>{"".join(bars)}'
                          f'<a href="#evidence" class="case-jump" data-case="{safe(group["case"])}" '
                          f'data-transport="{safe(group["transport"])}">Explore these checks →</a></article>')
        comparison_rows.append(f'<tr><th scope="row">{safe(group["case"])}</th><td>{safe(group["transport"])}</td>'
                               f'<td>{safe(", ".join(map(str, group["seeds"])))}</td><td>{safe(arm_text[0])}</td>'
                               f'<td>{safe(arm_text[1])}</td><td>{group["prevented_pairs"]}/{group["exploitable_pairs"]}</td></tr>')

    outcomes = []
    for mode, label in (("vulnerable", "Baseline"), ("hardened", "Hardened")):
        arm = [row for row in live if row.get("mode") == mode]
        counts = Counter("model_error" if "error" in row else row.get("task", {}).get("status", "ungraded") for row in arm)
        segments, legend = [], []
        for status, title in (("completed", "Completed"), ("safely_blocked", "Safely blocked"),
                              ("incomplete", "Incomplete"), ("model_error", "Model error"), ("ungraded", "Ungraded")):
            if counts[status]:
                segments.append(f'<i class="{status}" style="width:{100 * counts[status] / len(arm):.2f}%"></i>')
                legend.append(f'<span><i class="dot {status}"></i>{title} <b>{counts[status]}</b></span>')
        outcomes.append(f'<div class="outcome"><h3>{label} <small>{len(arm)} attempts</small></h3>'
                        f'<div class="stack" aria-hidden="true">{"".join(segments)}</div>'
                        f'<div class="legend">{"".join(legend) or "No actor attempts recorded"}</div></div>')

    matrix = []
    for transport in sorted({row.get("transport", "") for row in live}):
        for seed in seeds:
            group = [row for row in live if row.get("transport") == transport and row.get("seed") == seed]
            if not group:
                continue
            cells = []
            for mode in ("vulnerable", "hardened"):
                arm = [row for row in group if row.get("mode") == mode]
                evaluated = [row for row in arm if "exploit_observed" in row]
                effects = sum(row["exploit_observed"] for row in evaluated)
                cells.append(f'<td><b>{effects}/{len(evaluated)}</b> effects <span class="muted">· '
                             f'{sum("error" in row for row in arm)} errors</span></td>')
            graded = [row for row in group if row.get("mode") == "hardened" and "task" in row]
            matrix.append(f'<tr><th scope="row">Seed {safe(seed)}</th><td>{safe(transport)}</td>{"".join(cells)}'
                          f'<td>{sum(row["task"]["completed"] for row in graded)}/{len(graded)} completed</td></tr>')

    table_rows, templates = [], []
    for index, row in enumerate(rows):
        status = "pass" if row["passed"] else "fail"
        task = row.get("task", {})
        fields = {"evaluation": row["evaluation"], "transport": row.get("transport", ""),
                  "mode": row.get("mode", ""), "case": row["case"], "seed": str(row.get("seed", "")),
                  "outcome": task.get("status", "ungraded"), "result": status,
                  "tools": " ".join(call["tool"] for call in row.get("deputy", {}).get("calls", []))}
        attributes = " ".join(f'data-{key}="{safe(value)}"' for key, value in fields.items())
        label = " / ".join(str(value) for value in (row["case"], row.get("mode", ""), row.get("transport", ""), row.get("seed", "")) if value != "")
        table_rows.append(f'<tr {attributes} data-index="{index}"><td>{safe(row["case"])}</td>'
                          f'<td>{safe(row["evaluation"])}</td><td>{safe(row.get("transport", "—"))}</td>'
                          f'<td>{safe(row.get("mode", "—"))}</td><td>{safe(row.get("seed", "—"))}</td>'
                          f'<td>{safe(task.get("status", "—"))}</td><td><span class="badge {status}">{status.upper()}</span></td>'
                          f'<td><div class="actions"><button class="inspect" data-evidence="evidence-{index}" aria-label="Inspect {safe(label)}">Inspect ↗</button>'
                          f'<button class="pin-check" data-index="{index}" aria-label="Pin {safe(label)}" aria-pressed="false">Pin</button></div></td></tr>')
        deputy = row.get("deputy", {})
        steps = []
        for call in deputy.get("calls", []):
            rejected = call["result"].get("isError", False)
            steps.append(f'<li><div><b>{safe(call["tool"])}</b><span class="badge {"fail" if rejected else "pass"}">'
                         f'{"ERROR / BLOCK" if rejected else "OBSERVED"}</span></div><pre>{safe(json.dumps(call["arguments"], indent=2))}</pre>'
                         f'<details><summary>Tool response</summary><pre>{safe(json.dumps(call["result"], indent=2))}</pre></details></li>')
        checks = "".join(f'<li><span class="badge {"pass" if value else "fail"}">{"PASS" if value else "FAIL"}</span> {safe(key.replace("_", " "))}</li>'
                         for key, value in task.get("checks", {}).items())
        rubric = f'<h3>Task rubric · {safe(task.get("status", "ungraded"))}</h3><ul class="rubric">{checks}</ul><p class="muted">{safe(task.get("limitation", ""))}</p>' if task else ""
        answer = f'<h3>Deputy answer</h3><p class="answer">{safe(deputy.get("answer", ""))}</p>' if deputy else ""
        error = f'<p class="error-box">{safe(row["error"])}</p>' if "error" in row else ""
        templates.append(f'<template id="evidence-{index}"><h2>{safe(label)}</h2>{error}'
                         f'<div class="evidence-links">{evidence_links(row, destination.parent)}</div>'
                         f'<p class="answer">{safe(row.get("intent", "Fixed protocol probe; inspect the recorded arguments and response below."))}</p>'
                         f'{rubric}{answer}<h3>Tool-call sequence</h3><ol class="sequence">{"".join(steps)}</ol>'
                         f'{"" if steps else "<p class=muted>No deputy tool-call sequence for this check.</p>"}'
                         f'<details><summary>Full recorded evidence</summary><pre>{safe(json.dumps(row, indent=2, ensure_ascii=True))}</pre></details></template>')

    def options(key):
        values = sorted({str(row.get(key, "")) for row in rows if key in row and row[key] != ""})
        return "".join(f'<option value="{safe(value)}">{safe(value)}</option>' for value in values)

    notices = []
    if failed:
        notices.append(f'<li><b>{failed} failed assertions.</b> Baseline refusals remain failures of the exploit assertion; inspect the matching evidence.</li>')
    if summary.get("llm_errors"):
        notices.append(f'<li><b>{summary["llm_errors"]} model/infrastructure errors.</b> These are excluded from exploit-rate denominators.</li>')
    if not live:
        notices.append('<li>No live actor outcomes recorded. Protocol probes do not measure model behavior.</li>')
    if not notices:
        notices.append('<li>No failed assertions in the recorded checks. These outcomes describe this experiment only.</li>')
    config = {"Backend": report["model"].get("backend", "Not recorded"),
              "Model": report["model"]["model"], "Seeds": ", ".join(map(str, experiment.get("seeds", seeds))) or "Not run",
              "Turn budget": experiment.get("max_turns", "Not recorded"),
              "Task requirement": "Strict completion" if experiment.get("require_task_success") else "Reported separately",
              "Started (UTC)": report.get("started_at", "Not recorded"), "Saved (UTC)": report.get("updated_at", "Not recorded")}
    # Embed only the comparison fields, never duplicate prompts or secrets in script data.
    comparison_data = {"schema_version": report.get("schema_version", 2), "model": report["model"],
                       "experiment": experiment, "rows": []}
    for row in rows:
        compact = {key: row[key] for key in ("case", "evaluation", "mode", "transport", "seed", "passed", "exploit_observed") if key in row}
        if "task" in row:
            compact["task"] = {"completed": row["task"].get("completed", False)}
        if "error" in row:
            compact["error"] = True
        comparison_data["rows"].append(compact)
    encoded_data = json.dumps(comparison_data, ensure_ascii=True).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    slots = {"CARDS": tiles, "MODEL": safe(report["model"]["model"]), "ROWS": "".join(table_rows),
             "RUN_DATA": encoded_data, "RUN_KEY": hashlib.sha256(encoded_data.encode()).hexdigest()[:20],
             "SCRIPT": Path(__file__).with_name("dashboard.js").read_text(encoding="utf-8"),
             "DATA_SCRIPT": Path(__file__).with_name("dashboard-data.js").read_text(encoding="utf-8"),
             "TEMPLATES": "".join(templates), "CHARTS": "".join(chart_rows) or '<p class="empty">No live case comparisons yet.</p>',
             "COMPARISONS": "".join(comparison_rows), "OUTCOMES": "".join(outcomes),
             "MATRIX": "".join(matrix) or '<tr><td colspan="5">No seed outcomes recorded.</td></tr>',
             "METHOD": "".join(f'<li>{safe(item)}</li>' for item in report["methodology"]),
             "STATUS": safe(report.get("status", "completed")),
             "PROGRESS": "Partial results; reload to see saved progress." if report.get("status") == "running" else "Evaluation finished. This is a saved snapshot.",
             "CONFIG": "".join(f'<div><dt>{safe(key)}</dt><dd>{safe(value)}</dd></div>' for key, value in config.items()),
             "NOTICES": "".join(notices), "TOTAL": str(len(rows)), "PASSED": str(passed), "FAILED": str(failed),
             "DONUT": f'{100 * passed / len(rows):.2f}' if rows else "0",
             "PROTOCOL": f'{sum(row["passed"] for row in protocol)}/{len(protocol)}',
             "NEUTRALIZATION": percent(summary.get("protocol_attack_neutralization_rate")),
             "BENIGN": percent(summary.get("protocol_benign_pass_rate")),
             "LIVECOUNT": str(len(live)), "CASECOUNT": str(len({row["case"] for row in live})),
             "SEEDCOUNT": str(len(seeds)), "LIVEERRORS": str(summary.get("llm_errors", 0)),
             "EVALUATION_OPTIONS": options("evaluation"), "TRANSPORT_OPTIONS": options("transport"),
             "MODE_OPTIONS": options("mode"), "SEED_OPTIONS": options("seed"), "CASE_OPTIONS": options("case")}
    template = Path(__file__).with_name("dashboard.html").read_text(encoding="utf-8")
    # Substitute exactly once; evidence cannot introduce new template directives.
    destination.write_text(re.sub(r"__([A-Z_]+)__", lambda match: slots[match[1]], template), encoding="utf-8")
