"""Portable report exports and the self-contained experiment dashboard."""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from .dashboard import render_dashboard
from .performance import collect_protocol_metrics


def write_html_report(report: dict, destination: Path) -> None:
    render_dashboard(report, destination)


def write_reports(report: dict, directory: Path) -> None:
    """Replace each report atomically so readers never observe half a file."""
    def save(name, content):
        temporary = directory / (name + ".tmp")
        temporary.write_text(content, encoding="utf-8")
        temporary.replace(directory / name)

    summary = report["summary"]
    report["performance"] = collect_protocol_metrics(report["rows"], directory)
    save("performance.json", json.dumps(report["performance"], indent=2))
    performance_output = io.StringIO(newline="")
    performance_columns = ["capability", "method", "tool", "mode", "transport", "direction", "requests", "completed", "pending",
                           "cancelled", "tool_errors", "rpc_errors", "p50_ms", "p95_ms", "max_ms", "logical_bytes"]
    performance_writer = csv.DictWriter(performance_output, fieldnames=performance_columns)
    performance_writer.writeheader()
    for operation in report["performance"]["operations"]:
        performance_writer.writerow({key: "'" + value if isinstance(value := operation.get(key, ""), str)
            and value.startswith(("=", "+", "-", "@", "\t", "\r")) else value for key in performance_columns})
    save("performance.csv", performance_output.getvalue())
    save("report.json", json.dumps(report, indent=2))
    markdown = ["# MCP simulation evaluation", "", f'Run status: {report["status"]}', "",
                "```json", json.dumps(summary, indent=2), "```", "",
                "| Evaluation | Transport | Server | Case | Seed | Task | Result |", "|---|---|---|---|---|---|---|"]
    markdown += [f"| {r['evaluation']} | {r.get('transport', '')} | {r.get('mode', '')} | {r['case']} | {r.get('seed', '')} | {r.get('task', {}).get('status', '')} | {'PASS' if r['passed'] else 'FAIL'} |" for r in report["rows"]]
    markdown += ["", *report["methodology"]]
    markdown += ["", "Request timing and logical message-volume metrics: performance.json and performance.csv.",
                 "Timings include deliberate simulation delays and error responses; they are not production benchmarks."]
    save("report.md", "\n".join(markdown) + "\n")
    output = io.StringIO(newline="")
    columns = ["evaluation", "transport", "mode", "case", "seed", "passed", "exploit_observed", "task_status", "error"]
    writer = csv.DictWriter(output, fieldnames=columns)
    writer.writeheader()
    for row in report["rows"]:
        values = {key: row.get(key, "") for key in columns}
        values["task_status"] = row.get("task", {}).get("status", "")
        # Treat free text as data when opened in spreadsheet applications.
        values = {key: "'" + value if isinstance(value, str) and value.startswith(("=", "+", "-", "@", "\t", "\r")) else value
                  for key, value in values.items()}
        writer.writerow(values)
    save("results.csv", output.getvalue())
    temporary = directory / "report.html.tmp"
    write_html_report(report, temporary)
    temporary.replace(directory / "report.html")
