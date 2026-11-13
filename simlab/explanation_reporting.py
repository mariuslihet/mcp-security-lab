"""Bounded, escaped presentation of recorded recovery explanation responses."""
from html import escape

from jsonschema import Draft202012Validator

from .recovery_explanations import WAITS_OUTPUT, FAILURES_OUTPUT


def safe(value):
    return escape(str(value), quote=True)


def render_explanation_summaries(row):
    responses = row.get("responses", [])
    sources = [row.get("response"), *(responses if isinstance(responses, list) else [])]
    parts, seen = [], set()
    for response in sources:
        if not isinstance(response, dict) or response.get("isError"):
            continue
        value = response.get("structuredContent")
        if not isinstance(value, dict):
            continue
        if "record_totals" in value and "waits" not in seen and Draft202012Validator(WAITS_OUTPUT).is_valid(value):
            seen.add("waits")
            total = value["totals"]
            rows = ''.join('<tr>' + ''.join(f'<td>{safe(item)}</td>' for item in (
                event["record_id"], event["status"], event["attempt"], event["ready_ms"], event["start_ms"],
                event["outage_wait_ms"], event["busy_wait_ms"], event["dispatch_gap_ms"])) + '</tr>' for event in value["attempts"][:100])
            parts.append('<section class="recovery-waits"><h3>Recorded ready-to-dispatch waits</h3>'
                f'<p>{total["waiting_ms"]} task-ms waiting: {total["outage_wait_ms"]} all workers unavailable, '
                f'{total["busy_wait_ms"]} available workers busy, {total["dispatch_gap_ms"]} free-worker dispatch gaps.</p>'
                f'<p class="helper">Required retry backoff: {total["required_backoff_ms"]} task-ms, reported separately. '
                'Waiting starts after prerequisites and backoff are satisfied. Task waits may overlap; these are not worker-capacity totals.</p>'
                f'<details><summary>Attempt readiness and waits · first {min(100,len(value["attempts"]))} of {len(value["attempts"])}</summary>'
                '<p class="helper">All attempt details remain in the full recorded evidence.</p>'
                '<div class="scroll" tabindex="0" role="region" aria-label="Attempt waiting explanations"><table>'
                '<caption>Recorded attempt waits · simulated milliseconds</caption><thead><tr>'
                '<th scope="col">Incident</th><th scope="col">Phase</th><th scope="col">Attempt</th>'
                '<th scope="col">Ready</th><th scope="col">Start</th><th scope="col">Unavailable</th>'
                f'<th scope="col">Busy</th><th scope="col">Dispatch gap</th></tr></thead><tbody>{rows}</tbody></table></div></details></section>')
        if "roots" in value and "failures" not in seen and Draft202012Validator(FAILURES_OUTPUT).is_valid(value):
            seen.add("failures")
            roots = ''.join('<tr>' + ''.join(f'<td>{safe(item)}</td>' for item in (
                root["record_id"], root["status"], root["reason"], root["stopped_ms"], root["affected_record_count"]))
                + '</tr>' for root in value["roots"])
            targets = []
            for target in value["targets"][:20]:
                paths = ''.join('<li>' + safe(' → '.join(f'{task["record_id"]} / {task["status"]}' for task in cause["path"]))
                                + '</li>' for cause in target["causes"])
                targets.append(f'<details><summary>{safe(target["record_id"])} · {target["cause_count"]} exhausted roots'
                    f'{" · causes truncated" if target["truncated"] else ""}</summary><ol>{paths}</ol></details>')
            parts.append('<section class="recovery-failures"><h3>Recorded failure propagation</h3>'
                f'<p>{len(value["roots"])} exhausted roots · {len(value["targets"])} unfinished incidents.</p>'
                '<p class="helper">Paths follow recorded failed and blocked phase/dependency edges. They describe this simulated trace.</p>'
                '<div class="scroll" tabindex="0" role="region" aria-label="Exhausted recovery roots"><table>'
                '<caption>Recorded exhausted attempts and downstream impact</caption><thead><tr>'
                '<th scope="col">Incident</th><th scope="col">Phase</th><th scope="col">Final reason</th>'
                f'<th scope="col">Stopped ms</th><th scope="col">Affected incidents</th></tr></thead><tbody>{roots}</tbody></table></div>'
                f'<p class="helper">Showing the first {min(20,len(value["targets"]))} of {len(value["targets"])} incident explanations. '
                'All returned paths and truncation counts remain in the full evidence.</p>' + ''.join(targets) + '</section>')
    return ''.join(parts)
