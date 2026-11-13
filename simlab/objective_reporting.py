"""Escaped summaries of recorded weighted objectives and capacity candidates."""
from html import escape

from jsonschema import Draft202012Validator

from .recovery_objectives import OBJECTIVES_OUTPUT, CAPACITY_OUTPUT


def safe(value):
    return escape(str(value),quote=True)


def render_objective_summaries(row):
    responses = row.get("responses",[])
    sources = [row.get("response"),*(responses if isinstance(responses,list) else [])]
    parts,seen = [],set()
    for response in sources:
        if not isinstance(response,dict) or response.get("isError"):
            continue
        value = response.get("structuredContent")
        if not isinstance(value,dict):
            continue
        if 'all_milestones_met' in value and 'objectives' not in seen and Draft202012Validator(OBJECTIVES_OUTPUT).is_valid(value):
            seen.add('objectives')
            rows = ''.join('<tr>'+''.join(f'<td>{safe(item)}</td>' for item in (
                goal['at_ms'],f'{goal["required_basis_points"]/100:.2f}%',f'{goal["coverage_basis_points"]/100:.2f}%',
                goal['covered_weight'],'Yes' if goal['met'] else 'No'))+'</tr>' for goal in value['milestones'])
            coverage = 'No observation interval' if value['time_coverage_basis_points'] is None else f'{value["time_coverage_basis_points"]/100:.2f}%'
            parts.append('<section class="recovery-objectives"><h3>Recorded weighted recovery objectives</h3>'
                f'<p>Unresolved burden: {value["unresolved_weight_ms"]} weight-ms over {value["horizon_ms"]} simulated ms. '
                f'Time-weighted coverage: {safe(coverage)}.</p><p class="helper">'
                f'{len(value["targets"])} weighted targets · total weight {value["total_weight"]} · '
                f'All targets eventually completed: {"Yes" if value["all_targets_completed"] else "No"} · '
                f'Whole recovery completed: {"Yes" if value["global_completed"] else "No"}. Weights express priorities, not probabilities.</p>'
                '<div class="scroll" tabindex="0" role="region" aria-label="Weighted recovery milestones"><table>'
                '<caption>Recorded weighted coverage at milestones</caption><thead><tr><th scope="col">Time ms</th>'
                '<th scope="col">Required coverage</th><th scope="col">Observed coverage</th><th scope="col">Covered weight</th>'
                f'<th scope="col">Met</th></tr></thead><tbody>{rows}</tbody></table></div></section>')
        if 'recommended_workers' in value and 'capacity' not in seen and Draft202012Validator(CAPACITY_OUTPUT).is_valid(value):
            seen.add('capacity')
            winner = 'None meets the supplied constraints' if value['recommended_workers'] is None else str(value['recommended_workers'])
            rows = ''.join('<tr>'+''.join(f'<td>{safe(item)}</td>' for item in (
                candidate['workers'],'Yes' if candidate['completed'] else 'No',candidate['elapsed_ms'],candidate['worker_busy_ms'],
                candidate['unresolved_weight_ms'],'Yes' if candidate['objectives_met'] else 'No',
                'Yes' if candidate['busy_budget_met'] and candidate['burden_budget_met'] else 'No',
                'Yes' if candidate['feasible'] else 'No'))+'</tr>' for candidate in value['candidates'])
            parts.append('<section class="recovery-capacity"><h3>Recorded worker capacity search</h3>'
                f'<p>Smallest qualifying tested pool: <b>{safe(winner)}</b>.</p><p class="helper">'
                f'Whole recovery required: {"Yes" if value["require_complete"] else "No"} · '
                f'Busy-time budget: {value["max_worker_busy_ms"]} worker-ms · '
                f'Unresolved-burden budget: {value["max_unresolved_weight_ms"]} weight-ms. '
                'All supplied options were evaluated; more workers need not improve the schedule.</p>'
                '<div class="scroll" tabindex="0" role="region" aria-label="Recovery worker capacity candidates"><table>'
                '<caption>Recorded capacity candidates · simulated time</caption><thead><tr><th scope="col">Workers</th>'
                '<th scope="col">Completed</th><th scope="col">Elapsed ms</th><th scope="col">Busy worker-ms</th>'
                '<th scope="col">Unresolved weight-ms</th><th scope="col">Milestones met</th><th scope="col">Budgets met</th>'
                f'<th scope="col">Qualifies</th></tr></thead><tbody>{rows}</tbody></table></div></section>')
    return ''.join(parts)
