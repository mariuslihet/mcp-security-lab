# Weighted recovery objectives and capacity search

These read-only MCP tools express incident priorities and find a qualifying worker pool among supplied options. Hardened names have the `sim_` prefix. Both are available in compact catalogs, enforce the full prerequisite closure's authority checks, and leave records and receipts unchanged.

## Evaluate recorded recovery objectives

`evaluate_recovery_objectives` takes:

| Argument | Contract |
|---|---|
| `scenario`, `trace` | Same evidence pair as `validate_recovery_trace`; audited against current records before scoring |
| `weights` | 1–128 distinct closure incidents, each with `record_id` and positive integer `weight` from 1 to 1000 |
| `milestones` | 1–16 distinct `at_ms` values, each with integer `required_basis_points` from 0 to 10000 |
| `horizon_ms` | Observation window end, 0–1,000,000 simulated milliseconds; all milestones must lie within it |

Weights apply only to explicitly listed targets. Unlisted prerequisites still participate in scheduling and authorization but do not enter the weighted denominator. Weights represent chosen priorities, not probabilities. Duplicate targets, duplicate milestone times, zero weights, out-of-closure targets, and out-of-window milestones are rejected. Lists are sorted in the output without mutating inputs.

A target initially resolved completes at time zero. Otherwise its completion is the successful resolution event's end time, or `null` if it remains unfinished. A completion at exactly a milestone counts as covered.

At time `t`, covered weight is the sum of weights whose targets completed by `t`. Coverage is `floor(10000 * covered_weight / total_weight)`. A milestone is met when coverage is at least its required basis points. The implementation uses exact integer arithmetic rather than floating-point rounding.

`unresolved_weight_ms` integrates unresolved target weight over `[0, horizon_ms)`. Equivalently, each target contributes `weight * min(completion_ms, horizon_ms)`; unfinished targets contribute their weight for the entire window. Work remains unresolved after a failed simulator run stops, so an early failure does not erase its remaining burden.

`time_coverage_basis_points` is the floor of `10000 * (1 - unresolved_weight_ms / (total_weight * horizon_ms))`, or `null` for a zero horizon. `horizon_coverage_basis_points` is the instantaneous coverage at the window end; a completion exactly at the horizon affects that endpoint but contributes no positive recovered interval before it. The result also includes per-target completion times and all milestone outcomes.

`all_targets_completed` describes eventual completion of the selected targets in the trace, while `global_completed` describes the entire prerequisite closure. Both can differ from coverage at a finite horizon. The report labels these distinctions explicitly.

For example, target A with weight 1 completing at 2 ms and target B with weight 2 completing at 5 ms produce 3333 basis points at 2 ms and 10000 at 5 ms. Over a 5 ms horizon the unresolved burden is `1*2 + 2*5 = 12` weight-ms, and time-weighted coverage is 2000 basis points.

## Search worker capacity

`search_recovery_capacity` takes the same `scenario`, `weights`, `milestones`, and `horizon_ms`, plus:

| Argument | Contract |
|---|---|
| `worker_options` | 1–16 distinct worker counts from 1 to 16 |
| `require_complete` | Explicit boolean: require the entire recovery to finish, in addition to weighted objectives |
| `max_worker_busy_ms` | Inclusive budget from 0 to 1,000,000 worker-ms, including all successful and failed attempts in the closure |
| `max_unresolved_weight_ms` | Inclusive weighted-burden budget from 0 to 128,000,000,000 weight-ms |

The original scenario must be valid. Every outage worker must exist in every tested option; invalid options are rejected rather than silently skipped. Each candidate changes only `max_parallel`. Durations, faults, retry limits, backoff, and worker outage identities/windows remain fixed on one frozen snapshot.

Every option is simulated. Results include completion, elapsed time, busy time, attempt count, weighted burden, horizon coverage, milestone compliance, budget compliance, and combined feasibility. The recommendation is the smallest supplied worker count meeting all requested constraints, or `null`. If `require_complete=false`, successful critical targets may qualify even while other incidents remain unfinished; the candidate's whole-recovery completion flag remains visible. If true, whole-recovery completion is required, but its completion is not implicitly required by the observation horizon unless the chosen milestones enforce that.

More workers are not assumed to improve the outcome. Dispatch changes can move an attempt into a fixed worker outage and exhaust its retry budget. Tests include a concrete case where one worker completes and two workers fail. The search therefore enumerates every supplied option instead of stopping early or using a monotonic binary search. It does not claim optimality outside those options or optimize retry/backoff policies.

## Inspection and stress campaigns

The report inspector shows **Recorded weighted recovery objectives** and **Recorded worker capacity search**. It displays all milestones and capacity candidates, with whole-recovery completion and budget outcomes separate from weighted milestone success. These summaries describe saved evidence; opening a report does not rerun the audit or call a server.

`--campaign-objectives-stress` adds version-2 `objectives` actions. They exercise weighted root/terminal priorities, outages, retry work, partial recovery, and completed-state minimum-pool selection. Each action separately requests every simulation witness and evaluates the first candidate's trace through the objective tool. A verifier audits these traces, independently integrates unresolved weight across event windows, and checks output schemas, milestone metrics, budgets, and the selected pool. Checkpoints repeat verification even after rehashed metric, selection, type, or trace tampering.

```powershell
& .\.venv\Scripts\python.exe tests\eval_matrix.py --suite all --protocol-only --transport all --campaign-graph-nodes 64 --campaign-graph-width 8 --campaign-steps 120 --parallel-calls 32 --distractors 80 --campaign-race-topology mixed --campaign-root-churn --campaign-outage-stress --campaign-timeline-stress --campaign-resilience-stress --campaign-strategy-stress --campaign-analysis-stress --campaign-utilization-stress --campaign-portfolio-stress --campaign-diagnostics-stress --campaign-objectives-stress --output runs\weighted-objectives-chaos
```

`tests/test_recovery_objectives.py` checks hand-calculated weighted metrics, exact threshold/budget boundaries, unfinished weight after early failure, partial critical-target success, zero horizons, all 16 options, nonmonotonic outcomes, whole-valued JSON numbers, ordering invariance, generated 8/32/128-node workloads, both server modes on all transports, compact calls, authority, invalid inputs, replay/resume, and rehashed checkpoint corruption. Reporting tests cover partial/global distinctions, zero-horizon text, safe evidence rendering, type rejection, and display of every candidate.
