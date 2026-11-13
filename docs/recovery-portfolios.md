# Recovery portfolios and trace comparisons

These two read-only MCP tools extend recovery analysis from one policy comparison to cross-scenario decisions and incident-level evidence review. Hardened tool names have the usual `sim_` prefix. Both tools remain available in compact catalogs, enforce nested scenario permissions, and leave records and receipts unchanged.

## Cross-scenario policy evaluation

`evaluate_recovery_portfolio` accepts:

| Argument | Contract |
|---|---|
| `scenarios` | 2–8 objects with a unique `label` and a full `simulate_recovery_resilience` argument object as `scenario` |
| `strategies` | 2–8 uniquely labeled policies with `max_parallel`, `max_attempts`, and `retry_backoff_ms`, as in `compare_recovery_strategies` |
| `deadline_ms` | Inclusive whole-recovery deadline, 0–1,000,000 simulated milliseconds |
| `max_worker_busy_ms` | Inclusive total attempt-work budget, 0–1,000,000 worker-milliseconds |

Labels use 1–40 ASCII letters, digits, underscores, or hyphens. All scenarios must target the same incident. Durations and faults must belong to its prerequisite closure. The original scenario must be valid; each outage worker must also exist in every selected policy. No invalid cell is silently omitted.

Policies replace the scenario's worker, retry, and backoff settings. Each cell uses the scenario's durations, faults, and outage windows and the same frozen record snapshot. There are at most 64 simulations. Results are sorted by policy label and scenario label, independently of input order.

Each cell reports completion, elapsed time, attempt/retry counts, unfinished incidents, busy worker-time, deadline compliance, and budget compliance. A cell is **eligible** only when recovery completes by the deadline within the work budget. A failed recovery can remain within budget, but is never eligible.

`robust_strategy` is a policy eligible in every supplied scenario. Among qualifying policies, selection minimizes worst elapsed time, worst busy worker-time, total attempts across scenarios, and finally label. If none qualify, it is `null`. Worst elapsed time for a policy is `null` if any scenario is unfinished; a fast failure cannot reduce its worst-case completion time. Empty, fully resolved workloads have zero work and time, and ties use label order.

`pareto_strategies` contains policies not strictly dominated on all four dimensions: maximize eligible scenarios and completed scenarios; minimize worst elapsed time (unfinished is treated as infinity) and worst busy worker-time. Tied policies both remain. A fragile policy can remain on this frontier by spending less work while failing more scenarios. Frontier membership alone is not a recommendation: inspect feasibility or `robust_strategy`.

These are deterministic supplied scenarios, with equal counting rather than probability weights. Results do not estimate outage likelihood or promise a globally optimal policy. Busy time includes successful, retried, and exhausted attempts; it excludes idle workers and backoff waiting.

## Audited trace differences

`compare_recovery_traces` takes `baseline` and `candidate`, each containing `scenario` and `trace`, plus `deadline_ms`. Both scenarios must target the same incident. Both traces must pass the independent legality audit against the same current snapshot. Policies, disruptions, durations, and legal schedules may differ. Invalid or stale evidence on either side returns a tool error before differences are calculated.

Per-incident completion time is zero for an incident already resolved in the snapshot, the successful resolution event's end time for recovered work, or `null` for unfinished work.

| Change | Meaning |
|---|---|
| `improved` / `regressed` | Both completed; candidate completed sooner / later |
| `unchanged` | Both have the same completion time |
| `recovered` | Only candidate completed |
| `lost` | Only baseline completed |
| `unfinished` | Neither completed |

Each incident includes both completion times and deadline outcomes. Signed deltas mean candidate minus baseline. Incident time deltas are `null` unless both times exist. Whole-recovery elapsed delta is `null` unless both complete. Busy time, attempt/retry counts, and unfinished counts still have signed deltas; a negative busy-time delta alone does not demonstrate improvement. These differences describe evidence and do not establish causation.

## Recorded report summaries

The report inspector shows a **Recorded recovery policy matrix** for portfolio responses and **Recorded recovery changes** for comparisons. Per-incident completion details are expandable. Native comparison checks retain both traces, so the existing timeline selector can inspect either one. Campaign rows retain all simulation witnesses and full raw evidence. Opening the report never reruns a simulation or audit; summaries describe the saved responses.

## Replayable stress profile

`--campaign-portfolio-stress` adds `portfolio` actions to version-2 graph manifests. It combines nominal and disrupted scenarios with fragile, resilient, and patient policies, overlapping worker outages, retry exhaustion, budget limits, and completed-state ties. The action runner separately requests each simulation witness and a comparison between the first two policies of the first scenario (labels sorted). An independent oracle audits all witnesses and reconstructs matrix metrics, selection, frontier, and incident differences without invoking the production analysis functions.

Checkpoint restore rechecks these responses even when the checkpoint envelope has been rehashed. Manifest validation rejects ambiguous labels, mismatched or out-of-graph targets, out-of-closure overrides, invalid outages, and oversized inputs before fixture creation.

```powershell
& .\.venv\Scripts\python.exe tests\eval_matrix.py --suite all --protocol-only --transport all --campaign-graph-nodes 32 --campaign-graph-width 4 --campaign-steps 100 --parallel-calls 24 --distractors 60 --campaign-race-topology mixed --campaign-root-churn --campaign-outage-stress --campaign-timeline-stress --campaign-resilience-stress --campaign-strategy-stress --campaign-analysis-stress --campaign-utilization-stress --campaign-portfolio-stress --output runs\portfolio-chaos
```

Run focused verification with `python -m pytest tests/test_recovery_portfolio.py tests/test_reporting.py -q` in the project's Python environment. Coverage includes 8/32/128-node graph witnesses, the full 8×8 bound, policy ties and dominance, failed-fast comparisons, stale/forged traces on either side, both server modes and all transports, compact catalogs, nested authority, replay/resume, and rehashed checkpoint corruption. The tools use the existing structured-result and tool-error conventions described in the [MCP tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools).
