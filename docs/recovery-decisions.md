# Recovery strategy comparisons and deadline evaluation

Dense MCP servers expose two more read-only tools. Hardened names have the `sim_` prefix. Both use the existing recovery scenario schema and validate the complete authorized prerequisite closure. They remain available in compact catalog mode.

## compare_recovery_strategies

Supply a `scenario`, a shared `deadline_ms` (0–1000000), and 2–8 strategies. Each strategy has a distinct label and explicitly sets `max_parallel` (1–16), `max_attempts` (1–4), and `retry_backoff_ms` (0–1000).

Labels contain 1–40 ASCII letters, digits, underscores, or hyphens.

```json
{"scenario":{"record_id":"GR-003","max_parallel":3,"max_attempts":3,"retry_backoff_ms":1,
 "durations":[],"faults":[{"record_id":"GR-000","status":"investigating","failed_attempts":1}],"worker_outages":[]},
 "deadline_ms":100,"strategies":[
 {"label":"fragile","max_parallel":1,"max_attempts":1,"retry_backoff_ms":0},
 {"label":"resilient","max_parallel":3,"max_attempts":3,"retry_backoff_ms":1}]}
```

Every candidate starts from the same frozen record snapshot. Durations, faults, outages, and target remain identical; only the three strategy fields change. An outage worker must exist in every candidate, so incompatible worker counts are rejected rather than silently dropping outages.

Results include completion, elapsed logical time, attempt/retry counts, unfinished incident count, deadline success, and aggregate worker busy time. Busy time sums attempt intervals across workers and can exceed elapsed time. A failed recovery never meets the overall deadline, even if it terminates quickly.

`best_strategy` selects the fastest completed candidate, then fewer attempts, then lexical label order. It is null if none complete. It compares only the supplied candidates and does not claim a globally optimal policy. Strategy summaries retain input order; winner selection is independent of input order. Already completed closures produce zero elapsed time and zero attempts.

## evaluate_recovery_deadlines

Supply a `scenario`, its `trace`, and 1–128 distinct `deadlines` entries containing `record_id` and `deadline_ms` (0–1000000). Every target must be in the scenario's prerequisite closure.

The tool audits the trace against current snapshots before scoring it. Forged or stale evidence produces a `recovery_trace_invalid` tool error. It does not turn invalid evidence into a claimed deadline result. Scope and argument errors also produce tool errors.

Each requested incident returns:

- `met` when resolution completes at or before its deadline; exact equality passes.
- `late` with completion time and positive lateness when resolution finishes too late.
- `unfinished` with null completion/lateness when no resolution succeeds, distinguishing direct attempt exhaustion from dependency blocking.

Already resolved incidents complete at logical time zero. Retry counts are per incident across both phases. Results include met/late/unfinished totals, `all_met`, sorted targets, and the original versioned snapshots.

Per-incident deadlines are distinct from the comparison tool's overall closure deadline: a requested incident can meet its deadline even if another incident prevents the full recovery from completing. All times are simulated milliseconds from the trace's origin, not wall-clock promises or scheduled infrastructure actions.

## Witnessed campaigns and checkpoints

```powershell
& .\.venv\Scripts\python.exe tests\eval_matrix.py --suite all --protocol-only --transport all --campaign-graph-nodes 64 --campaign-graph-width 8 --campaign-steps 120 --parallel-calls 32 --campaign-race-topology mixed --campaign-root-churn --campaign-outage-stress --campaign-timeline-stress --campaign-resilience-stress --campaign-strategy-stress --output runs\recovery-decisions-chaos
```

`--campaign-strategy-stress` adds policy trade-offs and deadline checks at initial, partial, and completed states. Negative probes deliberately corrupt trace versions or, for empty traces, completion summaries. Deadline evaluation must reject those probes.

A version-2 `strategy` action records comparison arguments, incident deadlines, and a tamper flag. The runner requests the comparison, separately calls the real simulation tool for every candidate, and requests deadline evaluation for each resulting trace. An independent checker audits these witnesses and recomputes comparison/deadline metrics; it does not invoke the comparison or scoring implementation. Checkpoint reconstruction repeats those evidence checks, rejecting rehashed winner or deadline forgeries.

Tests cover failed-versus-completed selection, ties and empty work, deadline causes and stale evidence, authority and bounds, all three transports, 128-node randomized witnesses, checkpoint continuation, and forged decisions. Campaign decisions are simulations and read-only analyses; they grant no write authority or record reservation.
