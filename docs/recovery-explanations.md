# Recovery waits and failure paths

`analyze_recovery_waits` and `explain_recovery_failures` explain recorded recovery evidence. Hardened names use the `sim_` prefix. Both are read-only, available in compact catalogs, and require a `scenario` plus `trace` using the same contract as `validate_recovery_trace`. Failure explanations additionally require `max_causes`, an integer from 1 to 8.

Both tools independently audit the trace against the current authorized incident snapshot before analysis. Forged or stale traces return `recovery_trace_invalid`; unauthorized targets or prerequisites are denied. A result does not reserve state or authorize a write. All times are simulated milliseconds.

## Ready-to-dispatch waiting

For each recorded attempt, `analyze_recovery_waits` returns:

| Field | Meaning |
|---|---|
| `dependency_ready_ms` | Latest successful completion of its required phase/dependency tasks, or zero when none are required |
| `retry_ready_ms` | Previous attempt's end plus mandatory exponential backoff, or zero for a first attempt |
| `ready_ms` | Maximum of dependency and retry readiness |
| `start_ms` | Recorded attempt dispatch time |
| `waiting_ms` | `start_ms - ready_ms` |
| `outage_wait_ms` | Time after readiness when every worker is unavailable |
| `busy_wait_ms` | Time after readiness when some workers are available but all available workers are occupied |
| `dispatch_gap_ms` | Time after readiness when at least one available worker is free |
| `required_backoff_ms` | Mandatory delay before this retry, reported separately |

The three waiting categories are disjoint and sum exactly to `waiting_ms`. Availability unions overlapping outage windows. Half-open intervals `[start, end)` ensure completion at a dispatch boundary does not double-count occupied time. Mixed intervals with some workers unavailable and the remainder occupied count as busy waiting.

Dependency and retry readiness are absolute times, not durations to add to the wait. Waiting starts only after both conditions are satisfied. Required backoff is not counted again as ready-to-dispatch waiting, and no backoff is invented after a final exhausted attempt.

`totals` sum task-level waiting categories and required backoff. Multiple attempts can wait at the same time, so these totals are not worker-capacity accounting and may exceed elapsed time. `record_totals` aggregates waiting and backoff per incident, ordered by descending wait, descending backoff, then incident ID. Use `analyze_recovery_utilization` for worker-capacity identities.

The analysis accepts any trace that passes the legality audit, including legal idle gaps and reordered evidence. It describes the recorded schedule; it does not prove a unique delay cause or globally optimal dispatch policy.

## Exhaustion and blocked work

`explain_recovery_failures` builds a task graph containing only phases still required by the initial snapshot. Investigation precedes the same incident's resolution. Unresolved prerequisite resolutions precede dependent resolutions; investigations themselves can run independently. Already resolved phases are not invented as tasks.

An exhausted phase is a root. Edges propagate only through exhausted or blocked tasks. For every unfinished incident's resolution task, the result lists distinct exhausted roots that reach it, including a failed incident's own phase when applicable. Successful retries are not roots.

Each root reports its final recorded fault/interruption reason, stopping time, attempt count, and the number of distinct unfinished incidents it affects, including its own incident. Root rows sort by descending impact, then incident ID and phase. This is deduplicated impact: multiple paths to one incident count once.

For each incident, each returned root has one shortest task path. Ties use lexicographic ordering of the forward `(record_id, status)` sequence. Causes sort by shortest path length, root ID, then phase. `cause_count` counts all distinct reachable exhausted roots before the `max_causes` limit. `truncated` means additional roots were omitted; it does not indicate alternative equal-length paths for an already displayed root.

Completed recoveries return empty roots and targets. Empty workloads also have zero waiting and backoff totals. These are deterministic propagation explanations for this simulation, not estimates of real-world fault probability or proof of a unique external cause.

## Reports and replay

Inspect **Recorded ready-to-dispatch waits** and **Recorded failure propagation** in a result's evidence panel. Wait summaries show totals and up to 100 attempt rows; failure summaries show all roots and the first 20 incident explanations. Bounds are labeled, and full returned evidence remains available below. Incident cause truncation is shown separately from the report's display bounds. Reports display saved claims without rerunning the audit or contacting a server.

`--campaign-diagnostics-stress` adds `diagnostics` actions to version-2 manifests. It combines overlapping worker outages, retry waits, simultaneous root exhaustion, bounded cause lists, partial recovery, and completed-state cases. A separate checker audits the simulation, verifies output types, recomputes waits through interval intersections, and reconstructs paths from reverse distances with forward tie-breaking. Checkpoint restore repeats verification even when a forged checkpoint envelope has been rehashed.

```powershell
& .\.venv\Scripts\python.exe tests\eval_matrix.py --suite all --protocol-only --transport all --campaign-graph-nodes 64 --campaign-graph-width 8 --campaign-steps 120 --parallel-calls 32 --distractors 80 --campaign-race-topology mixed --campaign-root-churn --campaign-outage-stress --campaign-timeline-stress --campaign-resilience-stress --campaign-strategy-stress --campaign-analysis-stress --campaign-utilization-stress --campaign-portfolio-stress --campaign-diagnostics-stress --output runs\recovery-explanation-chaos
```

`tests/test_recovery_explanations.py` covers manually calculated waits, valid dispatch gaps, diamond path ties, ties where forward and reverse lexical orders differ, multi-root truncation, interruption exhaustion, already investigated/resolved snapshots, whole-valued JSON numbers, reordered attempts, generated 8/32/128-node graphs, all transports and both modes, compact catalog calls, authorization, stale/forged evidence, manifest validation, checkpoint resume, and rehashed accounting/path/type corruption. Report tests check safe escaping, invalid/error-result omission, and display bounds.
