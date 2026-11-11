# Recovery resilience and trace auditing

Dense MCP servers expose `simulate_recovery_resilience` and `validate_recovery_trace`. Hardened names have the `sim_` prefix. Both are read-only, enforce the target's complete prerequisite closure, and remain available in compact discovery mode.

## Worker outages, attempt budgets, and backoff

`simulate_recovery_resilience` accepts the existing timeline fields (`record_id`, `max_parallel`, `durations`) plus:

| Argument | Bounds and meaning |
|---|---|
| `max_attempts` | 1–4 attempts per incident phase, including interrupted attempts |
| `retry_backoff_ms` | 0–1000; delay after failed attempt N is `base * 2^(N-1)` |
| `faults` | Up to 128 distinct incident/phase entries with `failed_attempts` from 0–3 |
| `worker_outages` | Up to 32 intervals with worker index, start_ms, and end_ms within 0–20000 |

Supply empty arrays for unused durations, faults, or outages. Duration overrides retain the 1–1000 ms bounds. Faults and overrides must reference members of the target closure; duplicate fault phases and duplicate duration IDs are rejected. Each outage must reference a worker in this scenario and have start strictly before end.

An available worker starts ready resolutions before investigations, then uses incident ID order. Outages use half-open intervals `[start, end)`: dispatch at the outage start is forbidden, while dispatch at its end is allowed. An outage that starts during an attempt interrupts it immediately. An operation finishing exactly at the outage start succeeds before the worker goes offline. Overlapping intervals keep that worker unavailable until all covering intervals end.

For a fault entry, the first N numbered attempts fail; an outage takes precedence as the reported failure reason. Interrupted attempts still consume attempt numbers. Retries retain the same expected version. Only successful simulated operations advance the hypothetical record version. No partial operation commits.

An exhausted phase blocks its dependent tasks, including resolution tasks that need a failed prerequisite. Independent investigations or recoveries may continue. The result reports every attempt, retry count, exhausted tasks, blocked tasks, unfinished incident IDs, elapsed logical time, original snapshots, and hypothetical final records. No incident state, receipt, catalog, or real server fault counter is changed.

These are logical simulations: no workers, clocks, or infrastructure are actually stopped. A completed simulation is not a reservation or write authorization.

## Independent trace auditing

Call `validate_recovery_trace` with a `scenario` object using the simulation schema and a `trace` object. The auditor does not call the simulator. It checks:

- Current snapshots, record versions, task membership, and scenario identity.
- Worker bounds and overlapping worker intervals.
- Outage dispatch rules, interruptions, and operation durations.
- Attempt numbering, per-phase budgets, failure reasons, and exponential backoff.
- Prerequisite completion before attempted dependent work.
- Exhaustion, blocked work, final records, and all summary counts.

It returns `{valid, violations}` with stable diagnostic codes. A malformed trace object is a diagnostic invalid result; malformed API arguments or unauthorized scenarios are tool errors. Hardened audits enforce the same scenario authority at the proxy and server. A changed live incident snapshot makes an older trace invalid.

The auditor verifies legal traces, not optimality or the simulator's exact greedy dispatch order. A legally delayed schedule can pass. Both tools are bounded to a 128-node closure, at most 256 phase tasks and 1024 attempts. Results use the existing bounded 1 MiB stdio response buffer.

## Replay, checkpoints, and stress campaigns

```powershell
& .\.venv\Scripts\python.exe tests\eval_matrix.py --suite all --protocol-only --transport all --campaign-graph-nodes 128 --campaign-graph-width 8 --campaign-steps 200 --parallel-calls 32 --campaign-race-topology mixed --campaign-root-churn --campaign-outage-stress --campaign-timeline-stress --campaign-resilience-stress --output runs\resilience-chaos
```

`--campaign-resilience-stress` adds retry/outage recovery, exhausted budgets, valid audits, and deliberate version, missing-attempt, and summary corruption. A version-2 `resilience` action records a scenario and corruption mode. The runner calls both real MCP tools, independently checks the returned attempt evidence, and requires the audit verdict to match the corruption mode. It also requires all state, receipt, resource-notification, and catalog invariants to remain unchanged.

When a completed closure has no attempts to edit, version/missing-attempt probes corrupt the completion summary instead. A passing exhaustion check means the expected failed recovery was modeled correctly; it does not mean recovery succeeded.

These actions compose with worker timelines, dependency outages, overlapping write races, root changes, lost acknowledgments, and approval callbacks. Saved manifests replay the profiles exactly. Checkpoint reconstruction re-audits both responses; rehashing an envelope cannot make a forged attempt valid against the reference state.

Tests cover outage boundaries, overlapping intervals, retry/version semantics, exhaustion and downstream blocking, alternative legal schedules, malicious trace edits, invalid profile bounds, all three transports, larger traces exceeding 400 attempts, randomized 128-node scenarios, and checkpoint recovery. These are controlled protocol and simulation evaluations, not live language-model judgments.

Randomized tests also execute the successful attempts against the real incident store and require its records to equal the simulated final records. Failed attempts produce no real writes in this verification.
