# Mitigation search and duration sensitivity

Dense MCP servers expose two more read-only tools: `search_recovery_mitigations` and `analyze_recovery_sensitivity`. Hardened names have the usual `sim_` prefix. Both validate the authorized prerequisite closure and run counterfactuals from one frozen incident snapshot. They remain available in compact catalog mode.

Whole-valued JSON numbers such as `2.0` are accepted as integers without modifying the caller's arguments. Fractional values remain invalid for integer fields.

## Search for mitigations

Pass a recovery `scenario`, `deadline_ms` (0–1000000), and:

| Argument | Meaning |
|---|---|
| `candidates` | 1–8 distinct references with kind `fault` or `outage` and an original scenario-array index |
| `max_removals` | 1 or 2; maximum number of candidate entries removed together |
| `max_evaluations` | 1–40; evaluation budget, including the unchanged baseline |

The tool simulates removing selected entries from `faults` or `worker_outages`. Indices always refer to the original arrays; removing one entry does not renumber another reference. Invalid or duplicate references are rejected. Removing a disruption is hypothetical and never changes actual server fault settings, incident records, or receipts.

Trials are deterministic: baseline first, then single removals, then pairs. References are canonically sorted by kind and index, so reordering the candidate list does not change the search. Eight candidates and pair removals produce at most 37 trials. The budget may stop enumeration early.

Each trial reports the removed entries, completion, elapsed logical time, attempt/retry counts, unfinished incidents, and deadline outcome. `best_trial` indexes the best observed deadline-meeting trial, preferring fewer removals, then lower elapsed time, fewer attempts, and canonical reference order. It is null if no visited trial meets the deadline. If the baseline already meets the deadline, zero removals win.

`total_trials`, `evaluated_trials`, and `search_complete` distinguish a complete bounded search from a truncated one. No solution in a truncated search does not establish that no solution exists. A complete search covers only the supplied candidates and the one/two-removal limit; it is not a global repair proof. Joint mitigations can succeed even when either removal alone fails.

## Analyze duration sensitivity

Pass a `scenario`, `deadline_ms`, and 2–8 distinct `duration_percent` values from 25 through 400. Both operation phases are scaled for every incident in the closure, including the default 1 ms costs for records without explicit overrides. Durations round upward to integer milliseconds. Any scaled duration above 1000 ms is rejected; values are never silently clamped.

Faults, worker-outage windows, retry backoff, worker count, and attempt budgets stay fixed. The tool returns sorted samples with completion, timing, retries, unfinished work, and deadline results. `robust_across_samples` is true only when every requested sample completes within the deadline. `worst_completed_elapsed_ms` excludes failed recoveries and is null when all samples fail.

The result is a deterministic sample set, not a statistical failure probability or a guarantee for every value between samples. Outcomes need not be monotonic: longer work can avoid one outage boundary or cross another. For example, a 2 ms resolution beginning at time 2 is interrupted by an outage at time 3, while a preceding investigation that ends exactly at time 3 may succeed before that outage and allow resolution after the worker returns.

## Independently witnessed campaigns

```powershell
& .\.venv\Scripts\python.exe tests\eval_matrix.py --suite all --protocol-only --transport all --campaign-graph-nodes 64 --campaign-graph-width 8 --campaign-steps 100 --parallel-calls 32 --campaign-race-topology mixed --campaign-root-churn --campaign-outage-stress --campaign-timeline-stress --campaign-resilience-stress --campaign-strategy-stress --campaign-analysis-stress --output runs\counterfactual-chaos
```

`--campaign-analysis-stress` adds joint-mitigation searches, deliberately limited budgets, non-monotonic duration scenarios, and analyses at partial and completed states. Each version-2 `counterfactual` action records separate mitigation and sensitivity specifications.

The runner calls both analysis tools, independently enumerates the expected variants, and requests real MCP simulations for all visited trials and samples. The reference enumerator uses bit-mask subsets and independently rounded durations; it never calls the search or sensitivity implementation. Every witness is audited, and its evidence must reproduce all metrics, winner selection, robustness, and completeness claims.

Counterfactual manifest actions require valid graph-scoped scenarios. Scope escapes, duplicate overrides, invalid outage intervals/references, and scaled-duration overflow are rejected before a fixture is created. Checkpoint continuation rechecks the saved witnesses and rejects forged winner or robustness claims even if the checkpoint envelope is rehashed.

Tests cover joint fault/outage removals, baseline preference, 37-trial searches, truncation, null results, non-monotonic sensitivity, bounds and authority, all three transports, randomized 128-node witnesses, and checkpoint continuation. The tools perform simulations only; they grant no write authority or reservation.
