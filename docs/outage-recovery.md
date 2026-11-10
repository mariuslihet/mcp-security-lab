# Outage cascades and recovery schedules

Dense MCP servers expose two additional read-only tools. Hardened names have the `sim_` prefix. Both return structured results and advertise read-only/idempotent annotations. These are graph simulations over synthetic records, not infrastructure outage controls.

## simulate_dependency_outage

Pass `failed_records`, an array of 1–16 distinct incident IDs. The simulator follows reverse dependency edges and returns:

- Sorted failed and impacted incident IDs, with shared descendants included once.
- Propagation waves based on minimum distance from any failed incident.
- A deterministic shortest causal path for every impacted incident.
- Versioned affected-record snapshots and an unaffected count.

All dependency edges propagate the hypothetical failure regardless of current incident status. This is a structural what-if calculation; it does not overwrite incident state, receipts, or fault counters. Multiple failed incidents start together in wave zero. A failed descendant remains at distance zero even if a failed ancestor can also reach it.

The hardened arm limits output and counts to authorized records, rejects unauthorized failure seeds, and validates affected prerequisite closures. Protected or missing prerequisites and dependency cycles fail closed. The comparison arm deliberately exposes protected incident analysis.

## plan_recovery

Pass `record_id` and `max_parallel` (1–16). The planner covers the incident's complete prerequisite closure and returns its starting snapshots, update count, and an ordered list of waves. Each update supplies `record_id`, `expected_version`, and `status` for the existing update tool.

Open records need investigation and resolution; investigating records need resolution; resolved records need no update. A resolving record's prerequisites must be resolved before its wave begins. The scheduler prioritizes ready resolutions, then investigation starts, sorting IDs for reproducible plans. Each wave contains at most one update per incident and respects the requested parallel limit. It is deterministic scheduling, not a claim of globally optimal makespan.

Complete a wave before beginning the next. Within a wave, individual updates may run concurrently in any order; callers supply their write handle and distinct idempotency keys. All existing authority, transition, dependency, and version checks still apply. Plans grant no write permission or reservation. If another writer changes a planned record, discard the stale schedule and request a fresh plan. Already completed closures return an empty schedule.

## Combined chaos campaigns

```powershell
& .\.venv\Scripts\python.exe tests\eval_matrix.py --suite all --protocol-only --transport all --campaign-graph-nodes 128 --campaign-graph-width 8 --campaign-steps 150 --parallel-calls 32 --campaign-race-topology mixed --campaign-root-churn --campaign-outage-stress --output runs\outage-recovery-chaos
```

`--campaign-outage-stress` adds root and middle-layer outages, recovery schedules before and after mutations, single-worker and 16-worker plans, protected-record probes, and seeded multi-fault outages. It composes with overlapping races, client-root churn, callback refusal, lost acknowledgments, compact catalogs, and retries. The requested action budget must fit the graph's complete sequence; the CLI reports the required minimum.

Version-2 manifests preserve these calls for replay and checkpoint continuation. The reference oracle computes outage paths by repeated relaxation and schedules a separate task dependency graph; it does not call the server planner. State, receipts, resource notifications, and catalogs must remain unchanged after each preview.

Tests execute generated schedules against the real incident store with shuffled writes within each wave, exercise 128-node graphs across seeds and concurrency budgets, reject stale schedules and invalid closures, and check discovery/results over stdio, SSE, and Streamable HTTP. These are controlled protocol and simulation checks, not live language-model evaluations.
