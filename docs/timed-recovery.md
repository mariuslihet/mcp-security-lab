# Timed recovery and dependency bottlenecks

Dense MCP servers expose two more read-only tools. Hardened names use the `sim_` prefix. Both validate prerequisite closures and expose versioned snapshots; they remain available in compact discovery mode.

## simulate_recovery_timeline

Arguments are `record_id`, `max_parallel` (1–16 workers), and `durations`. Supply `durations: []` to use 1 ms per operation, or provide up to 128 distinct overrides:

```json
{"record_id":"GR-003","max_parallel":2,"durations":[
  {"record_id":"GR-000","investigate_ms":3,"resolve_ms":7},
  {"record_id":"GR-003","investigate_ms":2,"resolve_ms":20}
]}
```

Each duration is an integer from 1 to 1000 ms. Overrides must belong to the target's prerequisite closure. Duplicate IDs, unrelated records, malformed bounds, missing prerequisites, and cycles are rejected; hardened traversal also rejects protected prerequisites.

The simulator schedules the remaining investigation/resolution work with non-preemptive workers. Open records require both steps, investigating records require resolution, and resolved records require no work. Investigation can start while prerequisites recover. Resolution waits for the incident's own investigation and every unresolved prerequisite's resolution. Ready resolutions have priority over investigation starts, then incident IDs break ties. Idle workers are assigned in ascending order.

Every returned event includes the record ID, target status, expected version, worker index, start time, and end time. All completions at a timestamp become visible before new work starts, so joins wait for every prerequisite even when several workers finish together. Durations advance a logical clock: no actual sleep or infrastructure change occurs.

The result also contains:

- `makespan_ms`: when the last scheduled operation finishes.
- `total_work_ms`: total duration of all remaining operations.
- `critical_path_ms`: a lower bound with unlimited workers, computed from remaining task dependencies.
- `worker_lower_bound_ms`: total work divided by worker count, rounded up.
- Starting record snapshots with versions.

The scheduling policy is deterministic and does not claim globally optimal completion time. Simulated timing is separate from measured MCP latency in `performance.json`. Changing worker count can change scheduling order; do not assume every additional worker strictly improves this greedy policy.

Events describe independently guarded updates, not a transaction or reservation. Execute updates only after their preceding tasks complete, with an authorized write handle and distinct receipt keys. Competing writes invalidate stale expected versions and require a fresh simulation. An already completed closure returns no events and zero timing bounds.

## rank_dependency_bottlenecks

Arguments are `record_id` and `limit` (1–20). The tool ranks nodes inside the target's prerequisite closure, rather than across unrelated incidents. Each entry reports:

| Field | Meaning |
|---|---|
| `impacted_count` | Distinct downstream closure nodes, including the ranked incident itself |
| `direct_dependents` | Immediate children inside the closure |
| `unresolved_dependents` | Downstream incidents that remain unresolved, excluding the ranked incident |
| `downstream_depth` | Longest downstream path in dependency edges |

Rank order is descending impacted count, descending unresolved dependent count, then ascending incident ID. Shared descendants count once. Structural impact still includes resolved records; current work pressure is shown separately. Results include the complete authorized closure snapshot and node count. This ranking is not a failure probability estimate.

## Combined campaigns and tests

```powershell
& .\.venv\Scripts\python.exe tests\eval_matrix.py --suite all --protocol-only --transport all --campaign-graph-nodes 128 --campaign-graph-width 8 --campaign-steps 180 --parallel-calls 32 --campaign-race-topology mixed --campaign-root-churn --campaign-outage-stress --campaign-timeline-stress --output runs\timed-recovery-chaos
```

`--campaign-timeline-stress` adds weighted one-worker and 16-worker schedules, contended three-worker timelines, bottleneck rankings at different state boundaries, protected-target probes, and post-stress analyses. These calls are saved in version-2 manifests and preserved through checkpoint reconstruction. The existing independent state/receipt/notification checks require them to remain read-only.

The server simulator tracks mutable record states with a completion-event heap. The reference model builds a separate task DAG and tracks completed tasks and worker intervals. Tests compare their complete results, execute events against the real store, check simultaneous completions, heterogeneous durations, stale versions, authority, schemas, and live discovery over all three transports. Larger tests cover 128-node graphs and durations up to 1000 ms using controlled clients.

The stdio proxy allows response lines up to 1 MiB, accommodating the structured result plus its serialized text copy. A dedicated 128-node regression crosses the previous 64 KiB buffer boundary and verifies a subsequent tool call still succeeds.
