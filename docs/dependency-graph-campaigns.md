# Dependency graph campaigns

Graph campaigns extend the independent-record campaign format with bounded dependency DAGs and parallel transaction groups. They preserve all existing version-1 manifests and add version-2 manifests containing the exact graph and action sequence.

## New MCP functions

| Tool | Arguments | Behavior |
|---|---|---|
| `analyze_dependencies` | `record_id` | Returns the authorized prerequisite closure, node/edge counts, execution layers, one longest critical path, and unresolved records |
| `incident_bundle` | `record_id` | Returns the record plus native MCP `resource_link` content blocks for its complete prerequisite closure |
| `set_catalog_profile` | `profile`, `handle` | Selects `standard` or `compact`, requiring a `catalog:manage` handle in the hardened arm |
| `simulate_dependency_outage` | `failed_records` | Simulates downstream impact from 1–16 failed incidents, including shortest causal paths and versioned snapshots |
| `plan_recovery` | `record_id`, `max_parallel` | Schedules prerequisite-aware versioned recovery waves with 1–16 concurrent updates |
| `simulate_recovery_timeline` | `record_id`, `max_parallel`, `durations` | Simulates worker-assigned recovery events with uneven durations and timing bounds |
| `rank_dependency_bottlenecks` | `record_id`, `limit` | Ranks deduplicated downstream impact and unresolved work within the target closure |
| `simulate_recovery_resilience` | Timeline fields, `max_attempts`, `retry_backoff_ms`, `faults`, `worker_outages` | Simulates retries, worker interruptions, exhaustion, and blocked recovery tasks |
| `validate_recovery_trace` | `scenario`, `trace` | Independently audits attempt evidence and final-state claims against current snapshots |
| `compare_recovery_strategies` | `scenario`, `deadline_ms`, `strategies` | Compares 2–8 worker/retry policies on one snapshot, excluding failed recoveries from winner selection |
| `evaluate_recovery_deadlines` | `scenario`, `trace`, `deadlines` | Audits evidence before classifying requested incidents as met, late, or unfinished |
| `search_recovery_mitigations` | `scenario`, `deadline_ms`, `candidates`, `max_removals`, `max_evaluations` | Searches bounded single/pair removals of selected disruptions |
| `analyze_recovery_sensitivity` | `scenario`, `deadline_ms`, `duration_percent` | Simulates discrete duration changes while keeping disruptions and backoff fixed |
| `analyze_recovery_utilization` | `scenario`, `trace` | Audits evidence, then accounts for worker capacity, busy/idle/outage time, and retry waits |

Hardened names use the usual `sim_` prefix. Analysis and bundles are read-only. Their prerequisite traversals enforce the same missing-record, permission, and cycle checks as resolution plans. Resource links identify JSON resources; clients follow them through `resources/read` for the current record rather than treating the link itself as a snapshot.

The standard resource catalog includes `lab://incidents/catalog`, which lists visible incident resource URIs. The hardened version excludes protected records. Compact mode removes that catalog resource and the `incident_triage` prompt from discovery and rejects requests for them. Incident URI templates and individual authorized incident resources remain available.

## Dynamic catalogs and native list-change notifications

Dense servers advertise `listChanged` for tools, resources, and prompts. `set_catalog_profile` emits one notification for each list when the profile changes:

- `notifications/tools/list_changed`
- `notifications/resources/list_changed`
- `notifications/prompts/list_changed`

Repeating the current profile is a no-op and emits no duplicate list-change notifications. Profile transitions are serialized so concurrent control requests return their own resulting profile and consistent notification counts. Notifications are delivered to live sessions observed through discovery or subscription operations; disconnected sessions are removed when detected.

Compact mode removes update, batch update, guided update, preview, roots, sampling, and form-input tools from discovery and rejects new calls to those tools at the server. Catalog control remains available so the standard profile can be restored. An in-flight operation is not cancelled by changing discovery profiles. Profiles are server-process state, reset to standard on restart; they are not durable authorization revocations.

The catalog handle is synthetic (`catalog-management-handle`) and scoped separately from incident writes. A read or incident-write handle cannot manage the hardened catalog. The vulnerable arm accepts unauthorized catalog control for comparison. Profiles enforce tool availability in both arms.

The deputy can refresh discovery through `list_tools`, `list_resources`, `list_prompts`, and `list_resource_templates` with empty argument objects after observing list-change notifications. It can also follow resource-link content through `read_resource`.

## Generated graph structure

Use `--campaign-graph-nodes N` with `--suite dense` or `all` to choose graph campaigns. Without it, existing independent-record campaigns continue unchanged.

- Generated graphs have 8–128 `GR-000` style nodes and a layer width of 2–8, smaller than the node count.
- Each node beyond the root layer depends on every node in the previous layer. Seeded extra edges can point to older layers, creating additional long paths and shared prerequisites.
- Parent lists are bounded to eight unique existing records. Self-edges, duplicate edges, unknown identifiers, and cycles are rejected before creating a fixture.
- The same graph and manifest are generated for both server arms and transports from the same parameters and seed.

The final incident's prerequisite closure can omit its siblings in the last layer; `analyze_dependencies` counts the requested closure, while campaign metadata and the topology diagram describe the entire generated graph.

## Campaign action sequence

The generated sequence includes:

1. Dependency analysis and native resource-link discovery.
2. Compact/standard catalog transitions and a rejected hidden-tool call.
3. Investigation-start batches of up to 16 records, with a lost post-commit acknowledgment and explicit retry.
4. A preview and guided attempt to close the terminal incident before prerequisites are ready.
5. Client refusal and concurrent two-record root-resolution batches, followed by replay of the whole race group.
6. A changed-payload receipt-key conflict.
7. An approved guided prerequisite update, including an uncertain acknowledgment and receipt replay in the hardened arm.
8. Topological resolution waves, with batch input deliberately reversed to test final-state rather than input-order validation.
9. Completed-state analysis followed by seeded reads, links, stale/reopen previews, refusals, and attempted invalid transitions.

The step count must fit the setup and complete resolution waves. If the requested graph needs more actions, the CLI reports the minimum. Omitting `--campaign-steps` with a graph uses `max(60, node_count)` actions. Campaigns remain bounded to 200 top-level actions; each race action can contain up to 32 actual MCP calls.

## State, receipt, concurrency, and notification checks

An independent reference model evaluates arguments, authority, receipt fingerprints, versions, transitions, and the proposed final dependency state. It models injected failures separately from commit success. The campaign compares the **entire record map and complete receipt contents** with the published state file after every action, including failed or uncertain calls.

The default race profile retains shared two-record batches. `--campaign-race-topology mixed` generates single-record, disjoint, partially overlapping, and hub batches, including requests carrying a weaker handle. Replay accepts heterogeneous write sets of 1–16 records per request; duplicate records within a request and duplicate receipt keys within a group are rejected.

The race checker derives precedence from returned per-record versions and prerequisite relationships. Receipts witness commits with lost acknowledgments. Rejections and cached responses are placed at a point where the reference state permits them, including rejection of a child before a disjoint parent commits. Every response and the complete final state/receipt set must agree with the resulting order. This is a bounded checker for these atomic incident operations; it does not establish general linearizability for arbitrary MCP tools.

`--campaign-root-churn` adds native root-change notifications, workspace withdrawal/restoration, and notified or silent changes during guided approval. The client declaration mode is modeled independently and checked after every action. These profiles are preserved in version-2 manifests and replayed without needing the original CLI flags.

`--campaign-outage-stress` composes multi-node failure cascades with recovery scheduling before and after mutations. It varies concurrency budgets, probes protected records, and samples additional failure sets after resolution. See [outage and recovery semantics](outage-recovery.md) for scheduling and authority boundaries. These read-only previews also remain available in compact catalog mode.

`--campaign-timeline-stress` adds weighted timelines, worker contention, simultaneous completion handling, and bottleneck rankings at initial, partial, and completed states. See [timed scheduling semantics](timed-recovery.md). All profiles can be enabled together and reconstructed from saved manifests.

`--campaign-resilience-stress` adds paired simulation/audit actions with worker outages, attempt budgets, exponential backoff, and deliberate evidence corruption. Saved checkpoints re-audit both responses. See [resilience and trace-audit semantics](recovery-resilience.md).

`--campaign-strategy-stress` adds policy comparisons, independently requested candidate traces, per-incident deadline evaluations, and corrupted-evidence rejection. Saved checkpoints verify all comparison witnesses and scoring responses. See [recovery decision semantics](recovery-decisions.md).

`--campaign-analysis-stress` adds bounded mitigation searches, truncated evaluation budgets, and duration sensitivity. Independently enumerated real simulation witnesses verify the reported results and checkpoint claims. See [counterfactual recovery semantics](counterfactual-recovery.md).

`--campaign-utilization-stress` adds paired simulation/accounting actions before mutations, partway through recovery, after completion, and during seeded stress. Overlapping outages and repeated failures exercise capacity accounting; an independent interval sweep checks every response and checkpoint. See [recovery capacity and viewer semantics](recovery-utilization.md).

Campaigns subscribe to the first and terminal graph resources. Each mutation must produce exactly the expected subscribed URI notifications, including post-commit error responses. Hardened receipt replays and failed transactions must produce none. Catalog transitions are checked separately for exactly one notification per changed list. All notification evidence is retained in result rows and the wire journal.

On Streamable HTTP, unsolicited notifications use a separate stream. The runner allows up to three seconds for expected deliveries before comparing exact counts; a tool response alone is not a notification barrier.

The hardened arm must enforce prerequisites and produce the reference state. The vulnerable arm deliberately permits stale, unauthorized, duplicate, and invalid-transition mutations. Its passing rows mean those expected vulnerable effects were observed, not that the arm behaved safely.

## Replay

```powershell
& .\.venv\Scripts\python.exe tests\eval_matrix.py --suite dense --protocol-only --transport both --replay-campaign runs\graph-chaos\campaign-stdio-hardened\campaign.json --output runs\graph-replay
```

Replay validates the complete graph and permitted action schemas, then starts fresh fixtures. It preserves the graph, batch membership, callback approval profiles, retry keys, and concurrent request groups. Race winner identity and response timing may differ; legal outcomes, receipt counts, and invariants must still hold.

Version-2 manifests allow only the listed synthetic graph/read/catalog/update operations. They cannot request arbitrary tools, commands, filesystem paths, or endpoints. Version-1 manifests retain their original validation and replay behavior.

## Stress tests and report inspection

`tests/test_graph_campaign.py` covers generation, invalid manifests, both arms and transports, replay, and larger hardened campaigns at 32, 64, and 128 nodes with 16, 24, and 32 parallel requests. `tests/test_graph_features.py` checks graph validation, resource links, analysis, scope enforcement, catalog transitions, and concurrent catalog control. It also uses a real competing MCP write while a guided approval is pending, confirming that final version checks reject stale approval.

The dashboard shows the initial topology, graph dimensions, capability counts, and individual action evidence. The topology is static; inspect each row's analysis, responses, receipt count, and notification checks to follow state changes. Resource, callback, manifest, and state links remain relative to the report folder. Invalid graph payloads cannot inject markup into the topology view.
