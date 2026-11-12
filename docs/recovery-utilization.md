# Recovery capacity and recorded timelines

`analyze_recovery_utilization` takes `scenario` and `trace`, using the same input contract as `validate_recovery_trace`. Hardened servers expose `sim_analyze_recovery_utilization`. The tool is read-only, available in compact catalogs, and enforces the target's prerequisite permissions. It audits the supplied trace against current records before doing accounting. Forged, inconsistent, or stale evidence returns `recovery_trace_invalid`; analysis never changes incidents or retry receipts.

For example, pass the `structuredContent` from `simulate_recovery_resilience` as `trace` and the original simulation arguments as `scenario`.

## Accounting

All times are simulated milliseconds. Each worker's accounting covers `[0, trace.elapsed_ms)`:

| Field | Meaning |
|---|---|
| `capacity_ms` | Elapsed horizon for one worker |
| `outage_ms` | Union of that worker's outage intervals, clipped to the horizon |
| `available_ms` | Capacity minus outage time |
| `productive_ms` | Time spent on successful attempts |
| `failed_attempt_ms` | Time spent on retry or exhausted attempts |
| `busy_ms` | Successful plus failed attempt time |
| `idle_ms` | Available time minus busy time |
| `utilization_basis_points` | `floor(10000 * busy / available)`, or `null` if availability is zero |

Overlapping outages count once; outages after the recovery horizon do not count. Totals sum each time field across workers. Total utilization uses total busy time divided by total available time, rather than averaging worker percentages. Capacity equals busy plus idle plus outage time. Utilization measures occupied capacity, including failed attempts; it does not measure successful recovery alone.

`retry_wait.required_backoff_ms` adds the exponential backoff between consecutive attempts of the same incident phase. `additional_wait_ms` adds the rest of those gaps, which can include worker contention and outages. These are task-level waits: they can overlap each other and worker activity, so they are separate from the capacity identities. No wait is invented after an exhausted final attempt.

An already resolved closure has a zero horizon, zero time fields, and `null` utilization. The response includes the audited snapshot so consumers can identify the record versions analyzed.

## Inspect a saved report

Open a result's inspector and find **Recovery timeline**. Supported timed schedules and resilience traces are extracted from recorded object evidence. Choose a trace, search by incident, or filter by outcome. Worker lanes keep the original time scale as filters change. Select an attempt in the table to see its expected version, phase, worker, timing, and outcome reason.

Tables show 25 attempts per page. **Export filtered attempts CSV** exports all matching attempts across pages; spreadsheet formula prefixes are neutralized. Pinned comparison panes have independent filters and selections. Utilization results also display capacity cards and a per-worker accounting table.

The viewer displays recorded claims; opening a report does not rerun the audit or contact a server. It does not parse embedded JSON strings or infer missing events. Extraction is bounded to 48 unique traces, 100,000 visited values, and depth 24; each supported trace has at most 1,024 resilience attempts or 256 timed events. Inspector parsing stops above 32 MiB. Limit and malformed-data notices point reviewers to the full evidence. Reports inline their assets and need no Node installation to open.

## Campaigns and verification

Add `--campaign-utilization-stress` to a generated graph campaign, or replay a saved manifest containing `utilization` actions. The profile includes overlapping outages, repeated failures, partial-state accounting, and completed-state zero-capacity checks. It composes with the other chaos profiles. An independent interval sweep verifies actual responses and rechecks saved checkpoint claims.

```powershell
& .\.venv\Scripts\python.exe tests\eval_matrix.py --suite all --protocol-only --transport all --campaign-graph-nodes 32 --campaign-graph-width 4 --campaign-steps 100 --parallel-calls 24 --campaign-race-topology mixed --campaign-root-churn --campaign-outage-stress --campaign-timeline-stress --campaign-resilience-stress --campaign-strategy-stress --campaign-analysis-stress --campaign-utilization-stress --output runs\capacity-chaos
```

`tests/test_trace_diagnostics.py` covers hand-calculated accounting, randomized 8/32/128-node graphs, all three transports and both arms, authority checks, forged traces, and rehashed checkpoint corruption. `tests/dashboard-recovery.test.cjs` exercises filters, pagination, selection, focus, independent panes, hostile text, and CSV controls in an offline in-memory DOM. It does not verify pixel layout or establish browser accessibility conformance.
