# Checkpoints and protocol performance

## Resumable graph campaigns

Every dependency-graph campaign saves `checkpoint.json` after a verified action. Checkpoints include the manifest hash, completed action count, session identity, records and receipts, remaining fault counters, catalog profile, prior result rows, and hashes/lengths of their evidence files.

The checkpoint is replaced atomically. If an action fails an assertion or execution is interrupted before its checkpoint is written, the most recent verified boundary remains available. A checkpoint does not claim to recover partially executed production transactions: continuation creates a new synthetic fixture and discards uncheckpointed local effects there. The original run remains untouched.

### Start and continue

```powershell
& .\.venv\Scripts\python.exe -m simlab.resume start --manifest runs\graph-chaos\campaign-stdio-hardened\campaign.json --mode hardened --transport sse --stop-after 6 --output runs\campaign-partial
& .\.venv\Scripts\python.exe -m simlab.resume continue --checkpoint runs\campaign-partial\checkpoint.json --output runs\campaign-continued
```

`start` accepts a version-2 graph manifest and defaults to hardened/stdio. `--stop-after` is the total completed-action boundary, including zero; omitting it runs to the end. A partial report is marked `checkpointed` and identifies remaining work. `continue` requires the checkpoint, preserves its mode and transport, and can stop at a later boundary using another `--stop-after` value. Output folders must be new.

### What recovery validates and restores

Before starting a resumed server, the runner:

1. Verifies the checkpoint checksum and the graph manifest hash.
2. Validates the manifest, saved action sequence, mode, transport, evidence paths, and evidence hashes.
3. Reconstructs the reference oracle from the initial state and recorded responses, including each race's saved legal serialization.
4. Requires exact agreement with the checkpoint's records, complete receipts, fault counters, and catalog profile.
5. Copies the verified evidence prefixes into a flat `history` folder and restores state in a fresh fixture.

Sessions and receipt keys retain their synthetic identity so saved idempotency receipts remain valid. Server fault counters resume with the consumed faults removed, preventing accidental reinjection. A compact catalog remains compact until its recorded restoration action. Connections and subscriptions are recreated rather than persisted. Earlier rows retain their recorded responses and callback traces; their evidence links point to the copied history.

Streamable HTTP is also supported by `start` and `continue`. Checkpoints preserve the controlled client's workspace/outside/empty root declaration mode, so resuming after workspace withdrawal cannot silently restore it. Native HTTP session identifiers and root notification generations belong to the live connection and are recreated. Older checkpoints without `client_root_mode` remain readable and default to workspace roots.

Checkpoints can be continued repeatedly. Evidence filenames use content hashes, keeping history paths bounded rather than nesting a new directory on every continuation. Move the whole campaign folder when moving a checkpoint: its manifest and evidence prefixes are required. Extra log data appended after the saved boundary is not copied as completed evidence. State is recovered from the checkpoint, not from an unverified current `state.json`.

Limits are 20 MB per checkpoint, 64 MB per evidence file prefix, and 256 MB of referenced evidence. Evidence paths must remain inside the original campaign folder, including after symlink resolution. Integrity hashes detect corruption; the reference oracle also rejects internally inconsistent state even if a checksum is recomputed. These are local simulation artifacts, not signed approval records.

## Protocol performance metrics

Every full report export derives metrics from the unique `wire.jsonl` files referenced by its rows. It writes `performance.json`, `performance.csv`, and a capability table in the HTML dashboard. JSON/CSV include per-operation metrics such as `tools/call` plus its exact tool name; the HTML table groups those measurements by capability, mode, transport, and direction.

Only the proxy's `client_send` and `client_receive` boundary records contribute message volume and latency. Forwarding stages are excluded so each logical message is counted once. Resumed campaign history is measured in separate audit segments, avoiding request-ID and clock collisions between connections.

### Correlation and counts

- Client requests are paired with server responses; server-initiated requests are paired with client responses separately. Numeric and string request IDs remain distinct, and opposite directions may reuse the same ID.
- Completed counts include successful responses and explicit errors. Tool-result errors and JSON-RPC errors are counted separately.
- Explicit cancellation closes a pending request as cancelled without inventing a completed latency sample.
- Unanswered requests remain pending. Unmatched responses, duplicate request IDs, and invalid records are exposed in totals. Ambiguous duplicate IDs do not create latency samples.
- Notifications contribute to total logical message volume but do not receive request/response latency samples.

The median uses the ordinary sample median. P95 uses nearest rank (`ceil(0.95 * sample_count)`), and the maximum is also exported. Empty groups have no percentile value. Capability percentiles are calculated from the combined samples, not by averaging operation percentiles.

### Interpretation

Timings use the proxy's monotonic elapsed clock, from a request crossing the client boundary to its corresponding response crossing that boundary. They measure MCP messages rather than the duration of an entire Python client method. Catalogue refreshes and validation work can produce additional messages.

Logical bytes are the size of compact UTF-8 JSON payloads. They exclude HTTP/SSE framing, pipe whitespace, TCP overhead, and other transport encoding overhead. Per-operation volume includes its requests and matched responses; totals also include notifications and unmatched messages.

Intentional tool delays, callback delays, failures, protocol rejections, server startups, and the host workload affect measurements. These figures characterize the configured simulation, not production throughput or language-model performance. Use the retained counts and operation breakdown when comparing runs. Re-exporting existing recorded evidence can add the metrics without rerunning its actors.

## Tests

Checkpoint tests stop and continue both modes over stdio and SSE, including compact catalogs and post-commit acknowledgment failures. They check repeated continuation, unchanged source artifacts, corruption and path-escape rejection, uncheckpointed state discard, fixed mode/transport binding, and reference-oracle consistency.

Performance tests exercise bidirectional ID collisions, percentiles, errors, cancellations, unanswered requests, duplicated audit references, malformed records, and CSV formula escaping. Existing report tests continue to validate escaping, portable evidence links, and saved-review identity.
