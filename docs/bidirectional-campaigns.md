# Bidirectional scenarios and campaigns

Dense scenarios now exercise MCP requests initiated by the server as part of a tool call. The client can advertise roots, sampling, and form elicitation independently. Tools check the required capabilities before starting their callback sequence.

| Tool | Inputs | Behavior |
|---|---|---|
| `inspect_client_roots` | `{}` | Requests `roots/list`, classifies the configured workspace, and rejects duplicate or excessive roots |
| `sample_incident` | `record_id` | Requests `sampling/createMessage` with only the authorized record, `includeContext: none`, and a 256-token limit |
| `request_incident_input` | `record_id` | Requests `elicitation/create` with a review form; returns accept, decline, or cancel without a write |
| `guided_update_record` | Same arguments as `update_record` | Combines client roots, sampling, a request-specific approval, and a final guarded commit |

The hardened names have the usual `sim_` prefix. These tools are absent from core catalogs. Their MCP annotations identify client interaction with `openWorldHint: true`; permission checks remain independent of these hints. Summaries and review forms are read-only. Guided updates are writes and advertise hardened idempotency.

## Guided update sequence

1. Validate record authority, write-handle scope, and request shape.
2. Check for a matching hardened receipt. A valid retry returns the saved snapshot without asking the client again; a changed payload or operation using the same key fails.
3. Require all three client capabilities, then preview the proposed version and transition.
4. Request client roots. The hardened workflow requires the exact configured workspace URI to be advertised. Root declarations never expand the server's allowed filesystem paths.
5. Request a summary of the current synthetic record. The result must be assistant text, nonempty, at most 4,096 characters, and complete rather than token-truncated. Hardened output filtering applies to the summary; its content never determines the target record, status, handle, or version.
6. Request a confirmation form. The form displays the proposed record, version, and status. Its digest binds confirmation to the session, full tool arguments, and a fresh challenge. Accepted content must contain exactly a boolean `confirm` and the matching digest. Extra fields, missing digests, copied approvals, and string booleans fail validation.
7. On decline, cancellation, or `confirm: false`, return a normal non-commit result. No record or receipt changes occur.
8. On accepted confirmation, revalidate versions, permissions, transitions, and dependencies under the store lock. A competing writer can therefore invalidate an earlier preview or approval. Publish the state and receipt atomically, then send resource notifications.

Guided receipts use a distinct operation fingerprint. A receipt from ordinary `update_record` cannot stand in for guided approval. A lost post-commit acknowledgment is retried with identical arguments, exactly as for the other state tools. The vulnerable arm deliberately lacks authority/version/idempotency enforcement, but still validates form responses and honors client refusal so those client decisions remain testable.

## Callback errors and deadlines

Trusted fixture configuration sets a server callback deadline of 2 seconds by default, bounded to 0.05–10 seconds. Interactive probes use at least 2 seconds, increasing to 0.1 seconds per concurrent request when that is larger. The slow-client profile explicitly exceeds that budget; normal concurrency probes therefore do not inherit an artificially short timeout. Client callback wrappers have a separate default 5-second deadline, bounded to 0.05–30 seconds. Missing callback functions do not advertise the corresponding capability.

Client exceptions, returned error responses, and malformed result objects become protocol errors rather than terminating the SDK receive loop. The server converts failed, malformed, or timed-out callback requests into tool errors. Unfinished workflows do not commit. Late responses may arrive after a server deadline; subsequent pings and benign operations must still work. Long-running custom callbacks should use a client deadline appropriate for the experiment.

The proxy keeps response correlation separate in each JSON-RPC direction. A server request may legally use the same numeric ID as an outstanding client request. Receiving a server request must not remove the client's pending response mapping. Concurrent sampling tests exercise this overlap over both transports.

## Controlled clients and trace inspection

`ControlledClient` explicitly simulates a client policy for fixed protocol experiments. It can advertise workspace, empty, duplicate, or outside roots; return normal, instruction-like, invalid-role, refused, or delayed sampling responses; and accept, decline, cancel, or mismatch confirmation forms.

These are controlled protocol responses. They do not measure a model, an actual person's approval behavior, or a real client's UI. Live actor scenarios continue to use their configured model endpoint. New callback tools used by an ordinary client without the required capabilities return an explicit capability error.

Each callback is recorded in `client.jsonl` with its operation, request, response, policy profile, and duration. The HTML inspector displays per-check server-to-client request sequences. Evidence links include the callback journal, campaign manifest, and final state file, restricted to files inside the report folder. Payload text is escaped in the HTML.

The **Capabilities exercised** table groups recorded protocol assertions by feature, server arm, and transport. It reports counts rather than claiming full MCP conformance or general language-model capabilities.

## Seeded campaigns and replay

Campaigns are opt-in through `--campaign-steps` (up to 200 actions). The generator combines:

- Valid transitions and accepted confirmations.
- Read-only handles and protected records.
- Stale expected versions and forbidden status changes.
- Declines, cancellations, false confirmations, and mismatched approval digests.
- Identical key/payload retries every seventh action and changed-payload key reuse every eleventh action, with the seventh-action rule taking priority.

The generator uses only its integer seed and a local reference workload state. It produces the same manifest for either server mode or transport. Each arm executes that manifest against its own fresh fixture, so their published states can diverge.

After each actual MCP operation, a reference state model predicts the response class and selected result fields, the entire incident-record map, and receipt count. Those expectations are compared with the published state file. An error, refusal, or invalid approval cannot silently introduce a partial mutation. An identical hardened retry must retain its original result snapshot. The model is a regression oracle for the specified rules, not an independent security proof.

`campaign.json` is schema-versioned and includes the seed, exact tool arguments, and client approval profile for every action. Replay starts from a fresh fixture and uses the saved actions; tool results and state are recomputed. Approval challenges and durations can differ while outcomes remain reproducible. Both arms can replay a manifest originally saved by either arm.

Version-1 manifest validation rejects files over 1 MB, unknown fields or versions, unsupported approval profiles, invalid tool arguments, empty or oversized action lists, and references outside the independent synthetic incident/PAY record set. Version 2 adds bounded DAGs and parallel action groups, described in [dependency graph campaigns](dependency-graph-campaigns.md). Manifests cannot name arbitrary tools, commands, paths, or endpoints. `--replay-campaign` takes precedence over generation settings; reports record the manifest's actual seed and action count.

## Tests

`tests/test_bidirectional.py` runs guided updates and retries over stdio and SSE, tests missing and partial capability negotiation, client refusal, malformed approvals, callback exceptions and invalid results, server/client deadlines and late responses, root boundaries, concurrent request-ID collisions, stale approvals after an intervening writer, and direct hardened-server enforcement without the proxy. The concurrent writer fixture is explicitly controlled test state, while the composed scenarios also exercise real concurrent guided requests.

`tests/test_campaign.py` checks deterministic manifest generation, rejection of invalid replay data, complete campaign outcomes across seeds, modes, and transports, and saved-manifest replay equivalence. Reporting tests verify capability counts, callback trace escaping, and local-only evidence links.
