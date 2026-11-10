# Streamable HTTP and live client roots

## Stateful Streamable HTTP

Use `--transport streamable-http` for the SDK's stateful Streamable HTTP transport, or `--transport all` for stdio, legacy SSE, and Streamable HTTP. `both` keeps its previous stdio/SSE meaning. The runner starts a loopback server at `/mcp/`, forwards messages through the existing policy/audit proxy, and records the chosen transport and local endpoint in `wire.jsonl`.

Tools, resources, subscriptions, native notifications, sampling, elicitation, and roots callbacks use real MCP messages. The SDK manages HTTP session headers, separate server notification streams, and DELETE termination. The server validates loopback Host/Origin values; unknown or terminated sessions return 404 and hostile origins return 403. This development server listens on 127.0.0.1 and provides no remote authentication service.

## Live roots and approval invalidation

Dense servers handle native `notifications/roots/list_changed` from clients that negotiated roots support. Each live session has its own generation, dirty flag, and last validated workspace declaration. A peer's notifications cannot invalidate another session's snapshot.

| Tool | Result |
|---|---|
| `inspect_client_roots` | Refreshes `roots/list`; returns root URIs, workspace membership, generation, and `dirty: false` |
| `get_client_root_status` | Returns generation, dirty, has_snapshot, and nullable last_workspace_advertised without making a callback |

Hardened tool names have the `sim_` prefix. A change notification increments generation and marks the cached snapshot dirty. A successful inspection clears dirty; a root change during inspection rejects the refresh. The status tool remains available in compact catalog mode to inspect invalidation state.

Guided approvals bind the request digest to the starting roots and generation. Before committing an accepted hardened update, the server rejects a notified change and requests fresh roots to detect silent drift. Losing the declared workspace or changing the root set invalidates approval. Fresh accepted writes therefore make four callbacks: roots, sampling, elicitation, roots. Receipt replays make none. Version, authority, and dependency checks still run at commit. The vulnerable arm intentionally permits root drift for comparison.

Roots remain client declarations; they grant no filesystem permissions. State is maintained per live SDK session with weak references. Notification dispatch uses a session-scoped context around the pinned MCP SDK 1.26.0 message handler because notification handlers do not expose request context; review this adapter when upgrading the SDK.

## Stress and recovery evidence

Graph campaigns combine `--campaign-race-topology mixed` with `--campaign-root-churn`. These add competing write sets, weaker handles, repeated race groups, root withdrawal/restoration, and notified and silent approval-time drift to the existing dependency, lost-acknowledgment, catalog-change, and retry workload. Saved manifests replay the exact profiles; checkpoints preserve root declaration mode across fresh connections.

`tests/test_http_roots.py` checks callback/resource traffic, session isolation, disconnect recovery, HTTP session validation, hostile origins, and both root-drift styles over all three transports. Graph tests compare randomized 24-request overlapping batches and receipt replays against the real incident store, check disjoint parent/child ordering, and run larger live mixed campaigns up to 128 nodes and 32 concurrent requests. These are controlled protocol clients, not live language-model evaluations or a full MCP conformance certification.
