# Native MCP features

The dense suite includes protocol features beyond ordinary tool calls. Run them without a model:

```powershell
& .\.venv\Scripts\python.exe tests\eval_matrix.py --suite dense --protocol-only --transport both --output runs\native-features
```

Use `--suite all` to include the core suite too. Native probes run in separate fixtures so their mutations and fault counters cannot interfere with other dense scenarios.

## Supported operations

| MCP operation | Behavior |
|---|---|
| `resources/templates/list` | Discovers `lab://incidents/{record_id}` with JSON content |
| `resources/read` | Reads an incident's current ID, status, and version |
| `resources/subscribe` | Subscribes the active MCP session to an authorized incident URI |
| `resources/unsubscribe` | Removes that session's subscription; repeated removals are harmless |
| `notifications/resources/updated` | Announces a committed change to a subscribed incident |
| `prompts/list`, `prompts/get` | Discovers and renders `incident_triage` with required `record_id` argument |
| `completion/complete` | Suggests incident IDs for `incident_triage` or the incident URI template |
| `notifications/progress` | Reports prerequisite planning progress when a request includes a progress token |
| `logging/setLevel`, `notifications/message` | Configures per-session severity thresholds and receives tool outcome logs |
| `notifications/cancelled` | Interrupts an in-flight planning request by its JSON-RPC request ID |
| `ping` | Checks connection health, including after cancellation |
| `tools/list`, `tools/call` | Advertises output schemas and annotations; returns structured results alongside JSON text |
| `notifications/tools/list_changed`, `notifications/resources/list_changed`, `notifications/prompts/list_changed` | Announces a catalog profile change so clients can refresh discovery |

The existing operations-status resource and `incident_review` prompt remain available. The core suite does not advertise subscriptions or completions. The dense server advertises these capabilities during initialization.

`incident_bundle` adds native resource-link tool results. Dynamic profile control, graph analysis, and their stress scenarios are described in [dependency graph campaigns](dependency-graph-campaigns.md).

## Resources and notifications

An incident URI is an exact identifier such as `lab://incidents/INC-001` or `lab://incidents/WF-006`. URI paths with extra segments, query strings, fragments, traversal, or encoded aliases are not accepted. The hardened arm permits only records in the active configuration's allowlist. The vulnerable arm intentionally permits the protected payroll record for contrast.

Subscriptions are sets associated with individual MCP sessions. Subscribing twice does not duplicate notifications. A successful single write or batch sends one notification for each subscribed incident that changed. A failed transaction, update preview, or hardened idempotent replay produces no notification. A lost acknowledgment after commit still sends the notification because state changed. The vulnerable retry performs another mutation and therefore sends another update.

Unsubscribe before another commit to stop updates. Notifications contain the URI rather than a state snapshot: read the resource again for its current version. Subscriptions are connection-local and must be recreated after reconnecting. Delivery is best-effort with a bounded wait per notification. Disconnected receivers are removed when detected; subscriptions do not form a durable event queue. The server rechecks authority before delivery.

The wire journal records notifications delivered through the proxy. Server events include `incident_resource_read`, `resource_subscribed`, `resource_unsubscribed`, and `resource_update_notified`.

## Prompt arguments and completions

Call `incident_triage` with `{"record_id":"WF-006"}`. It renders the current incident and asks the deputy to inspect prerequisites before taking action. Missing, extra, or non-string arguments are rejected. The hardened server also rejects protected IDs.

Completions accept either of these references:

```json
{"type":"ref/prompt","name":"incident_triage"}
```

```json
{"type":"ref/resource","uri":"lab://incidents/{record_id}"}
```

The argument is `{"name":"record_id","value":"WF-"}`. Matching is a case-sensitive prefix match against existing records. Values are sorted, capped at 100, and accompanied by `total` and `hasMore`. Hardened suggestions, totals, and flags are computed after filtering protected records. Unsupported references, argument names, and prefixes longer than 256 characters are rejected. Suggestions do not grant access; resource and prompt requests enforce permissions again.

## Progress and output contracts

`plan_resolution` emits progress only when the request contains a progress token. For the six-incident fixture, progress values are 0 through 6 with total 6. Messages describe the inspected incidents. Progress notifications describe planning; they do not indicate that any incident was modified. The proxy filters message text while preserving the exact opaque progress token, including zero and text that resembles an injection pattern.

Successful tools return matching `structuredContent` and JSON text. Their `outputSchema` describes required fields and types, including incident records, plan steps, pagination, and mutation receipts. Error results may contain text only. Catalog annotations identify tools that read or preview state and indicate hardened write idempotency. Local tools have `openWorldHint: false`; bidirectional tools that request client roots, sampling, or elicitation have `openWorldHint: true`. Annotations describe behavior for clients; permission checks run independently of them.

The lab also supports server-initiated roots, sampling, and form elicitation through [bidirectional workflows and seeded campaigns](bidirectional-campaigns.md).

## Logging and cancellation

Dense servers advertise the MCP logging capability. Logging notifications are opt-in: call `logging/setLevel` first. Tool successes produce `info` messages; server-side failures produce `warning` messages. The configured threshold suppresses less severe messages, and settings belong to individual sessions. Messages identify the tool, outcome, and failure reason without copying tool arguments, handles, or retry keys. Proxy-rejected calls never reach the server and therefore appear in the proxy audit rather than server logging notifications.

Cancellation uses `notifications/cancelled` with the in-flight JSON-RPC request ID. The SDK cancels the associated handler; the server records `request_cancelled`. Planning emits progress between steps, using `--latency-ms` to delay each progress step when requested. Native protocol probes use a fixed 40 ms delay in their separate fixture to make interruption observable. After cancellation the probes ping the same session and perform a benign calculation, and verify that saved state is unchanged. These probes interrupt read-only planning; cancellation does not roll back a write that has already committed. Clients should also cancel their local pending wait when they stop a request, as the cancelled server handler sends no final tool result.

## Client example

This example runs against the local hardened server and proxy. Use a new directory each time, as fixture creation preserves existing runs.

```python
import asyncio
from pathlib import Path
from mcp import types
from simlab.client import connect
from simlab.fixtures import create_fixture

async def main():
    directory = Path("runs/native-client-example")
    config, _ = create_fixture(directory, dense=True)

    async def notifications(message):
        if isinstance(message, types.ServerNotification):
            print(message.model_dump(mode="json", by_alias=True))

    async def progress(current, total, message):
        print(current, total, message)

    async with connect(config, "hardened", directory / "wire.jsonl",
                       message_handler=notifications) as session:
        print(await session.list_resource_templates())
        print(await session.complete(
            types.PromptReference(type="ref/prompt", name="incident_triage"),
            {"name": "record_id", "value": "WF-"}))
        print(await session.get_prompt("incident_triage", {"record_id": "WF-006"}))
        await session.subscribe_resource("lab://incidents/INC-001")
        result = await session.call_tool("sim_plan_resolution",
            {"record_id": "WF-006"}, progress_callback=progress)
        print(result.structuredContent)
        await session.unsubscribe_resource("lab://incidents/INC-001")

asyncio.run(main())
```

Notification callbacks should return promptly and avoid waiting for another request on the same session, since they run in the SDK's receive loop.

The dense deputy discovers resource templates and can read resources, render prompts with arguments, subscribe or unsubscribe, request completions, set logging levels, and ping. These operations use strict wrapper schemas and the real MCP client. Incoming notifications are attached to the next recorded observation and retained in the deputy result. Unknown tool names still pass through the tool transport and firewall.

## Verification

`tests/test_mcp_features.py` checks native discovery, permissions, prompt arguments, completion bounds, progress, token preservation, output contracts, subscription lifecycles, disconnected listeners, authority changes, logging thresholds, cancellation, and deputy operation wrappers. A scripted decision test checks notification delivery to the deputy without claiming to evaluate a model. The suite runs the native protocol matrix against vulnerable and hardened servers over stdio and SSE. A direct hardened-server test verifies that access controls remain effective without the proxy.
