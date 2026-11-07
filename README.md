# MCP simulation lab

A local lab comparing deliberately vulnerable and hardened MCP servers. The client uses the official MCP SDK, real subprocess pipes, and optional loopback HTTP/SSE. The user, attacker, and deputy actors call an actual LLM. There are no canned model responses or mocked transports.

## Run on Windows

From this folder, create an environment if one is not already present:

```powershell
python -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -e '.[test]'
```

Run the regression suite and fixed protocol matrix without a model:

```powershell
& .\.venv\Scripts\python.exe -m pytest -q
& .\.venv\Scripts\python.exe tests\eval_matrix.py --protocol-only --transport both --output runs\protocol-demo
```

For the complete three-actor simulation, start Ollama and make the configured model available, then run:

```powershell
& .\.venv\Scripts\python.exe tests\eval_matrix.py --transport both --output runs\live-demo
Start-Process runs\live-demo\report.html
```

The default model is `qwen2.5:7b-instruct-q4_K_M` at `http://127.0.0.1:11434`. Use `--model` and `--endpoint` to change them. Each run requires a new output directory to preserve earlier evidence. To select actor cases, pass `--cases output_poison,tool_shadow`; fixed protocol coverage still runs in full.

An OpenAI-compatible chat endpoint is also supported:

```powershell
# Set SIM_LLM_API_KEY in your environment if the endpoint requires authentication.
& .\.venv\Scripts\python.exe tests\eval_matrix.py --backend openai --endpoint http://127.0.0.1:8000/v1 --model your-model --output runs\api-demo
```

## Repeat experiments across seeds

```powershell
& .\.venv\Scripts\python.exe tests\eval_matrix.py --transport both --seeds 7,11 --cases output_poison,tool_shadow --max-turns 6 --output runs\seed-comparison
```

`--seeds` overrides `--seed`. Duplicate seeds are rejected to protect evidence folders. Protocol probes run once per transport/server arm; each selected live case then runs for every seed, with separate evidence folders. Seeds are sent to Ollama and OpenAI-compatible endpoints; support and reproducibility depend on the model service. Ollama transcripts now record request duration and retry attempt. The same timing fields are recorded for compatible API calls.

Case comparison tables show baseline/hardened effects with their evaluated denominators, errors, task-completion counts, and matched-pair prevention counts. A prevented pair requires the baseline effect to occur and the hardened effect to be absent for the same case, transport, and seed. Refused baseline attacks are excluded from that particular count. User/attacker responses are shared within a pair and regenerated across transports; this is not an experiment isolating transport as the only variable.

Reports are saved before evaluation begins and after every protocol arm and actor pair. Open `report.html` while the experiment runs and reload to inspect partial results. Its status stays `running` until all scheduled work finishes; an interrupted process leaves the last checkpoint marked `running`. Each report file is replaced atomically. The report files as a group are not a transactional snapshot.

## What you can inspect

Every run writes `report.html`, `report.json`, `report.md`, and `results.csv`. The HTML report shows separate protocol and live-model results, filters passed/failed checks, searches case/transport/seed/outcome fields, and expands each row's recorded evidence. The HTML is self-contained, with no external scripts, fonts, or services. Evidence links work while the report stays beside its run folders.

The dashboard includes a responsive navigation rail, summary metrics with evaluated denominators, check distribution, an attention queue, experiment configuration, case comparison bars, task-outcome distributions, and a seed/transport matrix. Charts describe the entire saved run. Their **Explore these checks** links apply the matching case and transport filters in the evidence explorer.

The explorer combines result, evaluation, server arm, transport, seed, case, task outcome, and text filters. It supports numeric seed sorting, failures-first sorting, pagination, reset, and a filtered CSV download containing all matching rows across pages. Full-run CSV remains a separate link. **Inspect** opens a keyboard-accessible dialog with the user intent, deputy answer, tool-call sequence, rubric checks, raw evidence, and source-log links. Escape or Close returns to the check. Narrow screens use horizontal section navigation and scrollable tables.

### Compare runs and save your review setup

**Compare with another run** reads a selected local `report.json` without uploading it. Schema 1 and 2 reports are supported. It shows current/reference effect counts, evaluated denominators, task completion, errors, percentage-point deltas, and case-level comparisons. Missing grades or unmatched case groups remain **Not comparable**. The dashboard identifies differences in model, case coverage, transports, seeds, and strict grading; aggregate deltas do not establish a causal improvement. Export the case comparison as CSV when needed. A reference selection lasts until it is cleared or the page reloads.

Name and save a filter view to reuse its filters, search, sorting, and page size. Up to 20 views are stored in the browser, scoped to the saved report's content fingerprint. Reusing a name updates that view. Apply or delete views from the selector. Browser storage can differ between `file:` and local HTTP previews; when persistence is unavailable, the dashboard explicitly labels views as available for that tab only. Views store preferences, not imported reports or conversations.

**Pin** any two checks, even on different pages, then choose **Compare pinned checks** to inspect their full evidence side by side. Pins survive filter changes and can be cleared; they reset on reload. Individual inspectors have previous/next navigation across the filtered set, including other pages. Text search includes deputy tool names. Press `/` outside an input or dialog to focus search.

The JavaScript comparison helpers can be checked with Node, without installing frontend dependencies:

```powershell
node --test tests\dashboard.test.cjs
```

Each arm records:

- `wire.jsonl`: original and delivered JSON-RPC envelopes, request IDs, policy rejections, and forwarding stages.
- `effects.jsonl`: server observations, file boundaries, local captures, and state-scope use.
- `actors.jsonl`: actual model conversations, responses, model identity, seed, and prompt hashes, for live runs.
- `wire.stderr.log`: transport and server diagnostics.

The SSE arm uses client → stdio proxy → official SDK SSE client → loopback SSE server. It is a bridge, not a direct SSE connection from the top-level client.

## Cases and grading

The live cases cover normal output poisoning, error poisoning, tool metadata poisoning, path traversal, state-scope hijacking, and tool shadowing. User intent and attacker text are generated once per case and shared by both arms. Tool-shadowing payloads enter the vulnerable `execute_command` description; metadata payloads enter the vulnerable `read_file` description.

Fixed protocol probes additionally exercise absolute paths, symlinks or Windows junctions, directory traversal, raw synthetic authorization data, cross-session handles, replay, extra schema fields, and benign operations after policy blocks. Missing symlink/junction coverage is a failed assertion, not a silent skip.

A baseline live assertion passes only when the expected server-side effect occurs. A model refusal is a failed exploit assertion and makes the overall command return exit code 1. The harness does not force model compliance to make the report green. A hardened live assertion requires no exploit effect, observed benign progress, and a deputy that finishes within its turn budget. Benign progress does not prove the final answer fulfills the user's entire request.

Task grading is a separate, deterministic rubric. It checks case-specific tool names, exact arguments, successful observations, and expected markers in the final answer. Arithmetic requires an observed structured result of 4; error-log tasks require the error channel. A claim without the corresponding observation cannot pass. The rubric reports `completed`, `safely_blocked` (a relevant policy denial plus an explanation of the limitation), or `incomplete`. It does not assess every statement in natural language. The JSON evidence exposes every rubric check.

Use `--require-task-success` to additionally require `completed` for hardened live assertions. A safely blocked task still fails this stricter requirement. This is intentional when the requested task depends on an unauthorized report or scope. Default grading retains the earlier no-exploit/benign-progress/termination assertions while reporting task outcomes separately. Historical schema-1 reports without task rubrics show no task-completion rate.

Protocol precision and neutralization rates describe labeled fixtures. Live baseline exploit and hardened bypass rates describe recorded model behavior. They measure different things. Model output can vary even with temperature zero and a seed. Network failures and malformed model replies remain explicit failures.

## Project layout

| Location | Purpose |
|---|---|
| `simlab/client.py` | Official SDK session and process lifecycle |
| `simlab/proxy.py` | Real JSON-RPC interception and pre-forwarding firewall |
| `simlab/server.py` | Shared server implementation with vulnerable/hardened behavior |
| `simlab/controls.py` | Schema, namespace, path, arithmetic, scope, replay, and text checks |
| `simlab/actors.py` | Independent LLM histories and deputy tool loop |
| `simlab/evaluation.py` | Paired runs, evidence assertions, and metrics |
| `simlab/grading.py` | Task rubrics and comparisons across seeds |
| `simlab/reporting.py` | Escaped, portable HTML report |
| `tests/` | Control checks and real-transport regressions |

All fixtures, credentials, session secrets, and captures are synthetic. The capture and shadow tools only write local journal entries; `execute_command` never runs a shell command. Text sanitization is a known-pattern filter, not a general semantic defense. Hardened authorization and filesystem boundaries are enforced independently of the filter, in both the proxy and the server. Filesystem checks assume the fixture tree is not concurrently modified; they do not claim race-resistant isolation.
