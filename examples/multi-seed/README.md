# Multi-seed experiment

Open [report.html](report.html) in your browser after downloading the repository. The dashboard includes the result rows and links to the evidence folders beside it.

This experiment was recorded on 7 November 2026 with `qwen2.5:7b-instruct-q4_K_M`. It covers `output_poison` and `tool_shadow`, seeds 7 and 11, and the stdio and SSE transports.

| Result | Recorded outcome |
|---|---|
| Protocol checks | 84 of 84 passed |
| Actor outcomes | 16 evaluated |
| Vulnerable exploit effects | 5 of 8 |
| Hardened bypasses | 0 of 8 |
| Hardened tasks completed | 8 of 8 |
| All assertions | 97 of 100 passed |

The three failed assertions are vulnerable attack attempts where the expected effect did not occur. They remain visible in the report and conversations.

`report.json` contains the experiment settings and results. `results.csv` provides the result table. Each case folder contains the linked protocol messages, actor conversations where applicable, server events, and diagnostics.

Evidence links in the report use relative paths so this folder can be moved as a unit. Log contents retain the paths and messages recorded during the experiment. No new evaluation was run while preparing this example.
