"""Start or continue a graph campaign at a verified checkpoint boundary."""
from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
from pathlib import Path

from .campaign import read_manifest
from .checkpoint import load_checkpoint
from .dependency_graph import validate_graph
from .evaluation import summarize
from .graph_campaign import graph_campaign_matrix
from .reporting import write_reports


async def execute(args):
    checkpoint = Path(args.checkpoint).resolve() if args.checkpoint else None
    if args.command == "continue":
        manifest, saved = load_checkpoint(checkpoint)
        mode, transport = saved["mode"], saved["transport"]
    else:
        manifest = read_manifest(Path(args.manifest))
        mode, transport = args.mode or "hardened", args.transport or "stdio"
    if manifest["schema_version"] != 2:
        raise ValueError("resuming is available for dependency graph campaigns only")
    output = Path(args.output).resolve()
    if output.exists():
        raise ValueError("output must be a new directory; original campaign evidence is preserved")
    rows = await graph_campaign_matrix(output, mode, transport, manifest,
                                       stop_after=args.stop_after, resume_checkpoint=checkpoint)
    status = "completed" if len(rows) == len(manifest["actions"]) else "checkpointed"
    report = {"schema_version": 2, "status": status, "updated_at": datetime.now(timezone.utc).isoformat(),
        "model": {"model": "controlled-protocol-client"}, "summary": summarize(rows), "rows": rows,
        "experiment": {"suite": "dense", "transport": transport, "protocol_only": True,
            "campaign_seed": manifest["seed"], "campaign_steps": len(manifest["actions"]),
            "completed_campaign_steps": len(rows), "campaign_graph_nodes": len(manifest["graph"]),
            "campaign_graph_width": max(map(len, validate_graph(manifest["graph"]))),
            "resumed": checkpoint is not None},
        "methodology": ["Graph campaign protocol checks use controlled clients, not live model decisions.",
            "Resume reconstructs the reference oracle and restores a verified action boundary in a new fixture.",
            "Uncheckpointed local fixture effects are discarded. This is simulation recovery, not production transaction recovery."]}
    write_reports(report, output)
    print(f"{status}: {len(rows)}/{len(manifest['actions'])} actions; checkpoint: {output / 'checkpoint.json'}")
    return 0 if report["summary"]["passed"] else 1


def main():
    parser = argparse.ArgumentParser(description="Resumable dependency graph campaigns")
    parser.add_argument("command", choices=["start", "continue"])
    parser.add_argument("--manifest")
    parser.add_argument("--checkpoint")
    parser.add_argument("--output", required=True)
    parser.add_argument("--mode", choices=["hardened", "vulnerable"])
    parser.add_argument("--transport", choices=["stdio", "sse"])
    parser.add_argument("--stop-after", type=int, help="Stop at this total completed-action boundary")
    args = parser.parse_args()
    if args.command == "start" and (not args.manifest or args.checkpoint):
        parser.error("start requires --manifest and does not accept --checkpoint")
    if args.command == "continue" and (not args.checkpoint or args.manifest):
        parser.error("continue requires --checkpoint and preserves the saved mode and transport")
    if args.command == "continue" and (args.mode or args.transport):
        parser.error("continue uses the checkpoint's mode and transport; omit --mode and --transport")
    try:
        code = asyncio.run(execute(args))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.error(str(exc))
    raise SystemExit(code)


if __name__ == "__main__":
    main()
