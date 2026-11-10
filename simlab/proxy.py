"""A real stdio intermediary; optionally bridges to an actual HTTP/SSE server.

Every wire envelope is recorded before transformation. A blocked call is answered
locally and is never forwarded to the target. stdout contains JSON-RPC only.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path

from .controls import Denied, Firewall, load_config, sanitize


class Audit:
    def __init__(self, path: Path):
        self.path = path
        self.sequence = 0
        self.started = time.perf_counter_ns()

    def record(self, stage: str, payload: dict, **extra):
        self.sequence += 1
        with self.path.open("a", encoding="utf-8") as out:
            out.write(json.dumps({"sequence": self.sequence, "stage": stage,
                                  "elapsed_ns": time.perf_counter_ns() - self.started,
                                  "payload": payload, **extra}, ensure_ascii=True) + "\n")


@asynccontextmanager
async def downstream(config_path: str, mode: str, url: str | None, http_url: str | None = None):
    if http_url:
        import httpx
        from mcp.client.streamable_http import streamable_http_client
        from mcp.shared.message import SessionMessage
        from mcp.types import JSONRPCMessage
        async with httpx.AsyncClient(timeout=httpx.Timeout(30, read=300), trust_env=False) as http:
            async with streamable_http_client(http_url, http_client=http) as (reader, writer, get_session_id):
                async def send(payload):
                    await writer.send(SessionMessage(JSONRPCMessage.model_validate(payload)))
                async def receive():
                    async for item in reader:
                        if isinstance(item, Exception):
                            raise item
                        yield item.message.model_dump(mode="json", by_alias=True, exclude_none=True)
                yield send, receive
        return
    if url:
        from mcp.client.sse import sse_client
        from mcp.shared.message import SessionMessage
        from mcp.types import JSONRPCMessage
        async with sse_client(url, timeout=10) as (reader, writer):
            async def send(payload):
                await writer.send(SessionMessage(JSONRPCMessage.model_validate(payload)))

            async def receive():
                async for item in reader:
                    if isinstance(item, Exception):
                        raise item
                    yield item.message.model_dump(mode="json", by_alias=True, exclude_none=True)
            yield send, receive
    else:
        proc = await asyncio.create_subprocess_exec(
            sys.executable, "-m", mode + "_mcp", "--config", config_path,
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=sys.stderr,
        )
        async def send(payload):
            proc.stdin.write((json.dumps(payload) + "\n").encode())
            await proc.stdin.drain()

        async def receive():
            while line := await proc.stdout.readline():
                yield json.loads(line)
        try:
            yield send, receive
        finally:
            if proc.returncode is None:
                proc.stdin.close()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=3)
                except TimeoutError:
                    proc.kill()
                    await proc.wait()


async def run(config_path: str, mode: str, audit_path: str, url: str | None, http_url: str | None = None):
    firewall = Firewall(load_config(config_path))
    audit = Audit(Path(audit_path))
    pending = {}
    audit.record("transport", {"kind": "streamable-http" if http_url else "sse" if url else "stdio", "endpoint": http_url or url})

    def output(payload):
        audit.record("client_receive", payload)
        sys.stdout.write(json.dumps(payload, ensure_ascii=True) + "\n")
        sys.stdout.flush()

    async with downstream(config_path, mode, url, http_url) as (send, receive):
        async def requests():
            # A thread reads the real pipe on Windows, where add_reader is unsupported.
            while line := await asyncio.to_thread(sys.stdin.buffer.readline):
                payload = json.loads(line)
                audit.record("client_send", payload)
                method = payload.get("method")
                if mode == "hardened" and method == "tools/call":
                    params = payload.get("params", {})
                    try:
                        firewall.check(params.get("name", ""), params.get("arguments", {}))
                    except (Denied, OSError) as exc:
                        reason = str(exc) if isinstance(exc, Denied) else "path_unavailable"
                        audit.record("policy_block", payload, reason=reason)
                        output({"jsonrpc": "2.0", "id": payload["id"], "result": {
                            "isError": True, "content": [{"type": "text", "text": json.dumps({"blocked": reason})}]}})
                        continue
                if "id" in payload and method:
                    pending[payload["id"]] = method
                audit.record("server_send", payload)
                await send(payload)

        async def responses():
            async for payload in receive():
                audit.record("server_receive", payload)
                # JSON-RPC request IDs are independent in the two directions.
                method = pending.pop(payload.get("id"), None) if "method" not in payload else None
                if mode == "hardened":
                    if method in ("tools/list", "resources/list", "prompts/list") and "result" in payload:
                        key = {"tools/list": "tools", "resources/list": "resources", "prompts/list": "prompts"}[method]
                        for entry in payload["result"].get(key, []):
                            entry["description"] = sanitize(entry.get("description", ""))
                    elif method in ("tools/call", "resources/read", "prompts/get"):
                        payload = sanitize(payload)
                    elif "method" in payload:
                        if payload["method"] == "notifications/progress":
                            # Progress tokens are opaque correlation identifiers, not prose.
                            params = payload.get("params", {})
                            payload = {**payload, "params": {**params,
                                **({"message": sanitize(params["message"])} if "message" in params else {})}}
                        elif payload["method"] != "notifications/resources/updated":
                            payload = sanitize(payload)
                output(payload)

        tasks = [asyncio.create_task(requests()), asyncio.create_task(responses())]
        try:
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--mode", choices=["vulnerable", "hardened"], required=True)
    parser.add_argument("--audit", required=True)
    parser.add_argument("--sse-url")
    parser.add_argument("--http-url")
    args = parser.parse_args()
    if args.sse_url and args.http_url:
        parser.error("choose one downstream HTTP transport")
    asyncio.run(run(args.config, args.mode, args.audit, args.sse_url, args.http_url))


if __name__ == "__main__":
    main()
