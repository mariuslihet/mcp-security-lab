from __future__ import annotations

import asyncio
import socket
import sys
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path

import httpx
import anyio
from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client


@asynccontextmanager
async def connect(config: Path, mode: str, audit: Path, transport="stdio", *, message_handler=None,
                  list_roots_callback=None, sampling_callback=None, elicitation_callback=None, callback_timeout=5):
    if type(callback_timeout) not in (int, float) or not 0.05 <= callback_timeout <= 30:
        raise ValueError("callback_timeout must be between 0.05 and 30 seconds")
    def protect(callback, result_type):
        if callback is None:
            return None
        async def guarded(*args):
            try:
                with anyio.fail_after(callback_timeout):
                    result = await callback(*args)
                if isinstance(result, types.ErrorData):
                    return result
                return result_type.model_validate(result)
            except Exception:
                # Keep malformed or failing callbacks from killing the SDK receive loop.
                return types.ErrorData(code=types.INTERNAL_ERROR, message="simulation_client_callback_failed")
        return guarded
    process = None
    errors = audit.with_suffix(".stderr.log").open("w", encoding="utf-8")
    try:
        args = ["-m", "simlab.proxy", "--config", str(config), "--mode", mode, "--audit", str(audit)]
        if transport == "sse":
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
            process = await asyncio.create_subprocess_exec(
                sys.executable, "-m", mode + "_mcp", "--config", str(config),
                "--transport", "sse", "--port", str(port), stdout=errors, stderr=errors)
            async with httpx.AsyncClient(trust_env=False) as http:
                for _ in range(100):
                    if process.returncode is not None:
                        raise RuntimeError("SSE server exited; inspect stderr log")
                    try:
                        await http.get(f"http://127.0.0.1:{port}/", timeout=0.2)
                        break
                    except httpx.TransportError:
                        await asyncio.sleep(0.1)
                else:
                    raise TimeoutError("SSE server did not start")
            args += ["--sse-url", f"http://127.0.0.1:{port}/sse"]
        parameters = StdioServerParameters(command=sys.executable, args=args,
                                           cwd=str(Path(__file__).resolve().parents[1]))
        async with stdio_client(parameters, errlog=errors) as (reader, writer):
            async with ClientSession(reader, writer, read_timeout_seconds=timedelta(seconds=30),
                                     message_handler=message_handler,
                                     list_roots_callback=protect(list_roots_callback, types.ListRootsResult),
                                     sampling_callback=protect(sampling_callback, types.CreateMessageResult),
                                     elicitation_callback=protect(elicitation_callback, types.ElicitResult)) as session:
                await session.initialize()
                yield session
    finally:
        if process and process.returncode is None:
            process.terminate()
            await process.wait()
        errors.close()
