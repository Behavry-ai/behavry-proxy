"""
Stdio MCP backend.

Spawns an MCP server process and communicates over stdin/stdout using
the MCP stdio transport (newline-delimited JSON-RPC).
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any

from behavry_proxy.proxy.mcp import JsonRpcRequest, JsonRpcResponse, JsonRpcError

logger = logging.getLogger(__name__)

JSONRPC_INTERNAL_ERROR = -32603
JSONRPC_TIMEOUT = -32001


class StdioBackend:
    """
    Manages a long-running MCP server subprocess communicating over stdio.

    The process is started lazily on first use and kept alive for the
    duration of the session. If it crashes, it's restarted on the next call.
    """

    def __init__(
        self,
        command: list[str],
        env: dict[str, str] | None = None,
        timeout: float = 120.0,
    ) -> None:
        self.command = command
        self.env = env
        self.timeout = timeout
        self._process: asyncio.subprocess.Process | None = None
        self._lock = asyncio.Lock()
        self._pending: dict[str | int, asyncio.Future] = {}
        self._reader_task: asyncio.Task | None = None

    async def _ensure_process(self) -> asyncio.subprocess.Process:
        async with self._lock:
            if self._process is None or self._process.returncode is not None:
                await self._start_process()
        return self._process  # type: ignore

    async def _start_process(self) -> None:
        """Start the MCP server subprocess."""
        env = {**os.environ}
        if self.env:
            env.update(self.env)

        logger.info("Starting stdio MCP backend: %s", self.command)
        self._process = await asyncio.create_subprocess_exec(
            *self.command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        if self._reader_task and not self._reader_task.done():
            self._reader_task.cancel()
        self._reader_task = asyncio.create_task(self._read_responses())
        logger.info("Stdio MCP backend started (pid=%d)", self._process.pid)

    async def _read_responses(self) -> None:
        """Background task: read newline-delimited JSON responses from stdout."""
        assert self._process and self._process.stdout
        try:
            async for line in self._process.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    msg_id = data.get("id")
                    if msg_id is not None and msg_id in self._pending:
                        future = self._pending.pop(msg_id)
                        if not future.done():
                            future.set_result(data)
                except json.JSONDecodeError as exc:
                    logger.warning("Stdio backend invalid JSON: %s", exc)
        except Exception as exc:
            logger.error("Stdio backend reader error: %s", exc)
            for future in self._pending.values():
                if not future.done():
                    future.set_exception(exc)
            self._pending.clear()

    async def forward(self, request: JsonRpcRequest) -> JsonRpcResponse:
        """
        Send a JSON-RPC request over stdin and await the response on stdout.
        """
        try:
            proc = await self._ensure_process()
        except Exception as exc:
            return JsonRpcResponse(
                id=request.id,
                error=JsonRpcError(
                    code=JSONRPC_INTERNAL_ERROR,
                    message=f"Failed to start stdio backend: {exc}",
                ),
            )

        line = json.dumps(request.model_dump(exclude_none=True)) + "\n"
        try:
            assert proc.stdin
            proc.stdin.write(line.encode())
            await proc.stdin.drain()
        except Exception as exc:
            return JsonRpcResponse(
                id=request.id,
                error=JsonRpcError(
                    code=JSONRPC_INTERNAL_ERROR,
                    message=f"Stdin write error: {exc}",
                ),
            )

        # JSON-RPC notifications have no id and expect no response
        if request.id is None:
            return JsonRpcResponse(id=None, result={})

        req_id = request.id
        future: asyncio.Future[dict] = asyncio.get_event_loop().create_future()
        self._pending[req_id] = future

        try:
            data = await asyncio.wait_for(future, timeout=self.timeout)
            return JsonRpcResponse.model_validate(data)
        except asyncio.TimeoutError:
            self._pending.pop(req_id, None)
            return JsonRpcResponse(
                id=request.id,
                error=JsonRpcError(
                    code=JSONRPC_TIMEOUT,
                    message=f"Stdio backend timed out after {self.timeout}s",
                ),
            )
        except Exception as exc:
            return JsonRpcResponse(
                id=request.id,
                error=JsonRpcError(
                    code=JSONRPC_INTERNAL_ERROR,
                    message=f"Stdio backend error: {exc}",
                ),
            )

    async def close(self) -> None:
        """Terminate the subprocess gracefully."""
        if self._reader_task and not self._reader_task.done():
            self._reader_task.cancel()
        if self._process and self._process.returncode is None:
            try:
                self._process.terminate()
                await asyncio.wait_for(self._process.wait(), timeout=5.0)
            except Exception:
                self._process.kill()
