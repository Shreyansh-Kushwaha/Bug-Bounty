"""Thread-local stdout tee for the web runner.

The CLI pipeline logs via two rich.Console instances (one in orchestrator, one
in agents/base). Both default to sys.stdout. When the web runner starts a run
in a worker thread it sets a thread-local StringIO; install() redirects both
Consoles' file attribute to a Tee that writes to the real stdout AND to that
thread-local buffer. Other threads (including the uvicorn workers) see the
buffer as None and only hit real stdout.
"""

from __future__ import annotations

import sys
import threading
from io import StringIO

_local = threading.local()


class _Tee:
    """Write-through file object: real stdout + current thread's buffer."""

    def __init__(self):
        self._real = sys.__stdout__

    def write(self, s: str) -> int:  # noqa: D401
        try:
            self._real.write(s)
        except (OSError, ValueError):
            pass
        buf: StringIO | None = getattr(_local, "buf", None)
        if buf is not None:
            # Cap buffer at ~256KB to stop memory creeping on long runs.
            if buf.tell() > 256_000:
                current = buf.getvalue()[-200_000:]
                buf.seek(0)
                buf.truncate()
                buf.write(current)
            buf.write(s)
        return len(s)

    def flush(self) -> None:
        try:
            self._real.flush()
        except (OSError, ValueError):
            pass

    def isatty(self) -> bool:
        return False


_tee: _Tee | None = None


def install() -> None:
    """Idempotently redirect both module-level Consoles' .file through the tee."""
    global _tee
    if _tee is not None:
        return
    _tee = _Tee()
    from src import orchestrator
    from src.agents import base as agent_base

    orchestrator.console.file = _tee
    agent_base.console.file = _tee


def set_buffer(buf: StringIO | None) -> None:
    """Set (or clear) the current thread's capture buffer."""
    _local.buf = buf


def tail(buf: StringIO, max_chars: int = 20_000) -> str:
    """Return the last `max_chars` of the buffer."""
    text = buf.getvalue()
    return text[-max_chars:] if len(text) > max_chars else text
