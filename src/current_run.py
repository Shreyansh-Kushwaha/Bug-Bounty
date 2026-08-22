"""Thread-local current-run-id.

Set by the web runner at worker-thread start so that the LLM router can
attribute token usage to the correct run. Defaults to None (CLI usage),
in which case usage rows are recorded with run_id=None.
"""

from __future__ import annotations

import threading

_local = threading.local()


def set_run_id(run_id: str | None) -> None:
    _local.run_id = run_id


def get_run_id() -> str | None:
    return getattr(_local, "run_id", None)
