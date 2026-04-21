"""Tamper-evident audit log.

Every agent action is appended as a JSON line whose `hash` = sha256(prev_hash + entry_json).
Any later modification invalidates the chain from that point forward.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any


class AuditLog:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        if not path.exists():
            path.write_text("")

    def append(self, event: str, payload: dict[str, Any]) -> str:
        prev_hash = self._last_hash()
        entry = {
            "ts": time.time(),
            "event": event,
            "payload": payload,
            "prev": prev_hash,
        }
        serialized = json.dumps(entry, sort_keys=True, default=str)
        digest = hashlib.sha256((prev_hash + serialized).encode()).hexdigest()
        line = json.dumps({**entry, "hash": digest}, sort_keys=True, default=str)
        with self.path.open("a") as f:
            f.write(line + "\n")
        return digest

    def _last_hash(self) -> str:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return "GENESIS"
        with self.path.open("rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 4096))
            tail = f.read().decode(errors="ignore")
        lines = [l for l in tail.splitlines() if l.strip()]
        if not lines:
            return "GENESIS"
        return json.loads(lines[-1])["hash"]

    def verify(self) -> tuple[bool, int | None]:
        """Return (ok, first_broken_line_number or None)."""
        prev = "GENESIS"
        if not self.path.exists():
            return True, None
        for i, raw in enumerate(self.path.read_text().splitlines(), 1):
            if not raw.strip():
                continue
            entry = json.loads(raw)
            got = entry.pop("hash")
            serialized = json.dumps(entry, sort_keys=True, default=str)
            expected = hashlib.sha256((prev + serialized).encode()).hexdigest()
            if expected != got or entry.get("prev") != prev:
                return False, i
            prev = got
        return True, None
