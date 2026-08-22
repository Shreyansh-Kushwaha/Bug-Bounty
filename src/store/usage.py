"""LLM usage tracking. Lives alongside FindingsStore in the same sqlite file.

Every successful LLM call writes one row: provider, model, token counts, ts, run_id.
Queries:
  - run_totals(run_id)          → totals + per-model breakdown for a single run
  - today_by_model()            → today's request count + tokens per model (UTC)
"""

from __future__ import annotations

import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS llm_usage (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    ts                 REAL NOT NULL,
    run_id             TEXT,
    provider           TEXT NOT NULL,
    model              TEXT NOT NULL,
    prompt_tokens      INTEGER NOT NULL DEFAULT 0,
    completion_tokens  INTEGER NOT NULL DEFAULT 0,
    total_tokens       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_usage_run ON llm_usage(run_id);
CREATE INDEX IF NOT EXISTS idx_usage_model_ts ON llm_usage(model, ts);
"""


def _start_of_utc_day(now: float | None = None) -> float:
    now = now if now is not None else time.time()
    dt = datetime.fromtimestamp(now, tz=timezone.utc)
    start = dt.replace(hour=0, minute=0, second=0, microsecond=0)
    return start.timestamp()


class UsageStore:
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def record(
        self,
        *,
        run_id: str | None,
        provider: str,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        total_tokens: int,
    ) -> None:
        self.conn.execute(
            """INSERT INTO llm_usage
               (ts, run_id, provider, model,
                prompt_tokens, completion_tokens, total_tokens)
               VALUES (?,?,?,?,?,?,?)""",
            (
                time.time(), run_id, provider, model,
                prompt_tokens, completion_tokens, total_tokens,
            ),
        )
        self.conn.commit()

    def run_totals(self, run_id: str) -> dict:
        """Return {total, prompt, completion, calls, by_model: [{model, calls, total}]}."""
        cur = self.conn.execute(
            """SELECT COUNT(*),
                      COALESCE(SUM(prompt_tokens),0),
                      COALESCE(SUM(completion_tokens),0),
                      COALESCE(SUM(total_tokens),0)
               FROM llm_usage WHERE run_id = ?""",
            (run_id,),
        )
        calls, prompt, completion, total = cur.fetchone()
        cur = self.conn.execute(
            """SELECT model, COUNT(*), COALESCE(SUM(total_tokens),0)
               FROM llm_usage WHERE run_id = ?
               GROUP BY model ORDER BY 3 DESC""",
            (run_id,),
        )
        by_model = [
            {"model": m, "calls": c, "total": t} for m, c, t in cur.fetchall()
        ]
        return {
            "calls": calls,
            "prompt": prompt,
            "completion": completion,
            "total": total,
            "by_model": by_model,
        }

    def today_by_model(self) -> list[dict]:
        """Per-model request count + tokens since start of current UTC day."""
        start = _start_of_utc_day()
        cur = self.conn.execute(
            """SELECT model,
                      COUNT(*),
                      COALESCE(SUM(prompt_tokens),0),
                      COALESCE(SUM(completion_tokens),0),
                      COALESCE(SUM(total_tokens),0)
               FROM llm_usage WHERE ts >= ?
               GROUP BY model ORDER BY 2 DESC""",
            (start,),
        )
        return [
            {
                "model": m, "calls": c,
                "prompt": p, "completion": comp, "total": t,
            }
            for m, c, p, comp, t in cur.fetchall()
        ]

    def close(self) -> None:
        self.conn.close()
