"""Threaded runner: wraps run_pipeline so the web request can return immediately.

- One daemon thread per run.
- Per-run stdout buffer (see log_tee) gives a live log tail to the UI.
- HITL gates: orchestrator calls back into a per-run gate_callback which blocks
  on a threading.Event. The UI's POST /runs/{id}/gate sets the decision and
  wakes the worker.
- Status is reconstructed from artifact files on disk for historical runs.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from io import StringIO
from pathlib import Path

from src.current_run import set_run_id
from src.orchestrator import new_run_context, run_pipeline
from src.web import log_tee


@dataclass
class GateEntry:
    gate: str
    prompt: str
    approved: bool
    decided_at: float


@dataclass
class RunStatus:
    run_id: str
    target: str
    started_at: float
    finished_at: float | None = None
    current_stage: str = "starting"  # starting|recon|analyst|exploit|patch|report|done|error|aborted
    stop_after: str | None = None
    auto_approve: bool = False
    error: str | None = None
    repo: str = ""
    pending_gate: str | None = None
    pending_gate_prompt: str = ""
    gate_history: list[GateEntry] = field(default_factory=list)
    log_buffer: StringIO | None = None  # Not serialized; lives only for live runs.


def _stage_from_artifacts(art_dir: Path, stop_after: str | None) -> str:
    if not art_dir.exists():
        return "starting"
    names = {p.name for p in art_dir.iterdir() if p.is_file()}
    has_report = any(n.startswith("05_report") for n in names)
    has_patch = any(n.startswith("04_patch") for n in names)
    has_exploit = any(n.startswith("03_exploit") for n in names)
    has_analyst = "02_analyst.json" in names
    has_recon = "01_recon.json" in names

    if has_report:
        return "done"
    if has_patch:
        return "done" if stop_after == "patch" else "report"
    if has_exploit:
        return "done" if stop_after == "exploit" else "patch"
    if has_analyst:
        return "done" if stop_after == "analyst" else "exploit"
    if has_recon:
        return "done" if stop_after == "recon" else "analyst"
    return "recon"


class RunManager:
    def __init__(
        self,
        *,
        repos_dir: Path,
        findings_dir: Path,
        audit_path: Path,
        db_path: Path,
    ):
        self.repos_dir = repos_dir
        self.findings_dir = findings_dir
        self.audit_path = audit_path
        self.db_path = db_path
        self._runs: dict[str, RunStatus] = {}
        self._gate_events: dict[str, threading.Event] = {}
        self._gate_decisions: dict[str, bool] = {}
        self._lock = threading.Lock()
        log_tee.install()

    def start(
        self,
        target: dict,
        stop_after: str | None = None,
        auto_approve: bool = False,
    ) -> str:
        status = RunStatus(
            run_id="",  # filled below
            target=target["name"],
            repo=target["repo"],
            started_at=time.time(),
            current_stage="recon",
            stop_after=stop_after,
            auto_approve=auto_approve,
            log_buffer=StringIO(),
        )

        gate_callback = None if auto_approve else self._make_gate_callback(status)
        ctx = new_run_context(
            target=target,
            repos_dir=self.repos_dir,
            findings_dir=self.findings_dir,
            audit_path=self.audit_path,
            db_path=self.db_path,
            auto_approve=auto_approve,
            gate_callback=gate_callback,
        )
        status.run_id = ctx.run_id
        with self._lock:
            self._runs[ctx.run_id] = status

        def _worker():
            log_tee.set_buffer(status.log_buffer)
            set_run_id(ctx.run_id)
            try:
                run_pipeline(ctx, stop_after=stop_after)
                if status.current_stage not in ("error", "aborted"):
                    status.current_stage = "done"
            except Exception as e:  # noqa: BLE001
                status.error = f"{type(e).__name__}: {e}"
                status.current_stage = "error"
                # Wake any pending gate so the page stops spinning
                ev = self._gate_events.pop(ctx.run_id, None)
                if ev is not None:
                    self._gate_decisions[ctx.run_id] = False
                    ev.set()
            finally:
                status.finished_at = time.time()
                log_tee.set_buffer(None)
                set_run_id(None)

        threading.Thread(
            target=_worker, daemon=True, name=f"run-{ctx.run_id}"
        ).start()
        return ctx.run_id

    def _make_gate_callback(self, status: RunStatus):
        run_id = None  # captured below via closure after run_id is set

        def cb(gate_name: str, prompt: str) -> bool:
            rid = status.run_id
            event = threading.Event()
            with self._lock:
                self._gate_events[rid] = event
                status.pending_gate = gate_name
                status.pending_gate_prompt = prompt
            event.wait()
            with self._lock:
                decision = self._gate_decisions.pop(rid, False)
                status.pending_gate = None
                status.pending_gate_prompt = ""
                status.gate_history.append(
                    GateEntry(
                        gate=gate_name, prompt=prompt,
                        approved=decision, decided_at=time.time(),
                    )
                )
                if not decision:
                    status.current_stage = "aborted"
            return decision

        return cb

    def decide_gate(self, run_id: str, gate_name: str, approve: bool) -> bool:
        with self._lock:
            status = self._runs.get(run_id)
            if status is None or status.pending_gate != gate_name:
                return False
            self._gate_decisions[run_id] = approve
            event = self._gate_events.pop(run_id, None)
        if event is not None:
            event.set()
            return True
        return False

    def get(self, run_id: str) -> RunStatus | None:
        with self._lock:
            s = self._runs.get(run_id)
        if s is None:
            art_dir = self.findings_dir / run_id
            if not art_dir.exists():
                return None
            s = self._reconstruct(run_id, art_dir)
        if s.current_stage not in ("done", "error", "aborted") and s.pending_gate is None:
            derived = _stage_from_artifacts(
                self.findings_dir / run_id, s.stop_after
            )
            if derived != "starting":
                s.current_stage = derived
        return s

    def log_tail(self, run_id: str, max_chars: int = 20_000) -> str:
        with self._lock:
            s = self._runs.get(run_id)
        if s is None or s.log_buffer is None:
            return ""
        return log_tee.tail(s.log_buffer, max_chars)

    def list_runs(self) -> list[RunStatus]:
        seen: set[str] = set()
        out: list[RunStatus] = []
        with self._lock:
            for s in sorted(
                self._runs.values(), key=lambda s: s.started_at, reverse=True
            ):
                out.append(s)
                seen.add(s.run_id)
        if self.findings_dir.exists():
            dirs = sorted(
                [p for p in self.findings_dir.iterdir() if p.is_dir()],
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            for d in dirs:
                if d.name in seen:
                    continue
                out.append(self._reconstruct(d.name, d))
        return out

    def list_artifacts(self, run_id: str) -> list[str]:
        art = self.findings_dir / run_id
        if not art.exists():
            return []
        return sorted(p.name for p in art.iterdir() if p.is_file())

    def _reconstruct(self, run_id: str, art_dir: Path) -> RunStatus:
        target = run_id.rsplit("_", 1)[0]
        started_at = art_dir.stat().st_mtime
        stage = _stage_from_artifacts(art_dir, None)
        return RunStatus(
            run_id=run_id,
            target=target,
            started_at=started_at,
            finished_at=started_at if stage == "done" else None,
            current_stage=stage,
        )
