"""End-to-end orchestrator.

Pipeline:
    Recon  ->  Analyst  ->  [HITL gate]  ->  Exploit  ->  [HITL gate]
                                                            ->  Patch  ->  Report

Each stage persists a JSON artifact under data/findings/<run_id>/ and appends to
the tamper-evident audit log. The `run_id` is a timestamp-based slug.

Human-in-the-loop gates:
    - Before Exploit:  "these N hypotheses will be PoC'd — continue? [y/N]"
    - Before Report:   "PoC validated=<bool> — generate report? [y/N]"

Non-interactive mode (--yes) skips gates but never auto-submits the report.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console

from src.agents.analyst import AnalystAgent, AnalystInput, AnalystOutput, Hypothesis
from src.agents.exploit import ExploitAgent, ExploitInput, ExploitOutput
from src.agents.patch import Patch, PatchAgent, PatchInput
from src.agents.recon import ReconAgent, ReconInput, ReconOutput
from src.agents.report import Report, ReportAgent, ReportInput
from src.store.audit import AuditLog
from src.store.findings import FindingsStore

console = Console()


@dataclass
class RunContext:
    run_id: str
    target: dict
    clone_dir: Path
    artifact_dir: Path
    audit: AuditLog
    store: FindingsStore
    auto_approve: bool = False
    recon: ReconOutput | None = None
    analyst: AnalystOutput | None = None
    exploits: dict[str, ExploitOutput] = field(default_factory=dict)
    patches: dict[str, Patch] = field(default_factory=dict)
    reports: dict[str, Report] = field(default_factory=dict)


def _write(ctx: RunContext, name: str, data: dict) -> Path:
    path = ctx.artifact_dir / f"{name}.json"
    path.write_text(json.dumps(data, indent=2, default=str))
    return path


def _confirm(prompt: str, auto: bool) -> bool:
    if auto:
        console.print(f"[yellow]auto-approve[/] {prompt}")
        return True
    ans = input(f"{prompt} [y/N] ").strip().lower()
    return ans in ("y", "yes")


def _read_source_for(clone_dir: Path, file_rel: str, budget: int = 6000) -> str:
    path = clone_dir / file_rel
    if not path.exists() or not path.is_file():
        return ""
    try:
        return path.read_text(errors="ignore")[:budget]
    except (OSError, UnicodeDecodeError):
        return ""


def new_run_context(
    target: dict,
    repos_dir: Path,
    findings_dir: Path,
    audit_path: Path,
    db_path: Path,
    auto_approve: bool = False,
) -> RunContext:
    run_id = f"{target['name']}_{int(time.time())}"
    artifact_dir = findings_dir / run_id
    artifact_dir.mkdir(parents=True, exist_ok=True)
    return RunContext(
        run_id=run_id,
        target=target,
        clone_dir=repos_dir / target["name"],
        artifact_dir=artifact_dir,
        audit=AuditLog(audit_path),
        store=FindingsStore(db_path),
        auto_approve=auto_approve,
    )


def run_pipeline(ctx: RunContext, stop_after: str | None = None) -> None:
    """Run the full pipeline. `stop_after` can be: recon|analyst|exploit|patch|report."""
    ctx.audit.append("run.start", {"run_id": ctx.run_id, "target": ctx.target["name"]})

    # --- Recon ---
    console.print("\n[bold]Stage 1/5 — Recon[/]")
    ReconAgent.clone(ctx.target["repo"], ctx.target["ref"], ctx.clone_dir)
    recon = ReconAgent().run(ReconInput(
        target_name=ctx.target["name"],
        repo_url=ctx.target["repo"],
        ref=ctx.target["ref"],
        clone_dir=ctx.clone_dir,
    ))
    ctx.recon = recon
    _write(ctx, "01_recon", recon.model_dump())
    ctx.audit.append("recon.done", {"risky_files": len(recon.risky_files)})
    if stop_after == "recon":
        return

    # --- Analyst ---
    console.print("\n[bold]Stage 2/5 — Analyst[/]")
    analyst = AnalystAgent().run(AnalystInput(recon=recon, clone_dir=ctx.clone_dir))
    ctx.analyst = analyst
    _write(ctx, "02_analyst", analyst.model_dump())
    ctx.audit.append("analyst.done", {"hypotheses": len(analyst.hypotheses)})
    for h in analyst.hypotheses:
        console.print(f"  [dim]{h.id}[/] {h.cwe} {h.severity}/{h.exploitability} — {h.title}")
    if stop_after == "analyst":
        return

    if not analyst.hypotheses:
        console.print("[yellow]No hypotheses produced — stopping.[/]")
        return

    if not _confirm(
        f"Proceed to write PoCs for top hypothesis (rank=1)?",
        ctx.auto_approve,
    ):
        console.print("[yellow]Aborted by user at Exploit gate.[/]")
        ctx.audit.append("gate.abort", {"stage": "exploit"})
        return

    # --- Exploit (top hypothesis only by default) ---
    console.print("\n[bold]Stage 3/5 — Exploit[/]")
    top = sorted(analyst.hypotheses, key=lambda h: h.rank)[0]
    source = _read_source_for(ctx.clone_dir, top.file)
    exploit_out = ExploitAgent().run(ExploitInput(
        hypothesis=top, clone_dir=ctx.clone_dir, source_context=source,
    ))
    ctx.exploits[top.id] = exploit_out
    _write(ctx, f"03_exploit_{top.id}", exploit_out.model_dump())
    ctx.audit.append("exploit.done", {
        "id": top.id,
        "validated": exploit_out.validated,
        "reason": exploit_out.validation_reason,
    })
    console.print(f"  validated={exploit_out.validated} reason={exploit_out.validation_reason}")
    if stop_after == "exploit":
        _record_finding(ctx, top, exploit_out, None, None)
        return

    if not exploit_out.validated:
        console.print("[yellow]PoC did not validate. Skipping patch and report.[/]")
        _record_finding(ctx, top, exploit_out, None, None)
        return

    if not _confirm("PoC validated. Generate patch + report?", ctx.auto_approve):
        console.print("[yellow]Aborted by user at Patch gate.[/]")
        ctx.audit.append("gate.abort", {"stage": "patch"})
        _record_finding(ctx, top, exploit_out, None, None)
        return

    # --- Patch ---
    console.print("\n[bold]Stage 4/5 — Patch[/]")
    patch = PatchAgent().run(PatchInput(
        hypothesis=top, exploit=exploit_out,
        clone_dir=ctx.clone_dir, source_context=source,
    ))
    ctx.patches[top.id] = patch
    _write(ctx, f"04_patch_{top.id}", patch.model_dump())
    ctx.audit.append("patch.done", {"id": top.id, "files": [f.path for f in patch.files_modified]})
    if stop_after == "patch":
        _record_finding(ctx, top, exploit_out, patch, None)
        return

    # --- Report ---
    console.print("\n[bold]Stage 5/5 — Report[/]")
    report = ReportAgent().run(ReportInput(
        target=ctx.target["name"], repo_url=ctx.target["repo"],
        hypothesis=top, exploit=exploit_out, patch=patch,
    ))
    ctx.reports[top.id] = report
    _write(ctx, f"05_report_{top.id}", report.model_dump())
    (ctx.artifact_dir / f"05_report_{top.id}.md").write_text(report.markdown)
    ctx.audit.append("report.done", {
        "id": top.id, "cvss_score": report.cvss_score, "severity": report.severity,
    })
    console.print(f"  [green]{report.severity}[/] (CVSS {report.cvss_score}) — {report.title}")

    _record_finding(ctx, top, exploit_out, patch, report)

    console.print(
        f"\n[bold yellow]⚠ Report written to disk but NOT submitted.[/] "
        f"Review {ctx.artifact_dir}/05_report_{top.id}.md before any disclosure."
    )


def _record_finding(
    ctx: RunContext,
    h: Hypothesis,
    exploit: ExploitOutput | None,
    patch: Patch | None,
    report: Report | None,
) -> None:
    ctx.store.record(
        run_id=ctx.run_id,
        target=ctx.target["name"],
        hypothesis_id=h.id,
        cwe=h.cwe,
        severity=(report.severity if report else h.severity),
        file=h.file,
        line_range=h.line_range,
        title=(report.title if report else h.title),
        validated=bool(exploit and exploit.validated),
        has_patch=patch is not None,
        has_report=report is not None,
        artifact_dir=ctx.artifact_dir,
        metadata={"cvss_score": report.cvss_score if report else None},
    )
