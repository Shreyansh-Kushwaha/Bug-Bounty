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
from typing import Callable

from rich.console import Console

from src.agents.analyst import AnalystAgent, AnalystInput, AnalystOutput, Hypothesis
from src.agents.exploit import ExploitAgent, ExploitInput, ExploitOutput
from src.agents.patch import Patch, PatchAgent, PatchInput
from src.agents.recon import ReconAgent, ReconInput, ReconOutput
from src.agents.report import Report, ReportAgent, ReportInput
from src.roadmap import build_roadmap
from src.scanners.deps import scan_dependencies
from src.scanners.secrets import scan_secrets, to_artifact as secrets_to_artifact
from src.scoring import compute_scores
from src.store.audit import AuditLog
from src.store.findings import FindingsStore

console = Console()


# Gate callback: receives (gate_name, prompt), returns True to approve, False to abort.
# Used by the web UI to bridge HITL confirmations. CLI leaves this None and falls
# back to stdin.
GateCallback = Callable[[str, str], bool]


@dataclass
class RunContext:
    run_id: str
    target: dict
    clone_dir: Path
    artifact_dir: Path
    audit: AuditLog
    store: FindingsStore
    auto_approve: bool = False
    gate_callback: GateCallback | None = None
    recon: ReconOutput | None = None
    analyst: AnalystOutput | None = None
    exploits: dict[str, ExploitOutput] = field(default_factory=dict)
    patches: dict[str, Patch] = field(default_factory=dict)
    reports: dict[str, Report] = field(default_factory=dict)
    secrets: dict | None = None
    deps: dict | None = None
    roadmap: dict | None = None
    score: dict | None = None


def _write(ctx: RunContext, name: str, data: dict) -> Path:
    path = ctx.artifact_dir / f"{name}.json"
    path.write_text(json.dumps(data, indent=2, default=str))
    return path


def _confirm(ctx: "RunContext", gate_name: str, prompt: str) -> bool:
    if ctx.auto_approve:
        console.print(f"[yellow]auto-approve[/] {prompt}")
        ctx.audit.append("gate.auto_approve", {"gate": gate_name, "prompt": prompt})
        return True
    if ctx.gate_callback is not None:
        console.print(f"[cyan]awaiting human gate[/] {gate_name}: {prompt}")
        ctx.audit.append("gate.pending", {"gate": gate_name, "prompt": prompt})
        decision = ctx.gate_callback(gate_name, prompt)
        ctx.audit.append(
            "gate.decided",
            {"gate": gate_name, "approved": bool(decision)},
        )
        return bool(decision)
    ans = input(f"{prompt} [y/N] ").strip().lower()
    approved = ans in ("y", "yes")
    ctx.audit.append("gate.decided", {"gate": gate_name, "approved": approved})
    return approved


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
    gate_callback: GateCallback | None = None,
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
        gate_callback=gate_callback,
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

    # Deterministic scanners run alongside Recon. They never block the pipeline.
    console.print("[dim]Running secrets + dependency scanners…[/]")
    try:
        secret_hits = scan_secrets(ctx.clone_dir)
        ctx.secrets = secrets_to_artifact(secret_hits)
        _write(ctx, "01b_secrets", ctx.secrets)
        ctx.audit.append("secrets.done", {"total": ctx.secrets["total"]})
        console.print(f"  secrets: {ctx.secrets['total']} hit(s)")
    except Exception as e:  # noqa: BLE001
        console.print(f"[yellow]secrets scan failed: {e}[/]")
        ctx.secrets = {"total": 0, "hits": [], "error": str(e)}
    try:
        ctx.deps = scan_dependencies(ctx.clone_dir)
        _write(ctx, "01c_deps", ctx.deps)
        ctx.audit.append("deps.done", {
            "total": ctx.deps.get("total", 0),
            "scanners_run": ctx.deps.get("scanners_run", []),
        })
        console.print(
            f"  deps: {ctx.deps.get('total', 0)} vuln(s) "
            f"(scanners: {', '.join(ctx.deps.get('scanners_run') or ['none']) })"
        )
    except Exception as e:  # noqa: BLE001
        console.print(f"[yellow]dep scan failed: {e}[/]")
        ctx.deps = {"total": 0, "vulnerabilities": [], "error": str(e)}

    if stop_after == "recon":
        _write_score(ctx, exploit_validated=None)
        return

    # --- Analyst ---
    console.print("\n[bold]Stage 2/5 — Analyst[/]")
    analyst = AnalystAgent().run(AnalystInput(recon=recon, clone_dir=ctx.clone_dir))
    ctx.analyst = analyst
    _write(ctx, "02_analyst", analyst.model_dump())
    ctx.audit.append("analyst.done", {"hypotheses": len(analyst.hypotheses)})
    for h in analyst.hypotheses:
        console.print(f"  [dim]{h.id}[/] {h.cwe} {h.severity}/{h.exploitability} — {h.title}")

    # Roadmap = all hypotheses + secrets + deps, ordered by priority.
    ctx.roadmap = build_roadmap(
        hypotheses=[h.model_dump() for h in analyst.hypotheses],
        secrets_artifact=ctx.secrets,
        deps_artifact=ctx.deps,
    )
    _write(ctx, "02b_roadmap", ctx.roadmap)
    ctx.audit.append("roadmap.done", {"total": ctx.roadmap["total"]})

    if stop_after == "analyst":
        _write_score(ctx, exploit_validated=None)
        return

    if not analyst.hypotheses:
        console.print("[yellow]No hypotheses produced — stopping.[/]")
        _write_score(ctx, exploit_validated=None)
        return

    if not _confirm(
        ctx, "exploit",
        "Proceed to write PoCs for top hypothesis (rank=1)?",
    ):
        console.print("[yellow]Aborted by user at Exploit gate.[/]")
        ctx.audit.append("gate.abort", {"stage": "exploit"})
        _write_score(ctx, exploit_validated=None)
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
        _write_score(ctx, exploit_validated=exploit_out.validated)
        return

    if not exploit_out.validated:
        docker_missing = "docker not available" in (exploit_out.validation_reason or "").lower()
        if not docker_missing:
            console.print("[yellow]PoC did not validate. Skipping patch and report.[/]")
            _record_finding(ctx, top, exploit_out, None, None)
            _write_score(ctx, exploit_validated=False)
            return
        console.print(
            "[yellow]Docker unavailable — PoC generated but not executed. "
            "Continuing to patch/report.[/]"
        )

    if not _confirm(ctx, "patch_report", "Generate patch + report?"):
        console.print("[yellow]Aborted by user at Patch gate.[/]")
        ctx.audit.append("gate.abort", {"stage": "patch"})
        _record_finding(ctx, top, exploit_out, None, None)
        _write_score(ctx, exploit_validated=exploit_out.validated)
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
        _write_score(ctx, exploit_validated=exploit_out.validated)
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
    (ctx.artifact_dir / f"05_report_{top.id}_eli5.md").write_text(report.eli5_markdown)
    ctx.audit.append("report.done", {
        "id": top.id, "cvss_score": report.cvss_score, "severity": report.severity,
    })
    console.print(f"  [green]{report.severity}[/] (CVSS {report.cvss_score}) — {report.title}")

    _record_finding(ctx, top, exploit_out, patch, report)
    _write_score(ctx, exploit_validated=exploit_out.validated)

    console.print(
        f"\n[bold yellow]⚠ Report written to disk but NOT submitted.[/] "
        f"Review {ctx.artifact_dir}/05_report_{top.id}.md before any disclosure."
    )


def _write_score(ctx: RunContext, *, exploit_validated: bool | None) -> None:
    """Compute the per-category score from whatever artifacts exist so far,
    write it as 06_score.json, and stash it on the run context."""
    hyps = [h.model_dump() for h in (ctx.analyst.hypotheses if ctx.analyst else [])]
    score = compute_scores(
        secrets_artifact=ctx.secrets,
        deps_artifact=ctx.deps,
        analyst_hypotheses=hyps,
        exploit_validated=exploit_validated,
    )
    ctx.score = score
    _write(ctx, "06_score", score)
    ctx.audit.append("score.done", {"overall": score["overall"], "grade": score["grade"]})


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
