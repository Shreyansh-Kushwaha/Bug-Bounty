"""End-to-end orchestrator.

Pipeline:
    Recon -> scanners (secrets/deps) -> Analyst -> roadmap -> [HITL gate]
          -> Exploit (top-N) -> [HITL gate] -> Patch -> Verify -> Report -> score

Each stage persists a JSON artifact under data/findings/<run_id>/ and appends to
the tamper-evident audit log. The `run_id` is a timestamp-based slug.

Features:
  - Top-N hypotheses are exploited (optionally in parallel).
  - Deterministic secrets + dependency scanners run alongside Recon; their
    results feed a prioritized fix roadmap and a per-category security score.
  - Patches are VERIFIED in the sandbox (test fails before, passes after).
  - Reports include a technical version and a plain-English ("ELI5") version.
  - One shared model router gives cross-stage cost tracking + response caching.
  - Runs can resume from on-disk artifacts (recon/analyst) instead of recomputing.
  - HITL gates can be satisfied via stdin (CLI) or a callback (web UI), and
    every gate decision — auto-approved, pending, or decided — is audited.

Human-in-the-loop gates:
    - Before Exploit:  "N hypotheses will be PoC'd — continue? [y/N]"
    - Before Patch/Report: "K PoC(s) validated — generate patches + reports? [y/N]"

Non-interactive mode (--yes) skips gates but never auto-submits the report.
"""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

from rich.console import Console
from rich.table import Table

from src.agents.analyst import AnalystAgent, AnalystInput, AnalystOutput, Hypothesis
from src.agents.exploit import ExploitAgent, ExploitInput, ExploitOutput
from src.agents.patch import Patch, PatchAgent, PatchInput
from src.agents.recon import ReconAgent, ReconInput, ReconOutput, RiskyFile
from src.agents.report import Report, ReportAgent, ReportInput
from src.current_run import set_run_id
from src.models.router import ModelRouter, default_router
from src.roadmap import build_roadmap
from src.sandbox.patch_verifier import verify_patch
from src.scanners.deps import scan_dependencies
from src.scanners.secrets import scan_secrets, to_artifact as secrets_to_artifact
from src.scoring import compute_scores
from src.store.audit import AuditLog
from src.store.findings import FindingsStore

console = Console()

STAGES = ("recon", "analyst", "exploit", "patch", "report")


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
    router: ModelRouter
    auto_approve: bool = False
    top_n: int = 1
    parallel: bool = False
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


def _confirm(ctx: RunContext, gate_name: str, prompt: str) -> bool:
    if ctx.auto_approve:
        console.print(f"[yellow]auto-approve[/] {prompt}")
        ctx.audit.append("gate.auto_approve", {"gate": gate_name, "prompt": prompt})
        return True
    if ctx.gate_callback is not None:
        console.print(f"[cyan]awaiting human gate[/] {gate_name}: {prompt}")
        ctx.audit.append("gate.pending", {"gate": gate_name, "prompt": prompt})
        decision = ctx.gate_callback(gate_name, prompt)
        ctx.audit.append("gate.decided", {"gate": gate_name, "approved": bool(decision)})
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


def _docker_missing(exploit_out: ExploitOutput) -> bool:
    return "docker not available" in (exploit_out.validation_reason or "").lower()


def new_run_context(
    target: dict,
    repos_dir: Path,
    findings_dir: Path,
    audit_path: Path,
    db_path: Path,
    auto_approve: bool = False,
    top_n: int = 1,
    parallel: bool = False,
    cache_dir: Path | None = None,
    run_id: str | None = None,
    gate_callback: GateCallback | None = None,
) -> RunContext:
    run_id = run_id or f"{target['name']}_{int(time.time())}"
    artifact_dir = findings_dir / run_id
    artifact_dir.mkdir(parents=True, exist_ok=True)
    router = default_router(cache_dir=cache_dir)
    return RunContext(
        run_id=run_id,
        target=target,
        clone_dir=repos_dir / target["name"],
        artifact_dir=artifact_dir,
        audit=AuditLog(audit_path),
        store=FindingsStore(db_path),
        router=router,
        auto_approve=auto_approve,
        top_n=max(1, top_n),
        parallel=parallel,
        gate_callback=gate_callback,
    )


def _load_artifact(ctx: RunContext, name: str) -> dict | None:
    path = ctx.artifact_dir / f"{name}.json"
    if path.exists():
        return json.loads(path.read_text())
    return None


def _run_scanners(ctx: RunContext, resume: bool = False) -> None:
    """Deterministic secrets + dependency scanners. Never blocks the pipeline."""
    cached_secrets = _load_artifact(ctx, "01b_secrets") if resume else None
    cached_deps = _load_artifact(ctx, "01c_deps") if resume else None
    if cached_secrets and cached_deps:
        ctx.secrets, ctx.deps = cached_secrets, cached_deps
        console.print("[dim]Scanners resumed from disk.[/]")
        return

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
            f"(scanners: {', '.join(ctx.deps.get('scanners_run') or ['none'])})"
        )
    except Exception as e:  # noqa: BLE001
        console.print(f"[yellow]dep scan failed: {e}[/]")
        ctx.deps = {"total": 0, "vulnerabilities": [], "error": str(e)}


def run_pipeline(ctx: RunContext, stop_after: str | None = None, resume: bool = False) -> None:
    """Run the pipeline. `stop_after` in STAGES; `resume` reuses on-disk artifacts."""
    set_run_id(ctx.run_id)  # attributes LLM usage rows to this run (idempotent)
    ctx.audit.append("run.start", {
        "run_id": ctx.run_id, "target": ctx.target["name"],
        "top_n": ctx.top_n, "parallel": ctx.parallel, "resume": resume,
    })

    # --- Recon ---
    cached_recon = _load_artifact(ctx, "01_recon") if resume else None
    if cached_recon:
        console.print("\n[bold]Stage 1/5 — Recon[/] [dim](resumed from disk)[/]")
        recon = ReconOutput.model_validate(cached_recon)
    else:
        console.print("\n[bold]Stage 1/5 — Recon[/]")
        ReconAgent.clone(ctx.target["repo"], ctx.target["ref"], ctx.clone_dir)
        recon = ReconAgent(ctx.router).run(ReconInput(
            target_name=ctx.target["name"], repo_url=ctx.target["repo"],
            ref=ctx.target["ref"], clone_dir=ctx.clone_dir,
        ))
        _write(ctx, "01_recon", recon.model_dump())
        ctx.audit.append("recon.done", {"risky_files": len(recon.risky_files)})
    ctx.recon = recon

    _run_scanners(ctx, resume=resume)

    if stop_after == "recon":
        return _finish(ctx, exploit_validated=None)

    # --- Analyst ---
    cached_analyst = _load_artifact(ctx, "02_analyst") if resume else None
    if cached_analyst:
        console.print("\n[bold]Stage 2/5 — Analyst[/] [dim](resumed from disk)[/]")
        analyst = AnalystOutput.model_validate(cached_analyst)
    else:
        console.print("\n[bold]Stage 2/5 — Analyst[/]")
        analyst = AnalystAgent(ctx.router).run(AnalystInput(recon=recon, clone_dir=ctx.clone_dir))
        _write(ctx, "02_analyst", analyst.model_dump())
        ctx.audit.append("analyst.done", {"hypotheses": len(analyst.hypotheses)})
    ctx.analyst = analyst
    for h in sorted(analyst.hypotheses, key=lambda h: h.rank):
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
        return _finish(ctx, exploit_validated=None)

    return _exploit_onward(ctx, stop_after)


def _exploit_onward(ctx: RunContext, stop_after: str | None) -> None:
    analyst = ctx.analyst
    if analyst is None or not analyst.hypotheses:
        console.print("[yellow]No hypotheses produced — stopping.[/]")
        return _finish(ctx, exploit_validated=None)

    targets = sorted(analyst.hypotheses, key=lambda h: h.rank)[: ctx.top_n]

    if not _confirm(
        ctx, "exploit",
        f"Proceed to write PoCs for the top {len(targets)} hypothesis(es)?",
    ):
        console.print("[yellow]Aborted by user at Exploit gate.[/]")
        ctx.audit.append("gate.abort", {"stage": "exploit"})
        return _finish(ctx, exploit_validated=None)

    # --- Exploit (top-N, optionally parallel) ---
    console.print(f"\n[bold]Stage 3/5 — Exploit[/] ({len(targets)} hypotheses)")
    exploit_results = _map(ctx, targets, lambda h: _run_exploit(ctx, h))
    for h, exploit_out in zip(targets, exploit_results):
        ctx.exploits[h.id] = exploit_out
        _write(ctx, f"03_exploit_{h.id}", exploit_out.model_dump())
        ctx.audit.append("exploit.done", {
            "id": h.id, "validated": exploit_out.validated,
            "reason": exploit_out.validation_reason,
        })
        console.print(f"  [dim]{h.id}[/] validated={exploit_out.validated} "
                      f"reason={exploit_out.validation_reason}")

    if stop_after == "exploit":
        for h in targets:
            _record_finding(ctx, h, ctx.exploits[h.id], None, None)
        any_validated = any(ctx.exploits[h.id].validated for h in targets)
        return _finish(ctx, exploit_validated=any_validated)

    # A hypothesis proceeds to patch/report if its PoC validated, or if Docker
    # simply wasn't available to run it (we can't disprove the bug in that case
    # either — better to still propose a fix than dead-end on tooling).
    proceed = [
        h for h in targets
        if ctx.exploits[h.id].validated or _docker_missing(ctx.exploits[h.id])
    ]
    skipped = [h for h in targets if h not in proceed]
    for h in skipped:
        console.print(f"[yellow]{h.id}: PoC did not validate. Skipping patch and report.[/]")
        _record_finding(ctx, h, ctx.exploits[h.id], None, None)

    if not proceed:
        console.print("[yellow]No PoC validated. Skipping patch and report.[/]")
        return _finish(ctx, exploit_validated=False)

    if not _confirm(
        ctx, "patch_report",
        f"{len(proceed)} PoC(s) validated (or unexecuted due to missing Docker). "
        f"Generate patches + reports?",
    ):
        console.print("[yellow]Aborted by user at Patch gate.[/]")
        ctx.audit.append("gate.abort", {"stage": "patch"})
        for h in proceed:
            _record_finding(ctx, h, ctx.exploits[h.id], None, None)
        return _finish(ctx, exploit_validated=any(ctx.exploits[h.id].validated for h in targets))

    # --- Patch -> Verify -> Report per proceeding hypothesis (optionally parallel) ---
    console.print(f"\n[bold]Stage 4-5/5 — Patch, Verify, Report[/] ({len(proceed)})")
    _map(ctx, proceed, lambda h: _patch_verify_report(ctx, h, stop_after))
    return _finish(ctx, exploit_validated=any(ctx.exploits[h.id].validated for h in targets))


_SOURCE_EXTS = {".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".rb", ".go", ".php", ".c", ".cpp"}


def run_diff_pipeline(ctx: RunContext, base_ref: str, head_ref: str, stop_after: str | None = None) -> None:
    """Diff-aware mode: analyze only files changed between base_ref and head_ref."""
    import subprocess

    set_run_id(ctx.run_id)
    ctx.audit.append("run.start", {
        "run_id": ctx.run_id, "target": ctx.target["name"],
        "mode": "diff", "base": base_ref, "head": head_ref,
    })
    console.print(f"\n[bold]Diff mode[/] — {base_ref}..{head_ref}")
    ReconAgent.clone(ctx.target["repo"], head_ref, ctx.clone_dir)
    subprocess.run(["git", "-C", str(ctx.clone_dir), "fetch", "--depth", "50", "origin", base_ref],
                   check=False, capture_output=True)
    diff = subprocess.run(
        ["git", "-C", str(ctx.clone_dir), "diff", "--name-only", f"{base_ref}...{head_ref}"],
        capture_output=True, text=True,
    )
    changed = [
        f.strip() for f in diff.stdout.splitlines()
        if f.strip() and Path(f.strip()).suffix in _SOURCE_EXTS
        and (ctx.clone_dir / f.strip()).exists()
    ]
    console.print(f"  {len(changed)} changed source file(s).")
    if not changed:
        console.print("[yellow]No changed source files to analyze.[/]")
        return _finish(ctx, exploit_validated=None)

    recon = ReconOutput(
        target=ctx.target["name"],
        entry_points=changed[:20],
        risky_files=[RiskyFile(path=f, reason="changed in diff", risk_level="medium") for f in changed],
        dependencies=[],
        summary=f"Diff between {base_ref} and {head_ref}: {len(changed)} changed source files.",
    )
    ctx.recon = recon
    _write(ctx, "01_recon", recon.model_dump())
    ctx.audit.append("recon.done", {"changed_files": len(changed), "mode": "diff"})

    _run_scanners(ctx)

    if stop_after == "recon":
        return _finish(ctx, exploit_validated=None)

    console.print("\n[bold]Analyst[/] (changed files only)")
    analyst = AnalystAgent(ctx.router).run(AnalystInput(
        recon=recon, clone_dir=ctx.clone_dir, max_files_to_read=len(changed),
    ))
    ctx.analyst = analyst
    _write(ctx, "02_analyst", analyst.model_dump())
    ctx.audit.append("analyst.done", {"hypotheses": len(analyst.hypotheses)})
    for h in sorted(analyst.hypotheses, key=lambda h: h.rank):
        console.print(f"  [dim]{h.id}[/] {h.cwe} {h.severity}/{h.exploitability} — {h.title}")

    ctx.roadmap = build_roadmap(
        hypotheses=[h.model_dump() for h in analyst.hypotheses],
        secrets_artifact=ctx.secrets,
        deps_artifact=ctx.deps,
    )
    _write(ctx, "02b_roadmap", ctx.roadmap)
    ctx.audit.append("roadmap.done", {"total": ctx.roadmap["total"]})

    if stop_after == "analyst":
        return _finish(ctx, exploit_validated=None)
    return _exploit_onward(ctx, stop_after)


def _map(ctx: RunContext, items: list, fn):
    """Run `fn` over items, in parallel threads when ctx.parallel, else sequentially."""
    if ctx.parallel and len(items) > 1:
        with ThreadPoolExecutor(max_workers=min(4, len(items))) as ex:
            return list(ex.map(fn, items))
    return [fn(x) for x in items]


def _run_exploit(ctx: RunContext, h: Hypothesis) -> ExploitOutput:
    set_run_id(ctx.run_id)  # thread-local; must be re-set in each worker thread
    source = _read_source_for(ctx.clone_dir, h.file)
    return ExploitAgent(ctx.router).run(ExploitInput(
        hypothesis=h, clone_dir=ctx.clone_dir, source_context=source,
    ))


def _patch_verify_report(ctx: RunContext, h: Hypothesis, stop_after: str | None) -> None:
    set_run_id(ctx.run_id)
    exploit_out = ctx.exploits[h.id]
    source = _read_source_for(ctx.clone_dir, h.file)

    # Patch
    patch = PatchAgent(ctx.router).run(PatchInput(
        hypothesis=h, exploit=exploit_out, clone_dir=ctx.clone_dir, source_context=source,
    ))

    # Verify
    verif = verify_patch(
        clone_dir=ctx.clone_dir,
        files_modified=patch.files_modified,
        regression_test_path=patch.regression_test_path,
        regression_test_code=patch.regression_test_code,
        language=exploit_out.poc.language if exploit_out.poc.language == "node" else "python",
    )
    patch.verification = asdict(verif)
    ctx.patches[h.id] = patch
    _write(ctx, f"04_patch_{h.id}", patch.model_dump())
    ctx.audit.append("patch.done", {
        "id": h.id, "files": [f.path for f in patch.files_modified],
        "patch_verified": verif.verified, "verify_reason": verif.reason,
    })
    console.print(f"  [dim]{h.id}[/] patch_verified={verif.verified} — {verif.reason}")

    if stop_after == "patch":
        _record_finding(ctx, h, exploit_out, patch, None)
        return

    # Report
    report = ReportAgent(ctx.router).run(ReportInput(
        target=ctx.target["name"], repo_url=ctx.target["repo"],
        hypothesis=h, exploit=exploit_out, patch=patch,
    ))
    ctx.reports[h.id] = report
    _write(ctx, f"05_report_{h.id}", report.model_dump())
    (ctx.artifact_dir / f"05_report_{h.id}.md").write_text(report.markdown)
    (ctx.artifact_dir / f"05_report_{h.id}_eli5.md").write_text(report.eli5_markdown)
    ctx.audit.append("report.done", {
        "id": h.id, "cvss_score": report.cvss_score, "severity": report.severity,
    })
    console.print(f"  [dim]{h.id}[/] [green]{report.severity}[/] "
                  f"(CVSS {report.cvss_score}) — {report.title}")
    _record_finding(ctx, h, exploit_out, patch, report)


def _finish(ctx: RunContext, *, exploit_validated: bool | None) -> None:
    _write_score(ctx, exploit_validated=exploit_validated)
    _print_cost(ctx)
    if ctx.reports:
        console.print(
            f"\n[bold yellow]⚠ {len(ctx.reports)} report(s) written to disk but NOT submitted.[/] "
            f"Review {ctx.artifact_dir}/ before any disclosure."
        )


def _print_cost(ctx: RunContext) -> None:
    u = ctx.router.total_usage
    ctx.audit.append("run.cost", {
        "calls": ctx.router.call_count, "cache_hits": ctx.router.cache_hits,
        "prompt_tokens": u.prompt_tokens, "completion_tokens": u.completion_tokens,
        "cost_usd": u.cost_usd,
    })
    table = Table(title="Run cost", show_header=False)
    table.add_row("LLM calls", str(ctx.router.call_count))
    table.add_row("Cache hits", str(ctx.router.cache_hits))
    table.add_row("Prompt tokens", f"{u.prompt_tokens:,}")
    table.add_row("Completion tokens", f"{u.completion_tokens:,}")
    table.add_row("Est. cost", f"${u.cost_usd:.4f}")
    console.print(table)


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
    patch_validated = bool(patch and patch.verification and patch.verification.get("verified"))
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
        patch_validated=patch_validated,
        artifact_dir=ctx.artifact_dir,
        metadata={
            "cvss_score": report.cvss_score if report else None,
            "cost_usd": ctx.router.total_usage.cost_usd,
        },
    )
