"""CLI entry point.

Commands:
  list                         show authorized targets
  run <target> [opts]          run the full pipeline (Recon → Analyst → Exploit → Patch → Report)
  recon <target>               run Recon only
  stage <target> <stage> [opts]
                               run up to a stage (recon|analyst|exploit|patch|report)
  diff <target> <base> <head>  diff-aware run: analyze only changed files
  findings [--target X]        list findings from SQLite
  triage                       show duplicate findings across runs
  dashboard [--target X] [-o]  render a standalone HTML findings dashboard
  audit verify                 verify the audit hash chain

Shared run options: --yes (auto-approve gates), --top-n N (exploit top N
hypotheses), --parallel (run hypotheses concurrently), --resume (reuse on-disk
recon/analyst artifacts), --no-cache (disable the LLM response cache).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from src.orchestrator import new_run_context, run_diff_pipeline, run_pipeline
from src.store.audit import AuditLog
from src.store.dashboard import generate_dashboard, triage_report
from src.store.findings import FindingsStore

ROOT = Path(__file__).resolve().parent.parent
TARGETS_FILE = ROOT / "config" / "targets.json"
REPOS_DIR = ROOT / "data" / "repos"
FINDINGS_DIR = ROOT / "data" / "findings"
AUDIT_LOG = ROOT / "data" / "audit.jsonl"
DB_PATH = ROOT / "data" / "findings.db"
CACHE_DIR = ROOT / "data" / "cache"

console = Console()


def load_targets() -> dict:
    return json.loads(TARGETS_FILE.read_text())


def find_target(name: str) -> dict:
    for t in load_targets()["authorized_targets"]:
        if t["name"] == name:
            return t
    raise SystemExit(
        f"Target '{name}' is NOT in the authorized allowlist (config/targets.json). "
        f"Refusing to proceed."
    )


def _cache_dir(args) -> Path | None:
    return None if getattr(args, "no_cache", False) else CACHE_DIR


def _ctx(target: dict, args, auto: bool | None = None):
    return new_run_context(
        target=target, repos_dir=REPOS_DIR, findings_dir=FINDINGS_DIR,
        audit_path=AUDIT_LOG, db_path=DB_PATH,
        auto_approve=args.yes if auto is None else auto,
        top_n=getattr(args, "top_n", 1),
        parallel=getattr(args, "parallel", False),
        cache_dir=_cache_dir(args),
    )


def cmd_list(_args):
    table = Table(title="Authorized Targets")
    for col in ("Name", "Repo", "Ref", "Category", "Known CVE"):
        table.add_column(col, style="cyan" if col == "Name" else None)
    for t in load_targets()["authorized_targets"]:
        table.add_row(t["name"], t["repo"], t["ref"], t["category"], t.get("known_cve") or "—")
    console.print(table)


def cmd_run(args):
    ctx = _ctx(find_target(args.target), args)
    run_pipeline(ctx, stop_after=None, resume=args.resume)
    console.print(f"\n[bold green]✓ Run {ctx.run_id} complete.[/] Artifacts: {ctx.artifact_dir}")


def cmd_stage(args):
    if args.stage not in ("recon", "analyst", "exploit", "patch", "report"):
        raise SystemExit(f"Unknown stage: {args.stage}")
    ctx = _ctx(find_target(args.target), args)
    run_pipeline(ctx, stop_after=args.stage, resume=args.resume)
    console.print(f"\n[bold green]✓ Stopped after {args.stage}.[/] Artifacts: {ctx.artifact_dir}")


def cmd_recon(args):
    ctx = _ctx(find_target(args.target), args, auto=True)
    run_pipeline(ctx, stop_after="recon")


def cmd_diff(args):
    ctx = _ctx(find_target(args.target), args)
    run_diff_pipeline(ctx, base_ref=args.base, head_ref=args.head, stop_after=args.stop_after)
    console.print(f"\n[bold green]✓ Diff run {ctx.run_id} complete.[/] Artifacts: {ctx.artifact_dir}")


def cmd_findings(args):
    store = FindingsStore(DB_PATH)
    try:
        rows = store.list_findings(target=args.target)
    finally:
        store.close()
    if not rows:
        console.print("[dim]No findings yet.[/]")
        return
    table = Table(title=f"Findings ({len(rows)})")
    cols = ["run_id", "target", "hypothesis_id", "cwe", "severity",
            "validated", "has_patch", "patch_validated", "has_report"]
    for col in cols:
        table.add_column(col)
    for r in rows:
        table.add_row(
            r["run_id"], r["target"], r["hypothesis_id"], r["cwe"] or "", r["severity"] or "",
            "✓" if r["validated"] else "", "✓" if r["has_patch"] else "",
            "✓" if r.get("patch_validated") else "", "✓" if r["has_report"] else "",
        )
    console.print(table)


def cmd_triage(_args):
    rep = triage_report(DB_PATH)
    console.print(f"[bold]{rep['total']}[/] findings, "
                  f"[bold]{len(rep['duplicates'])}[/] duplicate group(s).")
    for g in rep["duplicates"]:
        console.print(f"\n[yellow]● {g['count']}×[/] [cyan]{g['dedupe_key']}[/]")
        for f in g["findings"]:
            console.print(f"   [dim]{f['run_id']}[/] {f['hypothesis_id']} "
                          f"validated={'✓' if f['validated'] else '·'}")


def cmd_dashboard(args):
    out = Path(args.output) if args.output else (FINDINGS_DIR / "dashboard.html")
    path = generate_dashboard(DB_PATH, out, target=args.target)
    console.print(f"[green]Dashboard written to[/] {path}")


def cmd_audit(args):
    if args.action == "verify":
        ok, broken = AuditLog(AUDIT_LOG).verify()
        if ok:
            console.print("[green]Audit log intact.[/]")
        else:
            console.print(f"[red]Audit log broken at line {broken}.[/]")
            sys.exit(1)


def _add_run_opts(p, with_resume: bool = True) -> None:
    p.add_argument("--yes", action="store_true", help="auto-approve HITL gates")
    p.add_argument("--top-n", type=int, default=1, help="exploit the top N hypotheses")
    p.add_argument("--parallel", action="store_true", help="run hypotheses concurrently")
    p.add_argument("--no-cache", action="store_true", help="disable LLM response cache")
    if with_resume:
        p.add_argument("--resume", action="store_true", help="reuse on-disk recon/analyst artifacts")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="bughunter")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list")

    p_run = sub.add_parser("run", help="Run full pipeline")
    p_run.add_argument("target")
    _add_run_opts(p_run)

    p_stage = sub.add_parser("stage", help="Run up to a specific stage")
    p_stage.add_argument("target")
    p_stage.add_argument("stage", choices=["recon", "analyst", "exploit", "patch", "report"])
    _add_run_opts(p_stage)

    p_recon = sub.add_parser("recon", help="Recon only")
    p_recon.add_argument("target")
    p_recon.add_argument("--no-cache", action="store_true")

    p_diff = sub.add_parser("diff", help="Diff-aware run over changed files")
    p_diff.add_argument("target")
    p_diff.add_argument("base", help="base git ref")
    p_diff.add_argument("head", help="head git ref")
    p_diff.add_argument("--stop-after", default=None,
                        choices=["recon", "analyst", "exploit", "patch", "report"])
    _add_run_opts(p_diff, with_resume=False)

    p_findings = sub.add_parser("findings")
    p_findings.add_argument("--target", default=None)

    sub.add_parser("triage", help="Show duplicate findings across runs")

    p_dash = sub.add_parser("dashboard", help="Render HTML findings dashboard")
    p_dash.add_argument("--target", default=None)
    p_dash.add_argument("-o", "--output", default=None)

    p_audit = sub.add_parser("audit")
    p_audit.add_argument("action", choices=["verify"])

    args = parser.parse_args(argv)
    {
        "list": cmd_list,
        "run": cmd_run,
        "stage": cmd_stage,
        "recon": cmd_recon,
        "diff": cmd_diff,
        "findings": cmd_findings,
        "triage": cmd_triage,
        "dashboard": cmd_dashboard,
        "audit": cmd_audit,
    }[args.cmd](args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
