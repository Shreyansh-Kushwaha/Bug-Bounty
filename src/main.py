"""CLI entry point.

Commands:
  list                         show authorized targets
  run <target> [--yes]         run the full pipeline (Recon → Analyst → Exploit → Patch → Report)
  recon <target>               run Recon only
  stage <target> <stage> [--yes]
                               run up to a stage (recon|analyst|exploit|patch|report)
  findings [--target X]        list findings from SQLite
  audit verify                 verify the audit hash chain
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from src.orchestrator import new_run_context, run_pipeline
from src.store.audit import AuditLog
from src.store.findings import FindingsStore

ROOT = Path(__file__).resolve().parent.parent
TARGETS_FILE = ROOT / "config" / "targets.json"
REPOS_DIR = ROOT / "data" / "repos"
FINDINGS_DIR = ROOT / "data" / "findings"
AUDIT_LOG = ROOT / "data" / "audit.jsonl"
DB_PATH = ROOT / "data" / "findings.db"

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


def cmd_list(_args):
    table = Table(title="Authorized Targets")
    table.add_column("Name", style="cyan")
    table.add_column("Repo")
    table.add_column("Ref")
    table.add_column("Category")
    table.add_column("Known CVE")
    for t in load_targets()["authorized_targets"]:
        table.add_row(t["name"], t["repo"], t["ref"], t["category"], t.get("known_cve") or "—")
    console.print(table)


def cmd_run(args):
    target = find_target(args.target)
    ctx = new_run_context(
        target=target, repos_dir=REPOS_DIR, findings_dir=FINDINGS_DIR,
        audit_path=AUDIT_LOG, db_path=DB_PATH, auto_approve=args.yes,
    )
    run_pipeline(ctx, stop_after=None)
    console.print(f"\n[bold green]✓ Run {ctx.run_id} complete.[/] Artifacts: {ctx.artifact_dir}")


def cmd_stage(args):
    target = find_target(args.target)
    if args.stage not in ("recon", "analyst", "exploit", "patch", "report"):
        raise SystemExit(f"Unknown stage: {args.stage}")
    ctx = new_run_context(
        target=target, repos_dir=REPOS_DIR, findings_dir=FINDINGS_DIR,
        audit_path=AUDIT_LOG, db_path=DB_PATH, auto_approve=args.yes,
    )
    run_pipeline(ctx, stop_after=args.stage)
    console.print(f"\n[bold green]✓ Stopped after {args.stage}.[/] Artifacts: {ctx.artifact_dir}")


def cmd_recon(args):
    target = find_target(args.target)
    ctx = new_run_context(
        target=target, repos_dir=REPOS_DIR, findings_dir=FINDINGS_DIR,
        audit_path=AUDIT_LOG, db_path=DB_PATH, auto_approve=True,
    )
    run_pipeline(ctx, stop_after="recon")


def cmd_findings(args):
    store = FindingsStore(DB_PATH)
    rows = store.list_findings(target=args.target)
    if not rows:
        console.print("[dim]No findings yet.[/]")
        return
    table = Table(title=f"Findings ({len(rows)})")
    for col in ["run_id", "target", "hypothesis_id", "cwe", "severity", "validated", "has_patch", "has_report"]:
        table.add_column(col)
    for r in rows:
        table.add_row(
            r["run_id"], r["target"], r["hypothesis_id"], r["cwe"] or "", r["severity"] or "",
            "✓" if r["validated"] else "", "✓" if r["has_patch"] else "",
            "✓" if r["has_report"] else "",
        )
    console.print(table)


def cmd_audit(args):
    if args.action == "verify":
        ok, broken = AuditLog(AUDIT_LOG).verify()
        if ok:
            console.print("[green]Audit log intact.[/]")
        else:
            console.print(f"[red]Audit log broken at line {broken}.[/]")
            sys.exit(1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="bughunter")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list")

    p_run = sub.add_parser("run", help="Run full pipeline")
    p_run.add_argument("target")
    p_run.add_argument("--yes", action="store_true", help="auto-approve HITL gates")

    p_stage = sub.add_parser("stage", help="Run up to a specific stage")
    p_stage.add_argument("target")
    p_stage.add_argument("stage", choices=["recon", "analyst", "exploit", "patch", "report"])
    p_stage.add_argument("--yes", action="store_true")

    p_recon = sub.add_parser("recon", help="Recon only")
    p_recon.add_argument("target")

    p_findings = sub.add_parser("findings")
    p_findings.add_argument("--target", default=None)

    p_audit = sub.add_parser("audit")
    p_audit.add_argument("action", choices=["verify"])

    args = parser.parse_args(argv)
    {
        "list": cmd_list,
        "run": cmd_run,
        "stage": cmd_stage,
        "recon": cmd_recon,
        "findings": cmd_findings,
        "audit": cmd_audit,
    }[args.cmd](args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
