"""Run a diff-aware pipeline for a PR and emit a Markdown summary.

Intended for CI (see .github/workflows/pr-security-scan.yml). Runs the diff
pipeline between two refs against an authorized target, then writes a compact
Markdown summary (security score + top roadmap items) to the path given by
--out, suitable for posting as a PR comment.

Usage:
  python -m scripts.pr_scan --target <name> --base <ref> --head <ref> --out summary.md
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.orchestrator import new_run_context, run_diff_pipeline  # noqa: E402

TARGETS_FILE = ROOT / "config" / "targets.json"
REPOS_DIR = ROOT / "data" / "repos"
FINDINGS_DIR = ROOT / "data" / "findings"
AUDIT_LOG = ROOT / "data" / "audit.jsonl"
DB_PATH = ROOT / "data" / "findings.db"


def _find_target(name: str) -> dict:
    data = json.loads(TARGETS_FILE.read_text())
    for t in data["authorized_targets"]:
        if t["name"] == name:
            return t
    raise SystemExit(f"Target '{name}' not in config/targets.json allowlist.")


def _render(score: dict | None, roadmap: dict | None, base: str, head: str) -> str:
    lines = ["## 🔒 BugHunter PR security scan", ""]
    lines.append(f"Diff `{base}...{head}` — changed source files only.\n")

    if score:
        lines.append(f"**Security score:** {score.get('overall', '?')}/100 "
                     f"(grade {score.get('grade', '?')}, {score.get('risk_band', '?')} risk)\n")

    items = (roadmap or {}).get("items", []) if roadmap else []
    if not items:
        lines.append("No prioritized findings in the changed files. ✅")
        return "\n".join(lines)

    lines.append(f"**Top findings ({min(len(items), 10)} of {len(items)}):**\n")
    lines.append("| # | Severity | Type | Title | Fix |")
    lines.append("|---|----------|------|-------|-----|")
    for it in items[:10]:
        title = str(it.get("title", "")).replace("|", "\\|")[:80]
        fix = str(it.get("fix_recommendation", "")).replace("|", "\\|")[:100]
        lines.append(
            f"| {it.get('rank', '')} | {it.get('severity', '')} | "
            f"{it.get('kind', '')} | {title} | {fix} |"
        )
    lines.append("\n_Reports are advisory and never auto-submitted._")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="pr_scan")
    ap.add_argument("--target", required=True)
    ap.add_argument("--base", required=True)
    ap.add_argument("--head", required=True)
    ap.add_argument("--out", default="pr_scan_summary.md")
    ap.add_argument("--stop-after", default="analyst",
                    choices=["recon", "analyst", "exploit", "patch", "report"])
    args = ap.parse_args(argv)

    target = _find_target(args.target)
    ctx = new_run_context(
        target=target, repos_dir=REPOS_DIR, findings_dir=FINDINGS_DIR,
        audit_path=AUDIT_LOG, db_path=DB_PATH, auto_approve=True,
    )
    run_diff_pipeline(ctx, base_ref=args.base, head_ref=args.head, stop_after=args.stop_after)

    roadmap_path = ctx.artifact_dir / "02b_roadmap.json"
    score_path = ctx.artifact_dir / "06_score.json"
    roadmap = json.loads(roadmap_path.read_text()) if roadmap_path.exists() else None
    score = json.loads(score_path.read_text()) if score_path.exists() else None

    summary = _render(score, roadmap, args.base, args.head)
    Path(args.out).write_text(summary)
    print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
