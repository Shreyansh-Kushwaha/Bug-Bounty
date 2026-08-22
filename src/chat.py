"""'Ask Security AI' Q&A.

Loads a small context bundle (recent findings, the latest report, the latest
roadmap, the latest score) and asks the LLM a question grounded in it. This is
not a long-running conversation — each call is independent.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.models.router import Tier, default_router
from src.store.findings import FindingsStore

_SYSTEM = (
    "You are a helpful application-security advisor inside an internal tool. "
    "Answer the user's question using ONLY the JSON context block provided. "
    "If the context does not contain the answer, say so plainly — do not invent "
    "vulnerabilities, package versions, or CVE numbers. Be concise (under 200 words "
    "unless the question demands more), and prefer concrete next steps."
)

_MAX_ARTIFACT_BYTES = 8000


def _read_json(path: Path, budget: int = _MAX_ARTIFACT_BYTES) -> dict | None:
    if not path.exists() or not path.is_file():
        return None
    try:
        text = path.read_text(errors="ignore")
    except OSError:
        return None
    if len(text) > budget:
        text = text[:budget] + "\n... (truncated)"
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"_raw": text}


def _read_text(path: Path, budget: int = _MAX_ARTIFACT_BYTES) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    try:
        text = path.read_text(errors="ignore")
    except OSError:
        return None
    return text if len(text) <= budget else text[:budget] + "\n... (truncated)"


def build_context(*, findings_dir: Path, db_path: Path, run_id: str | None) -> dict:
    """Gather a compact JSON context bundle. Pull from a specific run if given,
    otherwise from the most recent findings across all runs."""
    ctx: dict = {"run_id": run_id, "findings": [], "score": None,
                 "roadmap": None, "report": None, "secrets_summary": None,
                 "deps_summary": None}

    store = FindingsStore(db_path)
    rows = store.list_findings()
    store.close()
    # Cap to avoid blowing the context window.
    ctx["findings"] = rows[:25]

    if not run_id:
        return ctx

    run_dir = findings_dir / run_id
    if not run_dir.is_dir():
        return ctx

    score = _read_json(run_dir / "06_score.json")
    if score:
        ctx["score"] = score
    roadmap = _read_json(run_dir / "02b_roadmap.json")
    if roadmap:
        # Trim roadmap items to top 10 for context budget.
        items = (roadmap.get("items") or [])[:10]
        ctx["roadmap"] = {"total": roadmap.get("total"), "items": items}
    secrets = _read_json(run_dir / "01b_secrets.json")
    if secrets:
        ctx["secrets_summary"] = {
            "total": secrets.get("total"),
            "by_confidence": secrets.get("by_confidence"),
        }
    deps = _read_json(run_dir / "01c_deps.json")
    if deps:
        ctx["deps_summary"] = {
            "total": deps.get("total"),
            "by_severity": deps.get("by_severity"),
            "scanners_run": deps.get("scanners_run"),
        }
    # Latest report markdown (any 05_report_*.md).
    md_candidates = sorted(run_dir.glob("05_report_*.md"))
    if md_candidates:
        ctx["report"] = _read_text(md_candidates[-1])
    return ctx


def ask(*, question: str, findings_dir: Path, db_path: Path, run_id: str | None) -> dict:
    question = (question or "").strip()
    if not question:
        return {"answer": "Ask a security question and I'll answer using your scan results.",
                "model": None, "provider": None, "context_used": None}

    bundle = build_context(findings_dir=findings_dir, db_path=db_path, run_id=run_id)
    bundle_json = json.dumps(bundle, default=str, indent=2)
    if len(bundle_json) > 30000:
        bundle_json = bundle_json[:30000] + "\n... (truncated)"

    prompt = (
        f"User question: {question}\n\n"
        f"Context (JSON):\n{bundle_json}\n"
    )
    router = default_router()
    resp = router.call(prompt, system=_SYSTEM, tier=Tier.FAST)
    return {
        "answer": resp.text.strip(),
        "model": resp.model,
        "provider": resp.provider,
        "context_used": {
            "run_id": run_id,
            "findings_count": len(bundle.get("findings") or []),
            "has_report": bool(bundle.get("report")),
            "has_score": bool(bundle.get("score")),
        },
    }
