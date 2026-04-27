"""FastAPI backend for the bug-bounty pipeline.

The UI lives entirely in the React app at /app/* (built into frontend/dist).
The backend only exposes:
  - JSON API at /api/*
  - Static assets at /app/assets/*
  - SPA fallback at /app, /app/, /app/<anything> → index.html
  - Bare-path redirects (/, /dashboard, /findings, …) → /app/<corresponding>
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import asdict
from pathlib import Path

import markdown as md
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from src.chat import ask as chat_ask
from src.models.router import MODEL_DAILY_LIMITS
from src.pdf_report import render_full_report_pdf, render_markdown_to_pdf
from src.scoring import compute_scores
from src.store.audit import AuditLog
from src.store.findings import FindingsStore
from src.store.usage import UsageStore
from src.web.runner import RunManager

ROOT = Path(__file__).resolve().parent.parent.parent
TARGETS_FILE = ROOT / "config" / "targets.json"
REPOS_DIR = ROOT / "data" / "repos"
FINDINGS_DIR = ROOT / "data" / "findings"
AUDIT_LOG = ROOT / "data" / "audit.jsonl"
DB_PATH = ROOT / "data" / "findings.db"
WEB_DIR = Path(__file__).parent

app = FastAPI(title="Bug-Bounty Pipeline")

# Permissive CORS for the Vite dev server (and any local React dev origin).
# Tighten origins in production if you put this behind a domain.
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"http://(localhost|127\.0\.0\.1):\d+",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve the built React app (frontend/dist/) at /app.
# Mount only the assets directory; serve index.html via a catch-all so React
# Router can handle client-side deep links (/app/dashboard, /app/about, …).
FRONTEND_DIST = ROOT / "frontend" / "dist"
if FRONTEND_DIST.exists():
    assets_dir = FRONTEND_DIST / "assets"
    if assets_dir.exists():
        app.mount("/app/assets", StaticFiles(directory=str(assets_dir)), name="app-assets")


# Serve top-level static files from frontend/dist (favicon, robots, etc.)
# These sit at /app/<file>, not /app/assets/<file>, so they need explicit handling.
_TOP_STATIC = {"favicon.svg", "favicon.ico", "robots.txt"}

manager = RunManager(
    repos_dir=REPOS_DIR,
    findings_dir=FINDINGS_DIR,
    audit_path=AUDIT_LOG,
    db_path=DB_PATH,
)


def _load_targets() -> dict:
    return json.loads(TARGETS_FILE.read_text())


def _save_targets(data: dict) -> None:
    TARGETS_FILE.write_text(json.dumps(data, indent=2) + "\n")


def _slug(s: str) -> str:
    s = s.lower().strip()
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    return s[:40] or "target"


def _repo_name_from_url(url: str) -> str:
    url = url.rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]
    return _slug(url.split("/")[-1])


def _iso_utc(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts))




# Strip rich's ANSI-ish markup that leaks through when the Console writes to a
# non-terminal sink (e.g. "[bold cyan]Recon[/]"). Simple regex is enough here
# because we only see the markup form rich emits, not real ANSI escapes.
_RICH_MARKUP = re.compile(r"\[/?[a-z][a-z0-9_ #]*\]", re.IGNORECASE)


def _clean_log(text: str) -> str:
    return _RICH_MARKUP.sub("", text)


def _quota_rows() -> list[dict]:
    """Today's per-model usage with limit annotation for the home page widget."""
    store = UsageStore(DB_PATH)
    rows = store.today_by_model()
    store.close()
    out = []
    for r in rows:
        limit = MODEL_DAILY_LIMITS.get(r["model"])
        pct = (r["calls"] / limit * 100) if limit else None
        out.append({
            **r,
            "limit": limit,
            "pct": pct,
            "warn": pct is not None and pct >= 75,
        })
    # Also surface known-limit models that have zero usage today
    seen = {r["model"] for r in out}
    for model, limit in MODEL_DAILY_LIMITS.items():
        if model not in seen:
            out.append({
                "model": model, "calls": 0, "prompt": 0,
                "completion": 0, "total": 0,
                "limit": limit, "pct": 0, "warn": False,
            })
    return out


# All HTML page routes are served by the React app (mounted at /app).
# Bare paths redirect to their React equivalents so old bookmarks still work.

@app.get("/")
def root_redirect():
    return RedirectResponse("/app/", status_code=307)


@app.get("/dashboard")
def dashboard_redirect():
    return RedirectResponse("/app/dashboard", status_code=307)


@app.get("/about")
def about_redirect():
    return RedirectResponse("/app/about", status_code=307)


@app.get("/features")
def features_redirect():
    return RedirectResponse("/app/features", status_code=307)


@app.get("/contact")
def contact_redirect():
    return RedirectResponse("/app/contact", status_code=307)




@app.get("/runs/{run_id}")
def run_detail_redirect(run_id: str):
    return RedirectResponse(f"/app/runs/{run_id}", status_code=307)


# ---------- Artifact rendering ----------

def _artifact_kind(name: str) -> str:
    if name == "01_recon.json":
        return "recon"
    if name == "01b_secrets.json":
        return "secrets"
    if name == "01c_deps.json":
        return "deps"
    if name == "02_analyst.json":
        return "analyst"
    if name == "02b_roadmap.json":
        return "roadmap"
    if name.startswith("03_exploit") and name.endswith(".json"):
        return "exploit"
    if name.startswith("04_patch") and name.endswith(".json"):
        return "patch"
    if name.endswith("_eli5.md"):
        return "eli5_md"
    if name.startswith("05_report") and name.endswith(".md"):
        return "report_md"
    if name.startswith("05_report") and name.endswith(".json"):
        return "report"
    if name == "06_score.json":
        return "score"
    return "raw"


@app.get("/runs/{run_id}/artifact/{name}")
def artifact_redirect(run_id: str, name: str):
    return RedirectResponse(f"/app/runs/{run_id}/artifact/{name}", status_code=307)


@app.get("/findings")
def findings_redirect(target: str | None = None):
    suffix = f"?target={target}" if target else ""
    return RedirectResponse(f"/app/findings{suffix}", status_code=307)


@app.get("/audit")
def audit_redirect():
    return RedirectResponse("/app/audit", status_code=307)


# =====================================================================
# JSON API (for the React frontend in frontend/)
# =====================================================================

def _status_to_dict(status) -> dict:
    """RunStatus → JSON-safe dict (drops StringIO log_buffer)."""
    d = asdict(status)
    d.pop("log_buffer", None)
    return d


@app.get("/api/health")
def api_health():
    return {"ok": True}


# ---------- SPA fallback for the React app ----------
@app.get("/app", include_in_schema=False)
@app.get("/app/", include_in_schema=False)
@app.get("/app/{full_path:path}", include_in_schema=False)
def serve_spa(full_path: str = ""):
    if not FRONTEND_DIST.exists():
        raise HTTPException(404, "React build not present. Run `npm run build` in frontend/.")
    # Top-level static files (favicon etc.) live at /app/<file>.
    if full_path in _TOP_STATIC:
        target = FRONTEND_DIST / full_path
        if target.is_file():
            from fastapi.responses import FileResponse
            return FileResponse(str(target))
    # Real /assets/* paths are handled by the StaticFiles mount above; everything
    # else is a React Router route — return index.html.
    index = FRONTEND_DIST / "index.html"
    return HTMLResponse(index.read_text())


@app.get("/api/targets")
def api_targets():
    data = _load_targets()
    return {"targets": data["authorized_targets"]}


@app.get("/api/quota")
def api_quota():
    return {"quota": _quota_rows()}


@app.get("/api/runs")
def api_list_runs(limit: int = 20):
    runs = manager.list_runs()[: max(1, min(limit, 100))]
    return {"runs": [_status_to_dict(r) for r in runs]}


@app.post("/api/runs")
def api_create_run(payload: dict):
    repo_url = (payload.get("repo_url") or "").strip()
    ref = (payload.get("ref") or "main").strip() or "main"
    stop_after = payload.get("stop_after") or ""
    attested = bool(payload.get("attested"))
    attested_by = (payload.get("attested_by") or "").strip()[:80]
    notes = (payload.get("notes") or "").strip()[:200]
    auto_approve = bool(payload.get("auto_approve"))

    if not repo_url or not re.match(r"^https?://", repo_url):
        raise HTTPException(400, "Repo URL must start with http(s)://")
    if not attested:
        raise HTTPException(400, "Attestation required")

    data = _load_targets()
    target = next(
        (t for t in data["authorized_targets"] if t["repo"] == repo_url),
        None,
    )
    if target is None:
        base = _repo_name_from_url(repo_url)
        used = {t["name"] for t in data["authorized_targets"]}
        name, i = base, 2
        while name in used:
            name = f"{base}-{i}"
            i += 1
        target = {
            "name": name,
            "repo": repo_url,
            "ref": ref,
            "known_cve": None,
            "category": "attested",
            "notes": f"Attested by {attested_by or 'api-user'} at {_iso_utc(time.time())}."
            + (f" {notes}" if notes else ""),
        }
        data["authorized_targets"].append(target)
        _save_targets(data)

    stop = stop_after if stop_after in ("recon", "analyst", "exploit", "patch") else None
    run_id = manager.start(target, stop_after=stop, auto_approve=auto_approve)
    return {"run_id": run_id}


@app.get("/api/runs/{run_id}")
def api_run_detail(run_id: str):
    status = manager.get(run_id)
    if status is None:
        raise HTTPException(404, "Unknown run")
    artifacts = manager.list_artifacts(run_id)
    log_text = _clean_log(manager.log_tail(run_id))
    usage = UsageStore(DB_PATH)
    tokens = usage.run_totals(run_id)
    usage.close()
    return {
        "status": _status_to_dict(status),
        "artifacts": artifacts,
        "log": log_text,
        "tokens": tokens,
    }


@app.post("/api/runs/{run_id}/gate")
def api_gate(run_id: str, payload: dict):
    gate = (payload.get("gate") or "").strip()
    decision = (payload.get("decision") or "").strip()
    if decision not in ("approve", "abort"):
        raise HTTPException(400, "decision must be approve|abort")
    ok = manager.decide_gate(run_id, gate, decision == "approve")
    if not ok:
        raise HTTPException(409, f"No pending gate '{gate}' for run {run_id}")
    return {"ok": True}


@app.get("/api/runs/{run_id}/artifact/{name}")
def api_artifact(run_id: str, name: str):
    if "/" in name or ".." in name or "\\" in name:
        raise HTTPException(400, "Bad artifact name")
    path = FINDINGS_DIR / run_id / name
    if not path.exists() or not path.is_file():
        raise HTTPException(404)

    kind = _artifact_kind(name)
    out: dict = {"name": name, "run_id": run_id, "kind": kind}

    if kind in ("report_md", "eli5_md"):
        raw = path.read_text(errors="replace")
        out["raw"] = raw
        out["html"] = md.markdown(raw, extensions=["fenced_code", "tables", "toc", "sane_lists"])
        return out

    try:
        out["data"] = json.loads(path.read_text())
    except (json.JSONDecodeError, ValueError):
        out["raw"] = path.read_text(errors="replace")
    return out


@app.get("/api/findings")
def api_findings(target: str | None = None):
    store = FindingsStore(DB_PATH)
    rows = store.list_findings(target=target)
    store.close()
    return {"findings": rows, "target_filter": target}


@app.get("/api/runs/{run_id}/report.pdf")
def api_run_report_pdf(run_id: str):
    """Render the run's report into a styled multi-page PDF.

    Prefers the structured 05_report_*.json (richer layout: cover page,
    severity gauge, pipeline diagram, score chart, remediation checklist).
    Falls back to typesetting 05_report_*.md if only that exists.
    """
    run_dir = FINDINGS_DIR / run_id
    if not run_dir.is_dir():
        raise HTTPException(404, "Unknown run")

    json_candidates = sorted(p for p in run_dir.glob("05_report_*.json"))
    if json_candidates:
        report = json.loads(json_candidates[-1].read_text())
        score = None
        roadmap = None
        score_path = run_dir / "06_score.json"
        if score_path.exists():
            score = json.loads(score_path.read_text())
        roadmap_path = run_dir / "02b_roadmap.json"
        if roadmap_path.exists():
            roadmap = json.loads(roadmap_path.read_text())

        # Resolve target name + repo url from the run id (target_<unix>) and targets file.
        target_name = run_id.rsplit("_", 1)[0]
        repo_url = ""
        try:
            data = _load_targets()
            t = next((x for x in data["authorized_targets"] if x["name"] == target_name), None)
            if t:
                repo_url = t["repo"]
        except Exception:  # noqa: BLE001
            pass

        pdf_bytes = render_full_report_pdf(
            report=report, score=score, roadmap=roadmap,
            target_name=target_name, repo_url=repo_url, run_id=run_id,
        )
    else:
        md_candidates = sorted(run_dir.glob("05_report_*.md"))
        md_candidates = [p for p in md_candidates if not p.name.endswith("_eli5.md")]
        if not md_candidates:
            raise HTTPException(404, "No report for this run yet")
        pdf_bytes = render_markdown_to_pdf(md_candidates[-1].read_text(errors="replace"))

    headers = {"Content-Disposition": f'inline; filename="{run_id}.pdf"'}
    return Response(content=pdf_bytes, media_type="application/pdf", headers=headers)


@app.get("/api/score")
def api_score_overview(run_id: str | None = None):
    """Per-category score. With ?run_id=, returns that run's stored score
    (06_score.json). Without, computes a quick all-time score from the
    findings DB so the dashboard always has something to show."""
    if run_id:
        path = FINDINGS_DIR / run_id / "06_score.json"
        if not path.exists():
            raise HTTPException(404, "No score for that run yet")
        return {"score": json.loads(path.read_text()), "scope": "run", "run_id": run_id}

    # Aggregate fallback: convert each finding row into a hypothesis-like dict
    # and compute an overall score across the whole DB.
    store = FindingsStore(DB_PATH)
    rows = store.list_findings()
    store.close()
    pseudo_hypotheses = [{"severity": r.get("severity") or "low",
                          "exploitability": "high" if r.get("validated") else "medium",
                          "cwe": r.get("cwe")} for r in rows]
    score = compute_scores(
        secrets_artifact=None,
        deps_artifact=None,
        analyst_hypotheses=pseudo_hypotheses,
        exploit_validated=any(r.get("validated") for r in rows) if rows else None,
    )
    return {"score": score, "scope": "all", "findings_counted": len(rows)}


@app.post("/api/chat")
def api_chat(payload: dict):
    """'Ask Security AI' — one-shot Q&A grounded in the findings DB and (if
    given) a specific run's artifacts."""
    question = (payload.get("question") or "").strip()
    if not question:
        raise HTTPException(400, "question is required")
    run_id = payload.get("run_id")
    if run_id and ("/" in run_id or ".." in run_id or "\\" in run_id):
        raise HTTPException(400, "Bad run_id")
    try:
        result = chat_ask(
            question=question[:2000],
            findings_dir=FINDINGS_DIR,
            db_path=DB_PATH,
            run_id=run_id,
        )
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"LLM call failed: {e}")
    return result


@app.get("/api/audit")
def api_audit(limit: int = 200):
    entries: list[dict] = []
    if AUDIT_LOG.exists():
        for line in AUDIT_LOG.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    entries.reverse()
    ok, broken = AuditLog(AUDIT_LOG).verify()
    return {
        "entries": entries[: max(1, min(limit, 1000))],
        "total": len(entries),
        "chain_ok": ok,
        "broken_line": broken,
    }
