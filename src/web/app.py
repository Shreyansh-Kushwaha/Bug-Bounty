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
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from src.web import auth
from src.web.sanitize import host_allowed as _host_allowed, sanitize_html as _sanitize_html
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

if not auth.auth_enabled():
    import logging
    logging.getLogger("uvicorn.error").warning(
        "LOGIN_PASSWORD is not set - the web API is UNAUTHENTICATED. "
        "Set LOGIN_PASSWORD in .env before exposing this on a network."
    )


@app.middleware("http")
async def _require_auth(request: Request, call_next):
    """Gate every /api/* route behind a valid session when auth is enabled."""
    path = request.url.path
    if (
        auth.auth_enabled()
        and path.startswith("/api/")
        and path not in auth.PUBLIC_API_PATHS
        and request.method != "OPTIONS"
    ):
        if not auth.verify_token(request.cookies.get(auth.COOKIE_NAME)):
            return JSONResponse({"detail": "Authentication required"}, status_code=401)
    return await call_next(request)

# Permissive CORS for the Vite dev server (and any local React dev origin).
# Tighten origins in production if you put this behind a domain.
app.add_middleware(
    CORSMiddleware,
    # Local dev origins (Vite) plus any cross-origin frontend from ALLOWED_ORIGINS
    # (e.g. the Vercel deployment URL). Credentials are allowed so the session
    # cookie is sent cross-site.
    allow_origins=auth.allowed_origins(),
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

from src.store.targets import TargetsStore  # noqa: E402
targets_store = TargetsStore(DB_PATH)


def _all_targets() -> list[dict]:
    """Seed allowlist (config JSON) merged with web-attested targets (DB)."""
    seed = _load_targets()["authorized_targets"]
    seen = {t["repo"] for t in seed}
    merged = list(seed)
    for t in targets_store.list():
        if t["repo"] not in seen:
            merged.append(t)
    return merged


def _resolve_target_name(name: str) -> dict | None:
    for t in _load_targets()["authorized_targets"]:
        if t["name"] == name:
            return t
    return targets_store.get_by_name(name)


def _load_targets() -> dict:
    return json.loads(TARGETS_FILE.read_text())


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


# ---------- Authentication ----------

def _validate_run_id(run_id: str) -> str:
    if "/" in run_id or ".." in run_id or "\\" in run_id:
        raise HTTPException(400, "Bad run_id")
    return run_id


@app.get("/api/me")
def api_me(request: Request):
    authed = (not auth.auth_enabled()) or auth.verify_token(
        request.cookies.get(auth.COOKIE_NAME)
    )
    return {
        "authenticated": bool(authed),
        "auth_enabled": auth.auth_enabled(),
        "name": auth.operator_name() if authed else None,
    }


@app.post("/api/login")
def api_login(payload: dict):
    if not auth.auth_enabled():
        return {"ok": True, "auth_enabled": False}
    if not auth.check_password(str(payload.get("password", ""))):
        raise HTTPException(401, "Incorrect password")
    resp = JSONResponse({"ok": True, "name": auth.operator_name()})
    resp.set_cookie(
        auth.COOKIE_NAME, auth.mint_token(),
        httponly=True, samesite=auth.cookie_samesite(), secure=auth.cookie_secure(),
        max_age=7 * 24 * 3600, path="/",
    )
    return resp


@app.post("/api/logout")
def api_logout():
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(auth.COOKIE_NAME, path="/")
    return resp


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
    return {"targets": _all_targets()}


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
    if not _host_allowed(repo_url):
        raise HTTPException(
            400,
            "Repo host not allowed. Use github.com, gitlab.com, bitbucket.org, or codeberg.org.",
        )
    if not attested:
        raise HTTPException(400, "Attestation required")

    # Seed allowlist (static JSON) first, then previously-attested targets (DB).
    data = _load_targets()
    seed = {t["repo"]: t for t in data["authorized_targets"]}
    target = seed.get(repo_url) or targets_store.get_by_repo(repo_url)
    if target is None:
        base = _repo_name_from_url(repo_url)
        used_names = {t["name"] for t in data["authorized_targets"]} | targets_store.names()
        name, i = base, 2
        while name in used_names:
            name = f"{base}-{i}"
            i += 1
        # Persist the attestation to the DB — never mutate config/targets.json.
        target = targets_store.add(
            name=name, repo=repo_url, ref=ref, category="attested",
            notes=(f"Attested by {attested_by or 'api-user'} at {_iso_utc(time.time())}."
                   + (f" {notes}" if notes else "")),
            attested_by=attested_by or "api-user",
        )

    stop = stop_after if stop_after in ("recon", "analyst", "exploit", "patch") else None

    # Diff mode: analyze only files changed between two refs.
    base_ref = (payload.get("base_ref") or "").strip()
    head_ref = (payload.get("head_ref") or "").strip()
    if base_ref and head_ref:
        run_id = manager.start(
            target, stop_after=stop, auto_approve=auto_approve,
            diff=(base_ref, head_ref),
        )
        return {"run_id": run_id}

    run_id = manager.start(target, stop_after=stop, auto_approve=auto_approve)
    return {"run_id": run_id}


@app.get("/api/runs/{run_id}")
def api_run_detail(run_id: str):
    _validate_run_id(run_id)
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
    _validate_run_id(run_id)
    gate = (payload.get("gate") or "").strip()
    decision = (payload.get("decision") or "").strip()
    if decision not in ("approve", "abort"):
        raise HTTPException(400, "decision must be approve|abort")
    ok = manager.decide_gate(run_id, gate, decision == "approve")
    if not ok:
        raise HTTPException(409, f"No pending gate '{gate}' for run {run_id}")
    return {"ok": True}


_TERMINAL_STAGES = {"done", "error", "aborted"}


@app.get("/api/runs/{run_id}/events")
def api_run_events(run_id: str):
    """Server-Sent Events stream of status + log for a live run.

    Emits a `data:` frame roughly once a second until the run reaches a terminal
    stage, then closes. The React client falls back to polling if the stream
    errors or the browser lacks EventSource.
    """
    from fastapi.responses import StreamingResponse

    _validate_run_id(run_id)

    def _gen():
        deadline = time.time() + 2 * 3600  # hard stop after 2h
        while time.time() < deadline:
            status = manager.get(run_id)
            if status is None:
                yield 'data: {"error": "unknown run"}\n\n'
                return
            payload = {
                "status": _status_to_dict(status),
                "log": _clean_log(manager.log_tail(run_id)),
            }
            yield f"data: {json.dumps(payload, default=str)}\n\n"
            if status.current_stage in _TERMINAL_STAGES:
                return
            time.sleep(1.0)

    return StreamingResponse(
        _gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/api/runs/{run_id}/cancel")
def api_cancel(run_id: str):
    _validate_run_id(run_id)
    if not manager.cancel(run_id):
        raise HTTPException(409, "Run is not cancellable (unknown or already finished)")
    return {"ok": True}


@app.post("/api/runs/{run_id}/resume")
def api_resume(run_id: str, payload: dict | None = None):
    _validate_run_id(run_id)
    payload = payload or {}
    target_name = run_id.rsplit("_", 1)[0]
    target = _resolve_target_name(target_name)
    if target is None:
        raise HTTPException(404, f"No known target for run {run_id}")
    if not (FINDINGS_DIR / run_id).is_dir():
        raise HTTPException(404, "No artifacts to resume from")
    stop = payload.get("stop_after") or ""
    stop = stop if stop in ("recon", "analyst", "exploit", "patch") else None
    new_id = manager.resume(
        target, run_id=run_id, stop_after=stop,
        auto_approve=bool(payload.get("auto_approve")),
    )
    return {"run_id": new_id}


@app.get("/api/triage")
def api_triage():
    store = FindingsStore(DB_PATH)
    try:
        groups = store.duplicates()
        total = len(store.list_findings())
    finally:
        store.close()
    return {"total": total, "duplicates": groups}


@app.get("/api/runs/{run_id}/artifact/{name}")
def api_artifact(run_id: str, name: str):
    _validate_run_id(run_id)
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
        rendered = md.markdown(raw, extensions=["fenced_code", "tables", "toc", "sane_lists"])
        out["html"] = _sanitize_html(rendered)
        return out

    try:
        out["data"] = json.loads(path.read_text())
    except (json.JSONDecodeError, ValueError):
        out["raw"] = path.read_text(errors="replace")
    return out


@app.get("/api/findings")
def api_findings(target: str | None = None, limit: int = 50, offset: int = 0):
    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    store = FindingsStore(DB_PATH)
    try:
        rows = store.list_findings(target=target, limit=limit, offset=offset)
        total = store.count_findings(target=target)
    finally:
        store.close()
    return {
        "findings": rows,
        "target_filter": target,
        "total": total,
        "limit": limit,
        "offset": offset,
        "has_more": offset + len(rows) < total,
    }


@app.get("/api/runs/{run_id}/report.pdf")
def api_run_report_pdf(run_id: str):
    """Render the run's report into a styled multi-page PDF.

    Prefers the structured 05_report_*.json (richer layout: cover page,
    severity gauge, pipeline diagram, score chart, remediation checklist).
    Falls back to typesetting 05_report_*.md if only that exists.
    """
    _validate_run_id(run_id)
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
            t = _resolve_target_name(target_name)
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
        _validate_run_id(run_id)
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
