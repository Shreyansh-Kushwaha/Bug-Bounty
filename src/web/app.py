"""FastAPI web UI for the bug-bounty pipeline.

Routes:
  GET  /                         — home (new-run form + recent runs + targets)
  POST /runs                     — create & start a run (attestation required)
  GET  /runs/{run_id}            — run detail page (stages + live log + gates)
  GET  /runs/{run_id}/status     — HTMX poll partial
  POST /runs/{run_id}/gate       — approve/abort a pending HITL gate
  GET  /runs/{run_id}/artifact/{name}  — view an artifact (rendered or raw)
  GET  /findings                 — findings browser
  GET  /audit                    — audit log viewer

Authorization: the home form requires an attestation checkbox. On submit we
append to config/targets.json (deduped by repo URL) with attester handle and
UTC timestamp; the underlying allowlist enforcement is unchanged.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path

import markdown as md
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from src.store.audit import AuditLog
from src.store.findings import FindingsStore
from src.web.runner import RunManager

ROOT = Path(__file__).resolve().parent.parent.parent
TARGETS_FILE = ROOT / "config" / "targets.json"
REPOS_DIR = ROOT / "data" / "repos"
FINDINGS_DIR = ROOT / "data" / "findings"
AUDIT_LOG = ROOT / "data" / "audit.jsonl"
DB_PATH = ROOT / "data" / "findings.db"
WEB_DIR = Path(__file__).parent

app = FastAPI(title="Bug-Bounty Pipeline")
templates = Jinja2Templates(directory=str(WEB_DIR / "templates"))
app.mount(
    "/static",
    StaticFiles(directory=str(WEB_DIR / "static")),
    name="static",
)

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


templates.env.filters["iso_utc"] = _iso_utc


# Strip rich's ANSI-ish markup that leaks through when the Console writes to a
# non-terminal sink (e.g. "[bold cyan]Recon[/]"). Simple regex is enough here
# because we only see the markup form rich emits, not real ANSI escapes.
_RICH_MARKUP = re.compile(r"\[/?[a-z][a-z0-9_ #]*\]", re.IGNORECASE)


def _clean_log(text: str) -> str:
    return _RICH_MARKUP.sub("", text)


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    data = _load_targets()
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "targets": data["authorized_targets"],
            "runs": manager.list_runs()[:20],
        },
    )


@app.post("/runs")
def create_run(
    repo_url: str = Form(...),
    ref: str = Form("main"),
    stop_after: str = Form(""),
    attested: str = Form(""),
    attested_by: str = Form(""),
    notes: str = Form(""),
    auto_approve: str = Form(""),
):
    if not attested:
        raise HTTPException(
            status_code=400,
            detail="Authorization attestation required — tick the box confirming you own or have permission to test this repo.",
        )
    repo_url = repo_url.strip()
    if not re.match(r"^https?://", repo_url):
        raise HTTPException(400, "Repo URL must start with http(s)://")

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
        attester = (attested_by or "ui-user").strip()[:80]
        extra = (notes or "").strip()[:200]
        target = {
            "name": name,
            "repo": repo_url,
            "ref": ref.strip() or "main",
            "known_cve": None,
            "category": "attested",
            "notes": f"Attested by {attester} at {_iso_utc(time.time())}."
            + (f" {extra}" if extra else ""),
        }
        data["authorized_targets"].append(target)
        _save_targets(data)

    stop = stop_after if stop_after in ("recon", "analyst", "exploit", "patch") else None
    run_id = manager.start(
        target,
        stop_after=stop,
        auto_approve=bool(auto_approve),
    )
    return RedirectResponse(f"/runs/{run_id}", status_code=303)


def _render_run_context(request: Request, run_id: str, template: str):
    status = manager.get(run_id)
    if status is None:
        raise HTTPException(404, "Unknown run")
    artifacts = manager.list_artifacts(run_id)
    log_text = _clean_log(manager.log_tail(run_id))
    return templates.TemplateResponse(
        request,
        template,
        {
            "status": status,
            "artifacts": artifacts,
            "run_id": run_id,
            "log_text": log_text,
        },
    )


@app.get("/runs/{run_id}", response_class=HTMLResponse)
def run_detail(request: Request, run_id: str):
    return _render_run_context(request, run_id, "run_detail.html")


@app.get("/runs/{run_id}/status", response_class=HTMLResponse)
def run_status_partial(request: Request, run_id: str):
    return _render_run_context(request, run_id, "_run_status.html")


@app.post("/runs/{run_id}/gate")
def run_gate_decide(
    request: Request,
    run_id: str,
    gate: str = Form(...),
    decision: str = Form(...),
):
    if decision not in ("approve", "abort"):
        raise HTTPException(400, "decision must be approve|abort")
    ok = manager.decide_gate(run_id, gate, decision == "approve")
    if not ok:
        raise HTTPException(
            409, f"No pending gate '{gate}' for run {run_id} (already decided?)"
        )
    return RedirectResponse(f"/runs/{run_id}", status_code=303)


# ---------- Artifact rendering ----------

def _artifact_kind(name: str) -> str:
    if name == "01_recon.json":
        return "recon"
    if name == "02_analyst.json":
        return "analyst"
    if name.startswith("03_exploit") and name.endswith(".json"):
        return "exploit"
    if name.startswith("04_patch") and name.endswith(".json"):
        return "patch"
    if name.startswith("05_report") and name.endswith(".md"):
        return "report_md"
    if name.startswith("05_report") and name.endswith(".json"):
        return "report"
    return "raw"


@app.get("/runs/{run_id}/artifact/{name}", response_class=HTMLResponse)
def run_artifact(request: Request, run_id: str, name: str):
    if "/" in name or ".." in name or "\\" in name:
        raise HTTPException(400, "Bad artifact name")
    path = FINDINGS_DIR / run_id / name
    if not path.exists() or not path.is_file():
        raise HTTPException(404)

    kind = _artifact_kind(name)
    ctx: dict = {"name": name, "run_id": run_id, "kind": kind}

    if kind == "report_md":
        raw = path.read_text(errors="replace")
        html = md.markdown(
            raw,
            extensions=["fenced_code", "tables", "toc", "sane_lists"],
        )
        ctx["rendered_html"] = html
        ctx["raw"] = raw
        return templates.TemplateResponse(
            request, "artifact_markdown.html", ctx
        )

    # JSON artifacts
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, ValueError):
        ctx["raw"] = path.read_text(errors="replace")
        return templates.TemplateResponse(request, "artifact.html", ctx)

    ctx["data"] = data
    ctx["raw"] = json.dumps(data, indent=2)

    tmpl_map = {
        "recon": "artifact_recon.html",
        "analyst": "artifact_analyst.html",
        "exploit": "artifact_exploit.html",
        "patch": "artifact_patch.html",
        "report": "artifact_report.html",
    }
    template = tmpl_map.get(kind, "artifact.html")
    return templates.TemplateResponse(request, template, ctx)


# ---------- Findings & audit ----------

@app.get("/findings", response_class=HTMLResponse)
def findings_page(request: Request, target: str | None = None):
    store = FindingsStore(DB_PATH)
    rows = store.list_findings(target=target)
    store.close()
    return templates.TemplateResponse(
        request,
        "findings.html",
        {"findings": rows, "target_filter": target},
    )


@app.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request):
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
    return templates.TemplateResponse(
        request,
        "audit.html",
        {
            "entries": entries[:200],
            "total": len(entries),
            "chain_ok": ok,
            "broken_line": broken,
        },
    )
