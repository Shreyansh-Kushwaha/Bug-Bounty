"""Render the findings index into a standalone, self-contained HTML dashboard."""

from __future__ import annotations

import html
import json
import time
from pathlib import Path

from src.store.findings import FindingsStore

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "": 4, None: 4}

_CSS = """
:root { color-scheme: light dark; --bg:#0f1115; --card:#1a1d24; --fg:#e6e6e6;
  --muted:#9aa0aa; --line:#2a2f3a; --accent:#7aa2f7; }
* { box-sizing: border-box; }
body { margin:0; padding:2rem; background:var(--bg); color:var(--fg);
  font:15px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; }
h1 { margin:0 0 .25rem; font-size:1.5rem; }
.sub { color:var(--muted); margin-bottom:1.5rem; }
.cards { display:flex; gap:1rem; flex-wrap:wrap; margin-bottom:1.5rem; }
.card { background:var(--card); border:1px solid var(--line); border-radius:12px;
  padding:1rem 1.25rem; min-width:120px; }
.card .n { font-size:1.8rem; font-weight:700; }
.card .l { color:var(--muted); font-size:.8rem; text-transform:uppercase; letter-spacing:.04em; }
table { width:100%; border-collapse:collapse; background:var(--card);
  border:1px solid var(--line); border-radius:12px; overflow:hidden; }
th,td { text-align:left; padding:.6rem .8rem; border-bottom:1px solid var(--line);
  font-size:.9rem; vertical-align:top; }
th { color:var(--muted); text-transform:uppercase; font-size:.72rem; letter-spacing:.04em; }
tr:last-child td { border-bottom:none; }
.pill { display:inline-block; padding:.1rem .5rem; border-radius:999px; font-size:.75rem; font-weight:600; }
.critical{background:#5b1a1a;color:#ffb4b4;} .high{background:#5b3a1a;color:#ffcf9e;}
.medium{background:#4a4a1a;color:#f0eaa0;} .low{background:#1a3a4a;color:#a0d8f0;}
.yes{color:#7ee787;font-weight:700;} .no{color:#6b7280;}
code{background:#0008;padding:.1rem .35rem;border-radius:5px;font-size:.82rem;}
.overflow{overflow-x:auto;}
"""


def _pill(sev: str | None) -> str:
    s = (sev or "").lower()
    cls = s if s in ("critical", "high", "medium", "low") else "low"
    return f'<span class="pill {cls}">{html.escape(sev or "—")}</span>'


def _flag(v) -> str:
    return '<span class="yes">✓</span>' if v else '<span class="no">·</span>'


def generate_dashboard(db_path: Path, out_path: Path, target: str | None = None) -> Path:
    store = FindingsStore(db_path)
    try:
        rows = store.list_findings(target=target)
        dups = store.duplicates()
    finally:
        store.close()

    rows.sort(key=lambda r: (_SEV_ORDER.get((r["severity"] or "").lower(), 4), -r["created_at"]))

    total = len(rows)
    validated = sum(1 for r in rows if r["validated"])
    patched = sum(1 for r in rows if r["has_patch"])
    patch_ok = sum(1 for r in rows if r.get("patch_validated"))
    reported = sum(1 for r in rows if r["has_report"])

    body = [f"""<h1>Bug Bounty Findings</h1>
<div class="sub">{'Target: ' + html.escape(target) + ' · ' if target else ''}Generated {time.strftime('%Y-%m-%d %H:%M')}</div>
<div class="cards">
  <div class="card"><div class="n">{total}</div><div class="l">Findings</div></div>
  <div class="card"><div class="n">{validated}</div><div class="l">PoC validated</div></div>
  <div class="card"><div class="n">{patched}</div><div class="l">Patched</div></div>
  <div class="card"><div class="n">{patch_ok}</div><div class="l">Patch verified</div></div>
  <div class="card"><div class="n">{reported}</div><div class="l">Reports</div></div>
  <div class="card"><div class="n">{len(dups)}</div><div class="l">Duplicate groups</div></div>
</div>
<div class="overflow"><table>
<tr><th>Severity</th><th>Target</th><th>CWE</th><th>Title</th><th>Location</th>
<th>PoC</th><th>Patch</th><th>Verified</th><th>Report</th><th>Run</th></tr>"""]

    for r in rows:
        loc = f'{html.escape(r["file"] or "")}:{html.escape(r["line_range"] or "")}'
        body.append(
            f"<tr><td>{_pill(r['severity'])}</td>"
            f"<td>{html.escape(r['target'])}</td>"
            f"<td>{html.escape(r['cwe'] or '—')}</td>"
            f"<td>{html.escape(r['title'] or '')}</td>"
            f"<td><code>{loc}</code></td>"
            f"<td>{_flag(r['validated'])}</td>"
            f"<td>{_flag(r['has_patch'])}</td>"
            f"<td>{_flag(r.get('patch_validated'))}</td>"
            f"<td>{_flag(r['has_report'])}</td>"
            f"<td><code>{html.escape(r['run_id'])}</code></td></tr>"
        )
    body.append("</table></div>")

    if not rows:
        body.append('<p class="sub">No findings yet. Run the pipeline first.</p>')

    doc = (
        f"<!doctype html><html><head><meta charset='utf-8'>"
        f"<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>Bug Bounty Findings</title><style>{_CSS}</style></head>"
        f"<body>{''.join(body)}</body></html>"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(doc)
    return out_path


def triage_report(db_path: Path) -> dict:
    """Return duplicate groups + a flat summary for the `triage` command."""
    store = FindingsStore(db_path)
    try:
        return {
            "duplicates": store.duplicates(),
            "total": len(store.list_findings()),
        }
    finally:
        store.close()
