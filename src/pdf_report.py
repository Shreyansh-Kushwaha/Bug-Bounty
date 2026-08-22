"""PDF report renderer.

Two entry points:
  * render_full_report_pdf(...) — rich, multi-page report with a cover page,
    severity gauge, pipeline diagram, score chart, and remediation checklist.
    Used when we have the structured report.json + score.json + roadmap.json.
  * render_markdown_to_pdf(text) — minimal fallback that just typesets a
    markdown string. Kept for the case where the structured artifacts are
    missing (e.g. older runs).

Uses fpdf2's built-in Times font (no embedded font files needed).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from fpdf import FPDF

# ---------- design tokens ----------
PAGE_W = 210                   # A4 mm
PAGE_H = 297
M = 18                         # left/right margin
CONTENT_W = PAGE_W - 2 * M

INK = (28, 30, 38)             # body
INK_DIM = (110, 116, 130)
RULE = (210, 214, 224)
ACCENT = (37, 99, 235)         # blue
SOFT_BG = (244, 246, 251)

SEVERITY_COLORS = {
    "critical": (190, 18, 60),
    "high":     (220, 38, 38),
    "medium":   (217, 119, 6),
    "moderate": (217, 119, 6),
    "low":      (37, 99, 235),
    "unknown":  (110, 116, 130),
}

# Times is built into PDF; "Helvetica" is also built-in. We use Times for body
# per the user's request, and keep Helvetica for small accent labels (cleaner
# at small sizes).
BODY = "Times"
ACCENT_FONT = "Helvetica"


# ---------- low-level PDF subclass ----------
class _Doc(FPDF):
    """Adds running header/footer that skip the cover page.

    Also forces all text written via cell/multi_cell through `_latin()` so a
    stray Unicode character in upstream JSON (em-dash, smart quotes, etc.)
    can't kill the whole render — fpdf2 core fonts are Latin-1 only.
    """

    def cell(self, *args, **kwargs):  # type: ignore[override]
        if "text" in kwargs:
            kwargs["text"] = _latin(kwargs["text"])
        elif len(args) >= 3:
            args = (args[0], args[1], _latin(args[2]), *args[3:])
        return super().cell(*args, **kwargs)

    def multi_cell(self, *args, **kwargs):  # type: ignore[override]
        if "text" in kwargs:
            kwargs["text"] = _latin(kwargs["text"])
        elif len(args) >= 3:
            args = (args[0], args[1], _latin(args[2]), *args[3:])
        return super().multi_cell(*args, **kwargs)

    def header(self) -> None:
        if self.page_no() == 1:
            return
        self.set_font(ACCENT_FONT, "", 8)
        self.set_text_color(*INK_DIM)
        self.set_y(8)
        self.cell(0, 4, "Bug-Bounty Security Report", align="L")
        self.set_xy(M, 8)
        self.set_x(-M)
        self.cell(0, 4, getattr(self, "_running_title", ""), align="R")
        self.set_y(13)
        self.set_draw_color(*RULE)
        self.line(M, 13, PAGE_W - M, 13)
        self.set_y(M)

    def footer(self) -> None:
        if self.page_no() == 1:
            return
        self.set_y(-12)
        self.set_font(ACCENT_FONT, "I", 8)
        self.set_text_color(*INK_DIM)
        self.cell(0, 5, f"Page {self.page_no()}", align="C")


# ---------- PUBLIC ----------
def render_full_report_pdf(
    *,
    report: dict,
    score: dict | None = None,
    roadmap: dict | None = None,
    target_name: str = "",
    repo_url: str = "",
    run_id: str = "",
) -> bytes:
    """Render a structured Report + score + roadmap into a multi-page PDF."""
    pdf = _Doc(format="A4", unit="mm")
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.set_margins(M, M, M)
    pdf._running_title = (report.get("title") or "Security Report")[:80]

    _cover(pdf, report=report, target_name=target_name, repo_url=repo_url, run_id=run_id)
    _executive_summary(pdf, report=report, score=score)
    _pipeline_overview(pdf)
    _vulnerability_detail(pdf, report=report)
    if score:
        _score_section(pdf, score=score)
    if roadmap:
        _roadmap_section(pdf, roadmap=roadmap)
    _remediation_checklist(pdf, report=report)
    _references_and_glossary(pdf, report=report)

    out = pdf.output(dest="S")
    if isinstance(out, str):
        return out.encode("latin-1")
    return bytes(out)


def render_markdown_to_pdf(markdown_text: str) -> bytes:
    """Fallback for older runs: typeset a markdown string."""
    pdf = _Doc(format="A4", unit="mm")
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.set_margins(M, M, M)
    pdf._running_title = "Report"
    pdf.add_page()
    _markdown_block(pdf, markdown_text)
    out = pdf.output(dest="S")
    if isinstance(out, str):
        return out.encode("latin-1")
    return bytes(out)


# ---------- COVER PAGE ----------
def _cover(pdf: _Doc, *, report: dict, target_name: str, repo_url: str, run_id: str) -> None:
    pdf.add_page()
    sev = (report.get("severity") or "unknown").lower()
    sev_color = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["unknown"])

    # Top accent band.
    pdf.set_fill_color(*ACCENT)
    pdf.rect(0, 0, PAGE_W, 6, "F")

    # Brand mark.
    pdf.set_y(20)
    pdf.set_font(ACCENT_FONT, "B", 9)
    pdf.set_text_color(*ACCENT)
    pdf.cell(0, 5, "BUG-BOUNTY  |  SECURITY ASSESSMENT REPORT", align="L")

    # Big severity badge top-right.
    badge_w, badge_h = 46, 18
    badge_x = PAGE_W - M - badge_w
    badge_y = 18
    pdf.set_fill_color(*sev_color)
    pdf.rect(badge_x, badge_y, badge_w, badge_h, "F")
    pdf.set_text_color(255, 255, 255)
    pdf.set_font(ACCENT_FONT, "B", 11)
    pdf.set_xy(badge_x, badge_y + 3)
    pdf.cell(badge_w, 5, sev.upper(), align="C")
    pdf.set_xy(badge_x, badge_y + 9)
    pdf.set_font(ACCENT_FONT, "", 9)
    pdf.cell(badge_w, 5, f"CVSS {report.get('cvss_score', 'N/A')}", align="C")

    # Big title.
    pdf.set_y(60)
    pdf.set_x(M)
    pdf.set_text_color(*INK)
    pdf.set_font(BODY, "B", 24)
    title = report.get("title") or "Security Finding"
    _multi(pdf, title, h=10, w=CONTENT_W)

    pdf.ln(2)
    pdf.set_font(BODY, "", 12)
    pdf.set_text_color(*INK_DIM)
    if report.get("cwe"):
        pdf.cell(0, 6, f"{report['cwe']}  -  {_cwe_name(report['cwe'])}", ln=1)

    # Meta box.
    pdf.ln(8)
    box_y = pdf.get_y()
    pdf.set_fill_color(*SOFT_BG)
    pdf.set_draw_color(*RULE)
    pdf.rect(M, box_y, CONTENT_W, 50, "FD")

    rows = [
        ("Target", target_name or report.get("target", "n/a")),
        ("Repository", repo_url or "n/a"),
        ("Run ID", run_id or "n/a"),
        ("CWE", report.get("cwe", "n/a")),
        ("CVSS Vector", report.get("cvss_vector", "n/a")),
        ("Generated", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")),
    ]
    pdf.set_y(box_y + 4)
    for label, value in rows:
        pdf.set_x(M + 4)
        pdf.set_font(ACCENT_FONT, "B", 8)
        pdf.set_text_color(*INK_DIM)
        pdf.cell(28, 6, label.upper(), align="L")
        pdf.set_font(BODY, "", 10)
        pdf.set_text_color(*INK)
        pdf.cell(0, 6, str(value)[:90], ln=1)

    # Severity gauge.
    pdf.set_y(box_y + 60)
    _severity_gauge(pdf, score=float(report.get("cvss_score") or 0.0))

    # Footer disclaimer (turn off auto break so we can hug the bottom margin).
    pdf.set_auto_page_break(auto=False)
    pdf.set_y(PAGE_H - 40)
    pdf.set_x(M)
    pdf.set_font(BODY, "I", 9)
    pdf.set_text_color(*INK_DIM)
    _multi(pdf,
        "This report was generated by an automated AI security pipeline. "
        "It must be reviewed by a human before any disclosure or remediation work. "
        "The proof-of-concept inside is for validation only and must not be used "
        "against systems you do not own or have written permission to test.",
        h=4.5, w=CONTENT_W,
    )
    pdf.set_auto_page_break(auto=True, margin=20)


def _severity_gauge(pdf: _Doc, *, score: float) -> None:
    """Horizontal CVSS bar with current score marked."""
    pdf.set_x(M)
    pdf.set_font(ACCENT_FONT, "B", 9)
    pdf.set_text_color(*INK)
    pdf.cell(0, 5, "CVSS SEVERITY", ln=1)

    bar_y = pdf.get_y() + 2
    bar_h = 10
    # Coloured segments matching CVSS bands (None=0, Low<4, Med<7, High<9, Critical<=10)
    segs = [
        (0.0, 4.0, SEVERITY_COLORS["low"]),
        (4.0, 7.0, SEVERITY_COLORS["medium"]),
        (7.0, 9.0, SEVERITY_COLORS["high"]),
        (9.0, 10.0, SEVERITY_COLORS["critical"]),
    ]
    for lo, hi, color in segs:
        x = M + (lo / 10.0) * CONTENT_W
        w = ((hi - lo) / 10.0) * CONTENT_W
        pdf.set_fill_color(*color)
        pdf.rect(x, bar_y, w, bar_h, "F")

    # Marker.
    score_clamped = max(0.0, min(10.0, score))
    mx = M + (score_clamped / 10.0) * CONTENT_W
    pdf.set_draw_color(20, 20, 20)
    pdf.set_line_width(0.6)
    pdf.line(mx, bar_y - 2, mx, bar_y + bar_h + 2)
    pdf.set_line_width(0.2)

    # Tick labels under the bar.
    pdf.set_y(bar_y + bar_h + 1)
    pdf.set_font(ACCENT_FONT, "", 8)
    pdf.set_text_color(*INK_DIM)
    for label, x_off in [("Low 0", 0.0), ("Medium 4", 0.4), ("High 7", 0.7), ("Critical 9", 0.9), ("10", 1.0)]:
        pdf.set_xy(M + x_off * CONTENT_W - 8, bar_y + bar_h + 1)
        pdf.cell(16, 4, label, align="C")
    # Score label above the marker
    pdf.set_xy(mx - 10, bar_y - 8)
    pdf.set_font(ACCENT_FONT, "B", 9)
    pdf.set_text_color(20, 20, 20)
    pdf.cell(20, 4, f"{score_clamped:.1f}", align="C")


# ---------- PAGE 2: EXECUTIVE SUMMARY + SCORE PEEK ----------
def _executive_summary(pdf: _Doc, *, report: dict, score: dict | None) -> None:
    pdf.add_page()
    _section_title(pdf, "1.  Executive Summary")

    pdf.set_font(BODY, "", 11)
    pdf.set_text_color(*INK)
    _multi(pdf, report.get("summary") or "No summary provided.", h=5.5, w=CONTENT_W)
    pdf.ln(4)

    # Key facts mini-cards.
    _mini_cards(pdf, [
        ("Severity", (report.get("severity") or "—").title(), SEVERITY_COLORS.get((report.get("severity") or "unknown").lower(), INK)),
        ("CVSS",     str(report.get("cvss_score", "—")),       ACCENT),
        ("Category", report.get("cwe", "—"),                   INK),
        ("Score",    str((score or {}).get("overall", "—")) + (f" ({(score or {}).get('grade','')})" if score else ""), (37, 99, 235)),
    ])

    pdf.ln(6)
    _section_title(pdf, "1.1  Plain-English Explanation")
    pdf.set_font(BODY, "", 11)
    pdf.set_text_color(*INK)
    eli5 = report.get("eli5") or _derive_eli5(report)
    _callout_box(pdf, eli5, color=ACCENT)


# ---------- PIPELINE OVERVIEW ----------
def _pipeline_overview(pdf: _Doc) -> None:
    pdf.add_page()
    _section_title(pdf, "2.  How This Report Was Generated")

    pdf.set_font(BODY, "", 11)
    pdf.set_text_color(*INK)
    _multi(pdf,
        "Every finding in this report was produced by a five-stage automated pipeline. "
        "Each stage feeds the next; humans approve before any potentially intrusive step.",
        h=5.5, w=CONTENT_W,
    )
    pdf.ln(6)

    stages = [
        ("Recon",    "Clone the repo, map the attack surface, run secret + dependency scanners."),
        ("Analyst",  "Read the risky files and form ranked, evidence-cited vulnerability hypotheses."),
        ("Exploit",  "Generate a non-destructive proof-of-concept and validate it inside a sandbox."),
        ("Patch",    "Propose a unified diff fix with a regression test that proves the fix works."),
        ("Report",   "Draft this disclosure-ready document with CVSS, impact, and remediation."),
    ]
    _stage_diagram(pdf, stages)


def _stage_diagram(pdf: _Doc, stages: list[tuple[str, str]]) -> None:
    """Five horizontal pills connected by arrows + descriptions below each."""
    pill_w = (CONTENT_W - 4 * 6) / 5  # 4 gaps of 6mm
    pill_h = 14
    y = pdf.get_y()
    pdf.set_text_color(255, 255, 255)
    for i, (name, _) in enumerate(stages):
        x = M + i * (pill_w + 6)
        pdf.set_fill_color(*ACCENT)
        pdf.rect(x, y, pill_w, pill_h, "F")
        pdf.set_xy(x, y + 3.5)
        pdf.set_font(ACCENT_FONT, "B", 8)
        pdf.cell(pill_w, 4, f"STAGE {i+1}", align="C")
        pdf.set_xy(x, y + 8)
        pdf.set_font(ACCENT_FONT, "B", 12)
        pdf.cell(pill_w, 5, name, align="C")
        # arrow connector
        if i < len(stages) - 1:
            arr_x = x + pill_w
            arr_y = y + pill_h / 2
            pdf.set_draw_color(*INK_DIM)
            pdf.set_line_width(0.5)
            pdf.line(arr_x + 1, arr_y, arr_x + 5, arr_y)
            pdf.line(arr_x + 4, arr_y - 1, arr_x + 5, arr_y)
            pdf.line(arr_x + 4, arr_y + 1, arr_x + 5, arr_y)
            pdf.set_line_width(0.2)

    # Descriptions
    pdf.set_y(y + pill_h + 4)
    for i, (name, desc) in enumerate(stages):
        x = M + i * (pill_w + 6)
        pdf.set_xy(x, pdf.get_y() if i == 0 else y + pill_h + 4)
        pdf.set_text_color(*INK_DIM)
        pdf.set_font(BODY, "", 8.5)
        pdf.set_xy(x, y + pill_h + 4)
        pdf.multi_cell(pill_w, 3.6, desc)
    pdf.set_y(y + pill_h + 32)


# ---------- VULNERABILITY DETAIL ----------
def _vulnerability_detail(pdf: _Doc, *, report: dict) -> None:
    pdf.add_page()
    _section_title(pdf, "3.  Vulnerability Detail")

    _kv_block(pdf, [
        ("Title",  report.get("title", "—")),
        ("CWE",    f"{report.get('cwe', '—')}  -  {_cwe_name(report.get('cwe', ''))}"),
        ("CVSS",   f"{report.get('cvss_score', '—')}  ({report.get('cvss_vector', 'n/a')})"),
        ("Target", report.get("target", "—")),
    ])

    pdf.ln(5)
    _subsection_title(pdf, "3.1  Steps to Reproduce")
    steps = report.get("steps_to_reproduce") or []
    if steps:
        _numbered_list(pdf, steps)
    else:
        _muted(pdf, "No steps provided.")

    pdf.ln(2)
    _subsection_title(pdf, "3.2  Proof of Concept")
    poc = report.get("proof_of_concept") or "(none)"
    _code_block(pdf, poc)

    pdf.ln(2)
    _subsection_title(pdf, "3.3  Impact")
    pdf.set_font(BODY, "", 11)
    pdf.set_text_color(*INK)
    _multi(pdf, report.get("impact") or "Not specified.", h=5.5, w=CONTENT_W)


# ---------- SCORE SECTION ----------
def _score_section(pdf: _Doc, *, score: dict) -> None:
    pdf.add_page()
    _section_title(pdf, "4.  Repository Security Score")

    overall = int(score.get("overall", 0))
    grade = score.get("grade", "?")
    band = score.get("risk_band", "")
    cats = score.get("categories", []) or []

    # Overall callout.
    y = pdf.get_y()
    pdf.set_fill_color(*SOFT_BG)
    pdf.rect(M, y, CONTENT_W, 30, "F")
    pdf.set_xy(M + 6, y + 4)
    pdf.set_font(ACCENT_FONT, "B", 10)
    pdf.set_text_color(*INK_DIM)
    pdf.cell(0, 4, "OVERALL SECURITY SCORE")
    pdf.set_xy(M + 6, y + 10)
    pdf.set_font(BODY, "B", 28)
    color = (16, 185, 129) if overall >= 80 else (217, 119, 6) if overall >= 60 else (220, 38, 38)
    pdf.set_text_color(*color)
    pdf.cell(40, 14, f"{overall}", align="L")
    pdf.set_xy(M + 50, y + 12)
    pdf.set_font(BODY, "B", 16)
    pdf.set_text_color(*INK)
    pdf.cell(0, 6, f"Grade {grade}  -  {band.title()} risk", ln=1)
    pdf.set_y(y + 35)

    # Per-category bar chart.
    _subsection_title(pdf, "4.1  Per-Category Breakdown")
    for c in cats:
        _hbar_row(pdf, label=str(c.get("name", "")).title(),
                  value=int(c.get("score", 0)), detail=str(c.get("detail", "")))

    pdf.ln(2)
    _muted(pdf,
        "Higher score = safer. Categories: Secrets (leaked credentials), Dependencies "
        "(known CVEs), Code (analyst hypotheses), Exploitability (PoC outcome).",
    )


def _hbar_row(pdf: _Doc, *, label: str, value: int, detail: str) -> None:
    label_w = 38
    bar_w = CONTENT_W - label_w - 38
    pdf.set_x(M)
    pdf.set_font(BODY, "", 10)
    pdf.set_text_color(*INK)
    pdf.cell(label_w, 6, label)
    y = pdf.get_y()
    bar_x = M + label_w
    pdf.set_fill_color(*SOFT_BG)
    pdf.rect(bar_x, y + 1.5, bar_w, 4, "F")
    color = (16, 185, 129) if value >= 80 else (217, 119, 6) if value >= 60 else (220, 38, 38)
    pdf.set_fill_color(*color)
    pdf.rect(bar_x, y + 1.5, bar_w * value / 100.0, 4, "F")
    pdf.set_xy(bar_x + bar_w + 2, y)
    pdf.set_font(ACCENT_FONT, "B", 10)
    pdf.cell(20, 6, f"{value}/100")
    pdf.set_x(M + label_w)
    pdf.set_font(BODY, "I", 8.5)
    pdf.set_text_color(*INK_DIM)
    pdf.set_y(y + 6)
    pdf.set_x(M + label_w)
    pdf.multi_cell(bar_w + 38, 4, detail[:160])
    pdf.ln(1)


# ---------- ROADMAP ----------
def _roadmap_section(pdf: _Doc, *, roadmap: dict) -> None:
    items = (roadmap.get("items") or [])[:10]
    if not items:
        return
    pdf.add_page()
    _section_title(pdf, "5.  Prioritized Fix Roadmap")
    pdf.set_font(BODY, "", 11)
    pdf.set_text_color(*INK)
    _multi(pdf,
        "These are the top issues, ranked by severity and exploitability. Address #1 first.",
        h=5.5, w=CONTENT_W,
    )
    pdf.ln(3)

    for it in items:
        sev = (it.get("severity") or "low").lower()
        sev_color = SEVERITY_COLORS.get(sev, INK)
        rank = it.get("rank", "?")
        title = it.get("title", "")[:90]
        loc = it.get("file") or ""
        if it.get("line_range"):
            loc = f"{loc}:{it['line_range']}"
        fix = it.get("fix_recommendation", "")
        effort = (it.get("effort") or "").title()

        # Title row.
        y_top = pdf.get_y()
        pdf.set_xy(M + 5, y_top)
        pdf.set_font(BODY, "B", 11)
        pdf.set_text_color(*INK)
        pdf.cell(0, 5.5, f"#{rank}  {title}", ln=1)

        # Meta row.
        pdf.set_x(M + 5)
        pdf.set_font(ACCENT_FONT, "", 8)
        pdf.set_text_color(*INK_DIM)
        meta = f"Severity: {sev.title()}  -  Effort: {effort or 'medium'}"
        if loc:
            meta += f"  -  {loc}"
        pdf.cell(0, 4.5, meta, ln=1)

        # Fix recommendation, multi-line.
        pdf.set_x(M + 5)
        pdf.set_font(BODY, "", 10)
        pdf.set_text_color(*INK)
        pdf.multi_cell(CONTENT_W - 5, 4.8, fix[:300])
        y_bot = pdf.get_y()

        # Severity stripe sized to actual content height.
        pdf.set_fill_color(*sev_color)
        pdf.rect(M, y_top, 2, max(10, y_bot - y_top - 1), "F")

        pdf.ln(3)
        # Hairline separator between items.
        pdf.set_draw_color(*RULE)
        pdf.line(M, pdf.get_y() - 1, PAGE_W - M, pdf.get_y() - 1)


# ---------- REMEDIATION CHECKLIST ----------
def _remediation_checklist(pdf: _Doc, *, report: dict) -> None:
    pdf.add_page()
    _section_title(pdf, "6.  Remediation")
    pdf.set_font(BODY, "", 11)
    pdf.set_text_color(*INK)
    _multi(pdf, report.get("remediation") or "Not specified.", h=5.5, w=CONTENT_W)

    pdf.ln(4)
    _subsection_title(pdf, "6.1  Action Checklist")
    items = _derive_checklist(report)
    for it in items:
        y = pdf.get_y()
        # Checkbox.
        pdf.set_draw_color(*INK_DIM)
        pdf.rect(M, y + 1.5, 4, 4)
        pdf.set_xy(M + 7, y)
        pdf.set_font(BODY, "", 10.5)
        pdf.set_text_color(*INK)
        pdf.multi_cell(CONTENT_W - 7, 5, it)
        pdf.ln(1)


def _derive_checklist(report: dict) -> list[str]:
    cwe = (report.get("cwe") or "").upper()
    base = [
        "Confirm the finding by reproducing the steps in section 3.1 in a non-production environment.",
        "Apply the fix described in the remediation section above.",
        "Add a regression test that fails without the fix and passes with it.",
        "Search the codebase for similar patterns and apply the fix everywhere it occurs.",
        "Review related code paths for other variants of the same class of bug.",
        "If the vulnerability was reachable in production, rotate any credentials, tokens, or session keys that may have been exposed.",
        "Deploy the fix to staging, run integration tests, then promote to production.",
        "Document the incident: who found it, when it was fixed, and what changed.",
    ]
    cwe_specific = {
        "CWE-78":  "Refactor every shell call to use subprocess with shell=False and a list of arguments.",
        "CWE-89":  "Audit every SQL string concatenation; replace with parameterised queries / ORM bindings.",
        "CWE-79":  "Audit all places that render user input; ensure your templating engine escapes by default.",
        "CWE-502": "Replace pickle / yaml.load with safe loaders (json, yaml.safe_load) on every untrusted input boundary.",
        "CWE-22":  "Centralise path handling in one helper that normalises and rejects paths escaping the base directory.",
        "CWE-94":  "Eliminate dynamic eval/exec; if absolutely required, restrict to a vetted DSL with a whitelist.",
        "CWE-327": "Audit all uses of MD5/SHA1; switch to SHA-256+ for hashing and bcrypt/argon2 for passwords.",
        "CWE-330": "Replace insecure RNGs with secrets.token_bytes / crypto.randomBytes for security-sensitive use.",
        "CWE-798": "Move secrets to a secret manager and add pre-commit hooks (e.g. gitleaks) to block reintroduction.",
        "CWE-918": "Add an outbound URL allowlist; reject requests to private/loopback ranges from user input.",
        "CWE-352": "Add CSRF tokens to every state-changing endpoint and verify them server-side.",
    }
    if cwe in cwe_specific:
        base.insert(1, cwe_specific[cwe])
    return base


# ---------- REFERENCES + GLOSSARY ----------
def _references_and_glossary(pdf: _Doc, *, report: dict) -> None:
    pdf.add_page()
    _section_title(pdf, "7.  References")
    refs = report.get("references") or []
    cwe = (report.get("cwe") or "").upper()
    if cwe and not any(cwe in (r or "") for r in refs):
        refs.append(f"https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html")
    if not refs:
        _muted(pdf, "No references supplied.")
    else:
        pdf.set_font(BODY, "", 10.5)
        pdf.set_text_color(*INK)
        for r in refs:
            pdf.set_x(M)
            pdf.cell(4, 5, "-")
            pdf.set_x(M + 5)
            pdf.set_text_color(*ACCENT)
            pdf.multi_cell(CONTENT_W - 5, 5, str(r))
            pdf.set_text_color(*INK)

    pdf.ln(4)
    _section_title(pdf, "8.  Glossary")
    glossary = [
        ("CWE",            "Common Weakness Enumeration. A community-maintained taxonomy of software weakness types (cwe.mitre.org)."),
        ("CVSS",           "Common Vulnerability Scoring System. Industry-standard 0.0-10.0 severity score."),
        ("PoC",            "Proof of Concept. A small script or input that demonstrates the vulnerability is real."),
        ("HITL gate",      "Human-in-the-loop checkpoint. The pipeline pauses for explicit human approval before potentially intrusive stages."),
        ("Sandbox",        "An isolated container with no network and read-only filesystem in which the PoC is executed safely."),
        ("Audit chain",    "An append-only JSONL log where each entry includes a SHA-256 hash of the previous entry, making tampering detectable."),
    ]
    for term, defn in glossary:
        pdf.set_x(M)
        pdf.set_font(BODY, "B", 10.5)
        pdf.set_text_color(*INK)
        pdf.cell(28, 5, term)
        pdf.set_font(BODY, "", 10)
        pdf.set_text_color(*INK)
        x = pdf.get_x()
        y = pdf.get_y()
        pdf.set_xy(x, y)
        pdf.multi_cell(CONTENT_W - 28, 5, defn)
        pdf.ln(0.5)


# ---------- helpers ----------
def _section_title(pdf: _Doc, text: str) -> None:
    pdf.set_x(M)
    pdf.set_font(BODY, "B", 16)
    pdf.set_text_color(*INK)
    pdf.cell(0, 8, text, ln=1)
    y = pdf.get_y()
    pdf.set_draw_color(*ACCENT)
    pdf.set_line_width(0.6)
    pdf.line(M, y, M + 18, y)
    pdf.set_line_width(0.2)
    pdf.ln(3)


def _subsection_title(pdf: _Doc, text: str) -> None:
    pdf.set_x(M)
    pdf.set_font(BODY, "B", 12)
    pdf.set_text_color(*INK)
    pdf.cell(0, 6, text, ln=1)
    pdf.ln(1)


def _muted(pdf: _Doc, text: str) -> None:
    pdf.set_font(BODY, "I", 9.5)
    pdf.set_text_color(*INK_DIM)
    _multi(pdf, text, h=4.5, w=CONTENT_W)


def _multi(pdf: _Doc, text: str, *, h: float, w: float) -> None:
    pdf.set_x(M)
    safe = _latin(text)
    pdf.multi_cell(w, h, safe)


def _kv_block(pdf: _Doc, rows: list[tuple[str, str]]) -> None:
    for k, v in rows:
        pdf.set_x(M)
        pdf.set_font(ACCENT_FONT, "B", 8.5)
        pdf.set_text_color(*INK_DIM)
        pdf.cell(28, 6, k.upper())
        pdf.set_font(BODY, "", 10.5)
        pdf.set_text_color(*INK)
        pdf.multi_cell(CONTENT_W - 28, 6, _latin(str(v)))


def _numbered_list(pdf: _Doc, items: list[str]) -> None:
    pdf.set_font(BODY, "", 10.5)
    pdf.set_text_color(*INK)
    for i, it in enumerate(items, 1):
        pdf.set_x(M)
        pdf.cell(8, 5.5, f"{i}.", align="L")
        x = pdf.get_x()
        y = pdf.get_y()
        pdf.set_xy(x, y)
        pdf.multi_cell(CONTENT_W - 8, 5.5, _latin(it))
        pdf.ln(0.5)


def _code_block(pdf: _Doc, text: str) -> None:
    pdf.ln(1)
    y = pdf.get_y()
    pdf.set_fill_color(248, 248, 250)
    pdf.set_draw_color(*RULE)
    # Estimate height for the box: monospace 9pt at line height 4 gives ~4mm/line.
    lines = max(1, len(text.splitlines()) + 1)
    h = min(120, lines * 4 + 4)
    pdf.rect(M, y, CONTENT_W, h, "FD")
    pdf.set_xy(M + 3, y + 2)
    pdf.set_font("Courier", "", 9)
    pdf.set_text_color(*INK)
    pdf.multi_cell(CONTENT_W - 6, 4, _latin(text))
    pdf.set_y(y + h + 2)


def _callout_box(pdf: _Doc, text: str, *, color: tuple[int, int, int]) -> None:
    pdf.ln(1)
    y = pdf.get_y()
    pdf.set_fill_color(*color)
    pdf.rect(M, y, 2, 30, "F")  # left stripe; height fixed-ish
    pdf.set_xy(M + 5, y)
    pdf.set_font(BODY, "", 11)
    pdf.set_text_color(*INK)
    safe = _latin(text)
    pdf.multi_cell(CONTENT_W - 5, 5.5, safe)
    pdf.ln(2)


def _mini_cards(pdf: _Doc, cards: list[tuple[str, str, tuple[int, int, int]]]) -> None:
    n = len(cards)
    gap = 4
    cw = (CONTENT_W - gap * (n - 1)) / n
    y = pdf.get_y()
    for i, (label, value, color) in enumerate(cards):
        x = M + i * (cw + gap)
        pdf.set_fill_color(*SOFT_BG)
        pdf.rect(x, y, cw, 18, "F")
        pdf.set_fill_color(*color)
        pdf.rect(x, y, cw, 1.5, "F")  # top stripe
        pdf.set_xy(x, y + 3)
        pdf.set_font(ACCENT_FONT, "B", 8)
        pdf.set_text_color(*INK_DIM)
        pdf.cell(cw, 4, label.upper(), align="C")
        pdf.set_xy(x, y + 8)
        pdf.set_font(BODY, "B", 13)
        pdf.set_text_color(*color)
        pdf.cell(cw, 7, value, align="C")
    pdf.set_y(y + 22)


def _markdown_block(pdf: _Doc, md_text: str) -> None:
    """Used only by render_markdown_to_pdf fallback."""
    in_code = False
    code_buf: list[str] = []
    for line in md_text.splitlines():
        if line.lstrip().startswith("```"):
            if in_code:
                _code_block(pdf, "\n".join(code_buf))
                code_buf = []
                in_code = False
            else:
                in_code = True
            continue
        if in_code:
            code_buf.append(line)
            continue
        if not line.strip():
            pdf.ln(2)
            continue
        m = re.match(r"^(#{1,4})\s+(.*)$", line)
        if m:
            level = len(m.group(1))
            sizes = {1: 18, 2: 14, 3: 12, 4: 11}
            pdf.set_x(M)
            pdf.set_font(BODY, "B", sizes[level])
            pdf.set_text_color(*INK)
            pdf.multi_cell(CONTENT_W, sizes[level] * 0.6, _latin(_strip_inline(m.group(2))))
            pdf.ln(1)
            continue
        if re.match(r"^\s*[-*]\s+", line):
            pdf.set_x(M)
            pdf.set_font(BODY, "", 10.5)
            pdf.set_text_color(*INK)
            pdf.multi_cell(CONTENT_W, 5, "  -  " + _latin(_strip_inline(re.sub(r"^\s*[-*]\s+", "", line))))
            continue
        pdf.set_x(M)
        pdf.set_font(BODY, "", 10.5)
        pdf.set_text_color(*INK)
        pdf.multi_cell(CONTENT_W, 5, _latin(_strip_inline(line)))
    if in_code and code_buf:
        _code_block(pdf, "\n".join(code_buf))


def _strip_inline(text: str) -> str:
    text = re.sub(r"\*\*(.+?)\*\*", r"\1", text)
    text = re.sub(r"\*(.+?)\*", r"\1", text)
    text = re.sub(r"`([^`]+)`", r"\1", text)
    return text


def _latin(text: str) -> str:
    """fpdf2 core fonts are Latin-1; replace anything that doesn't fit."""
    if text is None:
        return ""
    return str(text).encode("latin-1", errors="replace").decode("latin-1")


_CWE_NAMES = {
    "CWE-78":  "OS Command Injection",
    "CWE-79":  "Cross-site Scripting (XSS)",
    "CWE-89":  "SQL Injection",
    "CWE-22":  "Path Traversal",
    "CWE-94":  "Code Injection",
    "CWE-327": "Use of Broken or Risky Cryptography",
    "CWE-330": "Use of Insufficiently Random Values",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-502": "Deserialisation of Untrusted Data",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
}


def _cwe_name(cwe: str) -> str:
    return _CWE_NAMES.get((cwe or "").upper(), "Software Weakness")


def _derive_eli5(report: dict) -> str:
    """Fallback ELI5 if the report didn't include one."""
    sev = (report.get("severity") or "unknown").lower()
    impact = (report.get("impact") or "").strip()
    title = report.get("title", "this issue")
    head = {
        "critical": "This is the most serious kind of bug.",
        "high":     "This is a serious bug that needs prompt attention.",
        "medium":   "This is a notable bug worth fixing soon.",
        "low":      "This is a minor issue but still worth fixing.",
    }.get(sev, "")
    if impact:
        return f"{head} In short: {impact[:300]}"
    return f"{head} See section 3 for details on '{title}'."
