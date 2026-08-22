"""Per-category security scoring.

Combines the deterministic scanner results (secrets, deps) with the LLM-driven
findings (Analyst hypotheses, Exploit validation) to produce per-category 0–100
scores and an overall letter grade.

Higher score = safer. The mapping is intentionally simple and stable so two
runs against the same code give the same score.
"""

from __future__ import annotations

from dataclasses import dataclass

# Severity weight: how much each finding penalises the score.
_SEV_WEIGHT = {
    "critical": 35,
    "high": 20,
    "medium": 10,
    "moderate": 10,
    "low": 4,
    "unknown": 6,
}


@dataclass
class CategoryScore:
    name: str
    score: int       # 0..100, higher is better
    issues: int
    detail: str


def grade(score: int) -> str:
    if score >= 90: return "A"
    if score >= 80: return "B"
    if score >= 65: return "C"
    if score >= 50: return "D"
    return "F"


def risk_band(score: int) -> str:
    if score >= 80: return "safe"
    if score >= 60: return "medium"
    return "high"


def _penalty(severity: str) -> int:
    return _SEV_WEIGHT.get((severity or "unknown").lower(), 6)


def _category_score(severities: list[str]) -> int:
    """100 minus capped sum of severity penalties. Floors at 0."""
    if not severities:
        return 100
    pen = sum(_penalty(s) for s in severities)
    return max(0, 100 - min(100, pen))


def compute_scores(
    *,
    secrets_artifact: dict | None,
    deps_artifact: dict | None,
    analyst_hypotheses: list[dict] | None,
    exploit_validated: bool | None = None,
) -> dict:
    cats: list[CategoryScore] = []

    # --- Secrets ---
    s_hits = (secrets_artifact or {}).get("hits", []) or []
    s_sev = []
    for h in s_hits:
        c = (h.get("confidence") or "low").lower()
        s_sev.append({"high": "high", "medium": "medium", "low": "low"}.get(c, "low"))
    cats.append(CategoryScore(
        name="secrets", score=_category_score(s_sev), issues=len(s_hits),
        detail=f"{len(s_hits)} potential secret(s) found",
    ))

    # --- Dependencies ---
    d_vulns = (deps_artifact or {}).get("vulnerabilities", []) or []
    d_sev = [v.get("severity", "unknown") for v in d_vulns]
    if not (deps_artifact or {}).get("scanners_run"):
        # No scanner ran — score is "unknown", report 50 (neutral).
        cats.append(CategoryScore(
            name="dependencies", score=50, issues=0,
            detail="No CVE scanner available (install osv-scanner or pip-audit).",
        ))
    else:
        cats.append(CategoryScore(
            name="dependencies", score=_category_score(d_sev),
            issues=len(d_vulns),
            detail=f"{len(d_vulns)} known vulnerable dependency version(s)",
        ))

    # --- Code (Analyst hypotheses) ---
    hyps = analyst_hypotheses or []
    h_sev = [h.get("severity", "low") for h in hyps]
    cats.append(CategoryScore(
        name="code", score=_category_score(h_sev), issues=len(hyps),
        detail=f"{len(hyps)} code-level vulnerability hypothesis/es",
    ))

    # --- Exploitability — derived from whether top hypothesis was validated. ---
    if exploit_validated is True:
        ex = CategoryScore(
            name="exploitability", score=20, issues=1,
            detail="Top hypothesis was validated by sandboxed PoC.",
        )
    elif exploit_validated is False:
        ex = CategoryScore(
            name="exploitability", score=85, issues=0,
            detail="Top hypothesis did not validate.",
        )
    else:
        ex = CategoryScore(
            name="exploitability", score=70, issues=0,
            detail="No PoC executed yet.",
        )
    cats.append(ex)

    overall = round(sum(c.score for c in cats) / len(cats))
    return {
        "overall": overall,
        "grade": grade(overall),
        "risk_band": risk_band(overall),
        "categories": [c.__dict__ for c in cats],
    }
