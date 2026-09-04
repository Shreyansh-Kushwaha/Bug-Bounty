"""Dependency vulnerability scanner.

Tries CLI tools in order of preference:
  1. osv-scanner (multi-ecosystem, single binary)
  2. pip-audit   (Python only)
  3. npm audit   (Node only)

If none are installed, returns a structured "no scanner available" result so
the rest of the pipeline can carry on. Never raises.

We deliberately don't `pip install` the scanner at runtime — operators decide
whether to install it. This keeps the runtime trust boundary small.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

_TIMEOUT_SECS = 120


def scan_dependencies(root: Path) -> dict:
    out: dict = {
        "scanners_run": [],
        "scanners_unavailable": [],
        "vulnerabilities": [],
        "manifests_found": _list_manifests(root),
    }

    if shutil.which("osv-scanner"):
        out["scanners_run"].append("osv-scanner")
        out["vulnerabilities"].extend(_run_osv(root))
    else:
        out["scanners_unavailable"].append("osv-scanner")

    # Only run pip-audit if there's a Python manifest and the CLI exists.
    if any(m in out["manifests_found"] for m in ("requirements.txt", "pyproject.toml", "Pipfile")):
        if shutil.which("pip-audit"):
            out["scanners_run"].append("pip-audit")
            out["vulnerabilities"].extend(_run_pip_audit(root))
        else:
            out["scanners_unavailable"].append("pip-audit")

    if "package.json" in out["manifests_found"]:
        if shutil.which("npm"):
            out["scanners_run"].append("npm-audit")
            out["vulnerabilities"].extend(_run_npm_audit(root))
        else:
            out["scanners_unavailable"].append("npm-audit")

    out["total"] = len(out["vulnerabilities"])
    out["by_severity"] = _bucket(out["vulnerabilities"])
    return out


def _list_manifests(root: Path) -> list[str]:
    candidates = [
        "requirements.txt", "pyproject.toml", "Pipfile", "Pipfile.lock",
        "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
        "go.mod", "go.sum", "Cargo.toml", "Cargo.lock", "composer.json",
        "Gemfile", "Gemfile.lock",
    ]
    return [c for c in candidates if (root / c).exists()]


def _run(cmd: list[str], cwd: Path) -> tuple[int, str, str]:
    try:
        r = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True,
            timeout=_TIMEOUT_SECS, check=False,
        )
        return r.returncode, r.stdout, r.stderr
    except (subprocess.TimeoutExpired, OSError) as e:
        return -1, "", str(e)


def _run_osv(root: Path) -> list[dict]:
    rc, stdout, _ = _run(["osv-scanner", "--format", "json", str(root)], cwd=root)
    if rc not in (0, 1) or not stdout:
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    rows: list[dict] = []
    for result in data.get("results", []):
        source = result.get("source", {}).get("path", "")
        for pkg in result.get("packages", []):
            name = pkg.get("package", {}).get("name", "")
            version = pkg.get("package", {}).get("version", "")
            for vuln in pkg.get("vulnerabilities", []):
                sev = _osv_severity(vuln)
                rows.append({
                    "source": "osv-scanner",
                    "package": name,
                    "version": version,
                    "id": vuln.get("id", ""),
                    "summary": vuln.get("summary") or vuln.get("details", "")[:200],
                    "severity": sev,
                    "manifest": source,
                    "fixed_in": _osv_fixed(vuln),
                })
    return rows


def _osv_severity(vuln: dict) -> str:
    """Normalize an OSV vuln to a severity band: critical|high|medium|low|unknown.

    OSV's `severity[].score` is a CVSS *vector string* for CVSS types (not a
    number), so the old code returned that vector verbatim and every consumer
    treated it as 'unknown'. Prefer an explicit band from database_specific,
    otherwise derive one from the CVSS vector's computed base score.
    """
    db = vuln.get("database_specific") or {}
    band = _band_word(db.get("severity"))
    if band != "unknown":
        return band
    for s in vuln.get("severity", []) or []:
        band = _cvss_to_band(str(s.get("score", "")))
        if band != "unknown":
            return band
    return "unknown"


def _band_word(value) -> str:
    w = str(value or "").strip().lower()
    if w in ("critical", "high", "low"):
        return w
    if w in ("medium", "moderate"):
        return "medium"
    return "unknown"


def _score_to_band(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "unknown"


def _cvss_to_band(score: str) -> str:
    """Accept either a numeric base score ('9.8') or a CVSS v3.x vector string."""
    score = score.strip()
    if not score:
        return "unknown"
    try:
        return _score_to_band(float(score))
    except ValueError:
        pass
    if score.upper().startswith("CVSS:3"):
        base = _cvss3_base_score(score)
        if base is not None:
            return _score_to_band(base)
    return "unknown"


# CVSS v3.1 base-score metric weights.
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}


def _cvss3_base_score(vector: str) -> float | None:
    """Compute a CVSS v3.1 base score from a vector string. None if malformed."""
    try:
        parts = dict(
            p.split(":", 1) for p in vector.split("/") if ":" in p and not p.startswith("CVSS")
        )
        av, ac, ui = _AV[parts["AV"]], _AC[parts["AC"]], _UI[parts["UI"]]
        scope_changed = parts["S"] == "C"
        pr = (_PR_C if scope_changed else _PR_U)[parts["PR"]]
        c, i, a = _CIA[parts["C"]], _CIA[parts["I"]], _CIA[parts["A"]]
    except (KeyError, ValueError):
        return None

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    raw = (1.08 if scope_changed else 1.0) * (impact + exploitability)
    return _roundup(min(raw, 10.0))


def _roundup(x: float) -> float:
    """CVSS 'roundup': smallest 1-decimal number >= x."""
    import math

    return math.ceil(x * 10) / 10.0


def _osv_fixed(vuln: dict) -> str:
    for affected in vuln.get("affected", []) or []:
        for r in affected.get("ranges", []) or []:
            for ev in r.get("events", []) or []:
                if "fixed" in ev:
                    return str(ev["fixed"])
    return ""


def _run_pip_audit(root: Path) -> list[dict]:
    rc, stdout, _ = _run(["pip-audit", "-f", "json", "--strict"], cwd=root)
    if rc < 0 or not stdout:
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    rows = []
    # pip-audit returns either a list (older) or {"dependencies": [...]} (newer).
    deps = data if isinstance(data, list) else data.get("dependencies", [])
    for dep in deps:
        for v in dep.get("vulns", []) or []:
            rows.append({
                "source": "pip-audit",
                "package": dep.get("name", ""),
                "version": dep.get("version", ""),
                "id": v.get("id", ""),
                "summary": (v.get("description") or "")[:200],
                "severity": "unknown",
                "manifest": "requirements.txt/pyproject.toml",
                "fixed_in": ", ".join(v.get("fix_versions", []) or []),
            })
    return rows


def _run_npm_audit(root: Path) -> list[dict]:
    rc, stdout, _ = _run(["npm", "audit", "--json"], cwd=root)
    if rc < 0 or not stdout:
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    rows = []
    for name, adv in (data.get("vulnerabilities") or {}).items():
        # npm audit nests advisories under 'via'
        via = adv.get("via", [])
        first = next((v for v in via if isinstance(v, dict)), None)
        rows.append({
            "source": "npm-audit",
            "package": name,
            "version": adv.get("range", "") or adv.get("version", ""),
            "id": (first or {}).get("source") or (first or {}).get("url", ""),
            "summary": (first or {}).get("title", ""),
            "severity": adv.get("severity", "unknown"),
            "manifest": "package.json",
            "fixed_in": str(adv.get("fixAvailable", "")),
        })
    return rows


def _bucket(rows: list[dict]) -> dict:
    buckets = {"critical": 0, "high": 0, "moderate": 0, "medium": 0, "low": 0, "unknown": 0}
    for r in rows:
        sev = (r.get("severity") or "unknown").lower()
        if sev in buckets:
            buckets[sev] += 1
        else:
            buckets["unknown"] += 1
    return buckets
