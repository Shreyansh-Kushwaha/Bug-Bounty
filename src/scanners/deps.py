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
    for s in vuln.get("severity", []) or []:
        score = s.get("score", "")
        if score:
            return score
    db = vuln.get("database_specific") or {}
    return str(db.get("severity") or "unknown")


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
