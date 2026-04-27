"""Prioritized fix roadmap.

Takes the Analyst's full hypothesis list (plus secrets and dependency findings)
and produces a single ordered list of fixes with effort estimates and one-line
recommendations. Generated deterministically — no extra LLM call.
"""

from __future__ import annotations

# Severity × exploitability priority. Higher = fix first.
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 1}
_EXP_RANK = {"high": 3, "medium": 2, "low": 1, "unknown": 1}

# CWE → effort & one-line fix template. Falls back to a generic line.
_CWE_FIX = {
    "CWE-502": ("medium", "Replace pickle/yaml.load() with safe loaders or signed payloads."),
    "CWE-78":  ("low",    "Pass arguments as a list to subprocess; never use shell=True with user input."),
    "CWE-79":  ("low",    "Escape output and use a templating engine; avoid innerHTML/dangerouslySetInnerHTML on user data."),
    "CWE-89":  ("low",    "Use parameterized queries / ORM bind parameters."),
    "CWE-352": ("medium", "Add CSRF tokens to state-changing endpoints."),
    "CWE-22":  ("low",    "Validate paths against a normalized base directory; reject '..'."),
    "CWE-94":  ("medium", "Eliminate dynamic eval/exec; if unavoidable, restrict to a vetted DSL."),
    "CWE-327": ("low",    "Replace md5/sha1 with sha256+; use bcrypt/argon2 for passwords."),
    "CWE-330": ("low",    "Use secrets.token_urlsafe / crypto.randomBytes for security-critical randomness."),
    "CWE-798": ("low",    "Move secrets out of source into env vars or a secret manager; rotate the leaked value."),
    "CWE-918": ("medium", "Validate URL host against an allowlist before making outbound requests."),
}


def build_roadmap(
    *,
    hypotheses: list[dict] | None,
    secrets_artifact: dict | None,
    deps_artifact: dict | None,
) -> dict:
    items: list[dict] = []

    for h in hypotheses or []:
        cwe = (h.get("cwe") or "").upper()
        effort, fix = _CWE_FIX.get(cwe, ("medium",
            "Validate input, narrow scope, and add a regression test."))
        items.append({
            "kind": "code",
            "id": h.get("id"),
            "title": h.get("title", ""),
            "file": h.get("file", ""),
            "line_range": h.get("line_range", ""),
            "cwe": cwe,
            "severity": h.get("severity", "low"),
            "exploitability": h.get("exploitability", "low"),
            "priority_score": _priority(h.get("severity"), h.get("exploitability")),
            "effort": effort,
            "fix_recommendation": fix,
        })

    # Secrets — high-confidence first.
    for s in (secrets_artifact or {}).get("hits", []) or []:
        conf = (s.get("confidence") or "low").lower()
        sev = {"high": "high", "medium": "medium", "low": "low"}[conf]
        items.append({
            "kind": "secret",
            "id": f"S-{s.get('id')}-{s.get('line')}",
            "title": f"{s.get('description')} in {s.get('file')}",
            "file": s.get("file", ""),
            "line_range": str(s.get("line", "")),
            "cwe": "CWE-798",
            "severity": sev,
            "exploitability": "high" if conf == "high" else "medium",
            "priority_score": _priority(sev, "high" if conf == "high" else "medium"),
            "effort": "low",
            "fix_recommendation": (
                "Remove the secret from the repo, rotate it at the provider, "
                "and load it from an environment variable or secret manager."
            ),
        })

    # Dependencies — one item per vulnerable package version.
    for v in (deps_artifact or {}).get("vulnerabilities", []) or []:
        sev = (v.get("severity") or "unknown").lower()
        normalized = {"moderate": "medium"}.get(sev, sev)
        if normalized not in _SEV_RANK:
            normalized = "medium"
        fixed = v.get("fixed_in") or "the latest patched version"
        items.append({
            "kind": "dependency",
            "id": f"D-{v.get('package')}-{v.get('id')}",
            "title": f"{v.get('package')} {v.get('version')} — {v.get('id')}",
            "file": v.get("manifest", ""),
            "line_range": "",
            "cwe": "",
            "severity": normalized,
            "exploitability": "medium",
            "priority_score": _priority(normalized, "medium"),
            "effort": "low",
            "fix_recommendation": (
                f"Upgrade {v.get('package')} to {fixed}. {v.get('summary', '')[:120]}"
            ).strip(),
        })

    items.sort(key=lambda x: x["priority_score"], reverse=True)
    for i, it in enumerate(items, 1):
        it["rank"] = i

    return {
        "total": len(items),
        "items": items,
    }


def _priority(severity: str | None, exploitability: str | None) -> int:
    s = _SEV_RANK.get((severity or "low").lower(), 1)
    e = _EXP_RANK.get((exploitability or "low").lower(), 1)
    return s * 10 + e
