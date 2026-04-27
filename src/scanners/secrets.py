"""Regex-based secrets scanner.

Looks for common high-confidence secret formats (AWS keys, GitHub tokens,
private keys, Slack tokens, generic API key assignments). Each hit includes
file path, line number, snippet, and a confidence label.

Designed to be cheap and deterministic — no LLM calls. False positives are
possible; the Analyst sees the report and can de-prioritise noise.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path

# Pattern shape:
#   id           — short stable label
#   pattern      — compiled regex; first capture group (if any) is the secret
#   description  — human-readable label
#   confidence   — high | medium | low
_PATTERNS: list[tuple[str, re.Pattern[str], str, str]] = [
    ("aws-access-key-id", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
     "AWS Access Key ID", "high"),
    ("aws-secret-access-key", re.compile(
        r"(?i)aws.{0,20}(secret|sk).{0,5}[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
     "AWS Secret Access Key", "high"),
    ("github-pat", re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
     "GitHub Personal Access Token", "high"),
    ("github-oauth", re.compile(r"\bgho_[A-Za-z0-9]{36}\b"),
     "GitHub OAuth Token", "high"),
    ("github-app", re.compile(r"\b(ghu|ghs)_[A-Za-z0-9]{36}\b"),
     "GitHub App Token", "high"),
    ("slack-bot-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
     "Slack Token", "high"),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
     "Google API Key", "high"),
    ("stripe-live", re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b"),
     "Stripe Live Secret Key", "high"),
    ("stripe-test", re.compile(r"\bsk_test_[0-9A-Za-z]{24,}\b"),
     "Stripe Test Secret Key", "medium"),
    ("private-key-block", re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----"),
     "Private key file content", "high"),
    ("jwt", re.compile(r"\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
     "JWT token", "medium"),
    # Generic high-entropy assignments. Capture group 1 is the value.
    ("generic-api-key", re.compile(
        r"(?i)\b(?:api[_-]?key|secret|token|passwd|password)\s*[:=]\s*['\"]([A-Za-z0-9/_+\-]{24,})['\"]"),
     "Generic API key / secret assignment", "medium"),
    # .env-style assignment: KEY=value (uppercase only, no spaces).
    ("env-file-secret", re.compile(
        r"(?m)^([A-Z][A-Z0-9_]{2,})\s*=\s*['\"]?([^\s'\"#]{16,})['\"]?\s*$"),
     ".env-style secret assignment", "low"),
]

_SKIP_DIRS = {".git", "node_modules", "__pycache__", "dist", "build",
              ".venv", "venv", "vendor", "target", ".next"}
_SKIP_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf", ".zip",
              ".tar", ".gz", ".woff", ".woff2", ".ttf", ".eot", ".ico",
              ".mp4", ".webm", ".lock"}
_MAX_FILE_BYTES = 1_000_000  # skip very large files
_MAX_HITS = 200


@dataclass
class SecretHit:
    id: str
    description: str
    confidence: str
    file: str
    line: int
    snippet: str


def scan_secrets(root: Path) -> list[SecretHit]:
    hits: list[SecretHit] = []
    for path in root.rglob("*"):
        if len(hits) >= _MAX_HITS:
            break
        if not path.is_file():
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in _SKIP_EXTS:
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
            text = path.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue

        rel = str(path.relative_to(root))
        # .env files: drop env-file-secret confidence to "high" because the
        # file's purpose is to hold secrets — anything inside is suspicious.
        is_env = path.name in {".env", ".env.local", ".env.production"} \
            or path.name.startswith(".env.")

        for pid, regex, desc, base_conf in _PATTERNS:
            for m in regex.finditer(text):
                line_no = text.count("\n", 0, m.start()) + 1
                snippet = _redact(text.splitlines()[line_no - 1] if line_no <= len(text.splitlines()) else "")
                conf = "high" if (is_env and pid == "env-file-secret") else base_conf
                hits.append(SecretHit(
                    id=pid, description=desc, confidence=conf,
                    file=rel, line=line_no, snippet=snippet[:200],
                ))
                if len(hits) >= _MAX_HITS:
                    break
            if len(hits) >= _MAX_HITS:
                break
    return hits


def _redact(line: str) -> str:
    """Show the line but mask the middle of long base64-ish runs so secrets
    don't leak into reports verbatim."""
    def _mask(m: re.Match) -> str:
        s = m.group(0)
        return s[:4] + "…" + s[-4:] if len(s) > 16 else s
    return re.sub(r"[A-Za-z0-9/_+\-]{20,}", _mask, line).strip()


def to_artifact(hits: list[SecretHit]) -> dict:
    by_conf = {"high": 0, "medium": 0, "low": 0}
    for h in hits:
        by_conf[h.confidence] = by_conf.get(h.confidence, 0) + 1
    return {
        "total": len(hits),
        "by_confidence": by_conf,
        "hits": [asdict(h) for h in hits],
    }
