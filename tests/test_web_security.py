"""Security-layer tests: session tokens, HTML sanitization, host allowlist.

These import only stdlib-backed helpers (no FastAPI) so they run in CI.
"""

import importlib

from src.web import auth
from src.web.sanitize import host_allowed, sanitize_html


# --- Session token signing ------------------------------------------------

def test_token_round_trip_and_tamper():
    tok = auth.mint_token()
    assert auth.verify_token(tok) is True
    assert auth.verify_token(tok + "x") is False
    assert auth.verify_token("garbage") is False
    assert auth.verify_token(None) is False


def test_token_expiry():
    past = 1_000_000.0
    tok = auth.mint_token(now=past)
    # A token minted long ago is expired when checked "now".
    assert auth.verify_token(tok, now=past + 10 * 24 * 3600) is False


def test_password_check(monkeypatch):
    monkeypatch.setenv("LOGIN_PASSWORD", "s3cret")
    assert auth.auth_enabled() is True
    assert auth.check_password("s3cret") is True
    assert auth.check_password("wrong") is False
    monkeypatch.delenv("LOGIN_PASSWORD", raising=False)
    assert auth.auth_enabled() is False
    assert auth.check_password("anything") is False


# --- HTML sanitizer -------------------------------------------------------

def test_sanitizer_strips_scripts_and_handlers():
    dirty = '<p onclick="steal()">hi</p><script>alert(1)</script>'
    clean = sanitize_html(dirty)
    assert "<script" not in clean.lower()
    assert "onclick" not in clean.lower()
    assert "alert(1)" not in clean
    assert "hi" in clean


def test_sanitizer_blocks_javascript_urls():
    clean = sanitize_html('<a href="javascript:evil()">x</a>')
    assert "javascript:" not in clean.lower()
    clean_ok = sanitize_html('<a href="https://example.com">x</a>')
    assert 'href="https://example.com"' in clean_ok


def test_sanitizer_keeps_safe_markup():
    clean = sanitize_html("<h2>Title</h2><pre><code>x = 1</code></pre>")
    assert "<h2>Title</h2>" in clean
    assert "<code>x = 1</code>" in clean


# --- Host allowlist -------------------------------------------------------

def test_host_allowlist():
    assert host_allowed("https://github.com/a/b.git") is True
    assert host_allowed("https://gitlab.com/a/b") is True
    assert host_allowed("http://169.254.169.254/latest/meta-data") is False
    assert host_allowed("https://evil.example.com/x") is False
