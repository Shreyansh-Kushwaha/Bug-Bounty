"""HTML sanitization and repo-host allowlisting.

Kept free of FastAPI imports so it can be unit-tested without web deps.
"""

from __future__ import annotations

import re
from html import escape
from html.parser import HTMLParser
from urllib.parse import urlparse

# Report markdown is rendered from LLM output derived from attacker-influenceable
# repo content, so the resulting HTML must be sanitized before the SPA injects it
# via dangerouslySetInnerHTML. Allowlist of safe tags/attributes; everything else
# (script, style, event handlers, javascript: URLs) is dropped.
ALLOWED_TAGS = {
    "a", "abbr", "b", "blockquote", "br", "code", "del", "div", "em", "h1", "h2",
    "h3", "h4", "h5", "h6", "hr", "i", "img", "li", "ol", "p", "pre", "span",
    "strong", "sub", "sup", "table", "tbody", "td", "th", "thead", "tr", "ul",
}
ALLOWED_ATTRS = {"href", "title", "alt", "src", "class", "id", "colspan", "rowspan"}
_VOID = {"br", "hr", "img"}
# Reject javascript:/data:/vbscript: URLs; allow http(s), mailto, anchors, relative.
_SAFE_URL = re.compile(r"^(https?:|mailto:|#|/|\.\/|[^:]+$)", re.IGNORECASE)

ALLOWED_HOSTS = {
    "github.com", "www.github.com", "gitlab.com", "bitbucket.org", "codeberg.org",
}


class _San(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip_depth += 1
            return
        if self._skip_depth or tag not in ALLOWED_TAGS:
            return
        safe = []
        for k, v in attrs:
            kl = k.lower()
            if kl not in ALLOWED_ATTRS:
                continue
            if kl in ("href", "src") and not _SAFE_URL.match((v or "").strip()):
                continue
            safe.append(f' {k}="{escape(v or "", quote=True)}"')
        self.out.append(f"<{tag}{''.join(safe)}>")

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self._skip_depth = max(0, self._skip_depth - 1)
            return
        if self._skip_depth or tag not in ALLOWED_TAGS or tag in _VOID:
            return
        self.out.append(f"</{tag}>")

    def handle_data(self, data):
        if not self._skip_depth:
            self.out.append(escape(data))


def sanitize_html(html_text: str) -> str:
    p = _San()
    p.feed(html_text)
    return "".join(p.out)


def host_allowed(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return host in ALLOWED_HOSTS
