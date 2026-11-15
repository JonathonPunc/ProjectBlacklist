"""Look at a borderline host's page: does it ask for a password or secret and
name the brand?

Only the HTML of the home page is read; nothing on it is run. Phishing kits
often hide from obvious bots, so the request looks like an ordinary browser.
That's standard practice for scanners, and the only sites that see it are
ones whose names already look like a brand's login page.
"""

from __future__ import annotations

import http.client
import re
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit

BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
MAX_PAGE = 400_000

_PASSWORD = re.compile(r"<input[^>]*type\s*=\s*[\"']?password", re.I)
_SECRET = re.compile(r"seed phrase|recovery phrase|secret recovery|private key|mnemonic|"
                     r"card ?number|\bcvv\b|\bcvc\b|security code|one[- ]time (?:pass)?code|"
                     r"verification code|social security", re.I)
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_TAGS = re.compile(r"<script.*?</script>|<style.*?</style>|<[^>]+>", re.I | re.S)


@dataclass(frozen=True)
class Page:
    final_host: str      # where redirects ended up
    html: str            # empty if the server answered with an error


PageGetter = Callable[[str], "Page | None"]


def fetch_page(host: str, *, timeout: float = 8) -> Page | None:
    """GET https://host/. None if it can't be reached at all."""
    req = urllib.request.Request(f"https://{host}/", headers={
        "User-Agent": BROWSER_UA, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            final = urlsplit(resp.geturl()).hostname or host
            ctype = resp.headers.get("Content-Type", "")
            if ctype and "html" not in ctype.lower():
                return Page(final, "")
            data = resp.read(MAX_PAGE)
            charset = resp.headers.get_content_charset() or "utf-8"
    except urllib.error.HTTPError as exc:
        return Page(urlsplit(exc.geturl() or "").hostname or host, "")
    except (urllib.error.URLError, http.client.HTTPException, TimeoutError, OSError, ValueError):
        return None
    try:
        return Page(final, data.decode(charset, "replace"))
    except LookupError:
        return Page(final, data.decode("utf-8", "replace"))


def verdict(page: Page, terms: Iterable[str], owned: Callable[[str], bool]) -> tuple[str, str]:
    """("phish" | "brand-site" | "none", why)."""
    if owned(page.final_host):
        return "brand-site", f"redirects to {page.final_host}"
    if not page.html:
        return "none", ""
    title = " ".join(_TITLE.findall(page.html)).lower()
    text = _TAGS.sub(" ", page.html).lower()
    named = next((t for t in terms if t and (t in title or t in text)), "")
    asks = "a password" if _PASSWORD.search(page.html) else ""
    if not asks:
        m = _SECRET.search(text)
        asks = f"\"{m.group().lower()}\"" if m else ""
    if named and asks:
        return "phish", f"page asks for {asks} and names {named}"
    return "none", ""
