"""Host names: normalising feed entries, and the Public Suffix List.

Everything downstream works on lowercase ASCII (punycode) host names with at
least two labels. IP addresses are rejected: DNS blocklists can't block them.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

_LABEL = r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?"
_HOST = re.compile(rf"^(?:{_LABEL}\.)+{_LABEL}$")


def classify(token: str) -> tuple[str | None, str]:
    """Return (host, kind) for a bare name, URL or host:port.

    kind is "ok" with a normalised host, "ip" for IP addresses, or "invalid".
    """
    s = token.strip()
    if not s:
        return None, "invalid"
    if "://" in s or any(c in s for c in "/?#@"):
        try:
            host = urlsplit(s if "://" in s else "http://" + s).hostname
        except ValueError:
            return None, "invalid"
        if not host:
            return None, "invalid"
        s = host
    elif s.count(":") == 1:  # host:port; more colons would be IPv6
        s = s.split(":", 1)[0]
    s = s.strip().strip("[]").rstrip(".").lower()
    if s[:1].isdigit() or ":" in s:  # only these can be IP addresses
        try:
            ipaddress.ip_address(s)
            return None, "ip"
        except ValueError:
            pass
    if not s or s.startswith("."):
        return None, "invalid"
    if not s.isascii():
        try:
            s = s.encode("idna").decode("ascii")
        except UnicodeError:
            return None, "invalid"
    if len(s) > 253 or not _HOST.match(s) or s.rpartition(".")[2].isdigit():
        return None, "invalid"
    return s, "ok"


def normalize(token: str) -> str | None:
    """The normalised host for a token, or None if it isn't a usable DNS name."""
    return classify(token)[0]


def ancestors(host: str) -> list[str]:
    """Proper parent names with at least two labels: a.b.example.com -> [b.example.com, example.com]."""
    labels = host.split(".")
    return [".".join(labels[i:]) for i in range(1, len(labels) - 1)]


def sort_key(host: str) -> tuple[str, ...]:
    """Sort by reversed labels so a domain's hosts sit together (and compress well)."""
    return tuple(reversed(host.split(".")))


def _ascii_rule(rule: str) -> str:
    prefix = ""
    for p in ("!", "*."):
        if rule.startswith(p):
            prefix, rule = p, rule[len(p):]
    if not rule.isascii():
        rule = rule.encode("idna").decode("ascii")
    return prefix + rule


class PublicSuffixList:
    """The Public Suffix List, keeping its ICANN and PRIVATE sections apart.

    PRIVATE entries are services that hand out subdomains to their users
    (pages.dev, github.io, blogspot.com, ...). A host under one of those
    belongs to whoever registered that subdomain, not to the platform, so the
    platform itself must never be blocked.
    """

    def __init__(self, text: str) -> None:
        self._rules: dict[str, bool] = {}  # rule -> is_private
        self._wild: dict[str, bool] = {}   # "x.y" for a "*.x.y" rule
        self._exc: dict[str, bool] = {}    # "a.x.y" for a "!a.x.y" rule
        private = False
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("//"):
                if "===BEGIN PRIVATE DOMAINS===" in line:
                    private = True
                elif "===BEGIN ICANN DOMAINS===" in line:
                    private = False
                continue
            if not line:
                continue
            try:
                rule = _ascii_rule(line.split()[0].lower())
            except UnicodeError:
                continue
            if rule.startswith("!"):
                self._exc[rule[1:]] = private
            elif rule.startswith("*."):
                self._wild[rule[2:]] = private
            else:
                self._rules[rule] = private
        if not self._rules:
            raise ValueError("public suffix list is empty or unreadable")

    def __len__(self) -> int:
        return len(self._rules) + len(self._wild) + len(self._exc)

    @staticmethod
    def _hit(table: dict[str, bool], key: str, private: bool) -> bool:
        flag = table.get(key)
        return flag is not None and (private or not flag)

    def suffixes(self, host: str) -> tuple[str, str]:
        """(longest public suffix, longest ICANN-only public suffix), in one walk."""
        labels = host.split(".")
        found: list[str | None] = [None, None]  # [with PRIVATE section, ICANN only]
        for i in range(len(labels)):
            cand = ".".join(labels[i:])
            parent = ".".join(labels[i + 1:])
            for slot, private in ((0, True), (1, False)):
                if found[slot] is not None:
                    continue
                if self._hit(self._exc, cand, private):
                    found[slot] = parent
                elif self._hit(self._rules, cand, private) or (parent and self._hit(self._wild, parent, private)):
                    found[slot] = cand
            if found[0] is not None and found[1] is not None:
                break
        return found[0] or labels[-1], found[1] or labels[-1]

    def public_suffix(self, host: str, *, private: bool = True) -> str:
        """Longest matching public suffix; private=False ignores the PRIVATE section."""
        return self.suffixes(host)[0 if private else 1]

    @staticmethod
    def owner(host: str, suffix: str) -> str | None:
        """The suffix plus one label of host, or None if host is the suffix itself."""
        if host == suffix:
            return None
        n = suffix.count(".") + 2
        return ".".join(host.split(".")[-n:])

    def registrable(self, host: str, *, private: bool = True) -> str | None:
        """The suffix plus one label (the part someone owns), or None if host is a suffix."""
        return self.owner(host, self.public_suffix(host, private=private))

    def is_public_suffix(self, host: str) -> bool:
        return self.public_suffix(host, private=True) == host

    def is_shared(self, host: str) -> bool:
        """True when host sits under a PRIVATE-section platform (pages.dev and the like)."""
        priv, icann = self.suffixes(host)
        return self.owner(host, priv) != self.owner(host, icann)
