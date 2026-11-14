"""Writing the lists in each blocker's format, and reading them back to verify.

Two kinds of format:
* wildcard formats block a host and everything under it (abp, dnsmasq,
  unbound, rpz). A host whose parent is also listed is redundant there, so
  those files are minimised.
* exact formats block only the names listed (domains, hosts). Pi-hole treats
  plain lines this way, so they keep every host.
"""

from __future__ import annotations

import re

from .hosts import ancestors, sort_key

FILES = {
    "abp": "abp.txt",
    "domains": "domains.txt",
    "hosts": "hosts.txt",
    "dnsmasq": "dnsmasq.conf",
    "unbound": "unbound.conf",
    "rpz": "rpz.zone",
}
WILDCARD = frozenset({"abp", "dnsmasq", "unbound", "rpz"})
COMMENT = {"abp": "!", "domains": "#", "hosts": "#", "dnsmasq": "#", "unbound": "#", "rpz": ";"}
SYNTAX = {
    "abp": "Adblock (Pi-hole v6, AdGuard Home, uBlock Origin); blocks subdomains too",
    "domains": "one domain per line; exact match only",
    "hosts": "hosts file; exact match only",
    "dnsmasq": "dnsmasq local=/domain/; blocks subdomains too",
    "unbound": "Unbound local-zone always_nxdomain; blocks subdomains too",
    "rpz": "DNS Response Policy Zone (BIND, Knot, PowerDNS, Unbound); blocks subdomains too",
}


def minimise(hosts: set[str]) -> set[str]:
    """Drop hosts already covered by a listed parent."""
    return {h for h in hosts if not any(p in hosts for p in ancestors(h))}


def prepare(hosts: set[str]) -> dict[str, list[str]]:
    """Sorted names for each kind of format, computed once per build."""
    return {"wildcard": sorted(minimise(hosts), key=sort_key), "exact": sorted(hosts, key=sort_key)}


def render(fmt: str, hosts: set[str] | dict[str, list[str]], header: list[str], serial: int) -> str:
    """Render a list. Pass prepare()'s result instead of a set to avoid re-sorting."""
    prepared = hosts if isinstance(hosts, dict) else prepare(hosts)
    names = prepared["wildcard" if fmt in WILDCARD else "exact"]
    c = COMMENT[fmt]
    head = [f"{c} {line}".rstrip() for line in header]
    head.append(f"{c} Syntax: {SYNTAX[fmt]}")
    head.append(f"{c} Entries: {len(names)}")
    if fmt == "abp":
        lines = ["[Adblock Plus]", *head, *(f"||{h}^" for h in names)]
    elif fmt == "domains":
        lines = [*head, *names]
    elif fmt == "hosts":
        lines = [*head, *(f"0.0.0.0 {h}" for h in names)]
    elif fmt == "dnsmasq":
        lines = [*head, *(f"local=/{h}/" for h in names)]
    elif fmt == "unbound":
        lines = [*head, "server:", *(f'local-zone: "{h}." always_nxdomain' for h in names)]
    elif fmt == "rpz":
        lines = ["$TTL 300",
                 f"@ IN SOA localhost. hostmaster.localhost. {serial} 3600 600 604800 300",
                 "@ IN NS localhost.", *head]
        for h in names:
            lines += [f"{h} CNAME .", f"*.{h} CNAME ."]
    else:
        raise ValueError(f"unknown output format {fmt!r}")
    return "\n".join(lines) + "\n"


_DNSMASQ = re.compile(r"^local=/([^/]+)/$")
_UNBOUND = re.compile(r'^local-zone:\s*"([^"]+)\."\s+always_nxdomain$')
_RPZ = re.compile(r"^(\*\.)?(\S+)\s+CNAME\s+\.$")


def read_back(fmt: str, text: str) -> set[str]:
    """Read one of our own files back into the set of names it lists.

    Only for files we wrote (names are already valid), so this is plain string
    handling. Feeds from elsewhere go through pipeline.parse instead.
    """
    lines = text.splitlines()
    if fmt == "abp":
        return {ln[2:-1] for ln in lines if ln.startswith("||") and ln.endswith("^")}
    if fmt == "domains":
        return {ln.strip() for ln in lines if ln.strip() and not ln.startswith("#")}
    if fmt == "hosts":
        return {ln[8:].strip() for ln in lines if ln.startswith("0.0.0.0 ")}
    pattern = {"dnsmasq": _DNSMASQ, "unbound": _UNBOUND, "rpz": _RPZ}[fmt]
    out: set[str] = set()
    for line in lines:
        m = pattern.match(line.strip())
        if m:
            out.add(m.group(m.lastindex or 1))
    return out


def blocks(fmt: str, listed: set[str], name: str) -> bool:
    """Would a file listing `listed` in format fmt block `name`?"""
    if name in listed:
        return True
    return fmt in WILDCARD and any(p in listed for p in ancestors(name))
