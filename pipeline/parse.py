"""Turning a feed's text into a set of host names."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .hosts import classify

FORMATS = ("urls", "domains", "abp", "hosts")
_ABP = re.compile(r"^\|\|([^\^/$|*]+)\^(\$.*)?$")
_SINKHOLES = {"0.0.0.0", "127.0.0.1", "::", "::1"}


@dataclass
class Parsed:
    entries: set[str] = field(default_factory=set)
    lines: int = 0      # lines that should have held an entry
    rejected: int = 0   # ...but didn't parse
    skipped: int = 0    # IPs, ABP exception rules and rules with modifiers

    @property
    def junk_ratio(self) -> float:
        return self.rejected / self.lines if self.lines else 0.0


def parse(text: str, fmt: str) -> Parsed:
    if fmt not in FORMATS:
        raise ValueError(f"unknown feed format {fmt!r}")
    out = Parsed()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#!;[" or line.startswith("//"):
            continue
        if fmt == "abp":
            if line.startswith("@@"):
                out.skipped += 1          # allow rules are the list's business
                continue
            out.lines += 1
            m = _ABP.match(line)
            if not m:
                out.rejected += 1
                continue
            if m.group(2):
                out.skipped += 1          # $modifiers have no DNS meaning
                continue
            tokens = [m.group(1)]
        elif fmt == "hosts":
            parts = line.split("#", 1)[0].split()
            if not parts:
                continue
            out.lines += 1
            if len(parts) < 2 or parts[0] not in _SINKHOLES:
                out.rejected += 1
                continue
            tokens = parts[1:]
        else:  # domains, urls: first token per line; anything after is a comment
            out.lines += 1
            tokens = [line.split()[0]]
        for token in tokens:
            host, kind = classify(token)
            if host:
                out.entries.add(host)
            elif kind == "ip":
                out.skipped += 1
            else:
                out.rejected += 1
    return out
