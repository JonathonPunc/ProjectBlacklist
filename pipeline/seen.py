"""A memory of the domains we have seen certificates for.

The early-warning detector reads every Let's Encrypt certificate. Remembering
each registrable domain (pages.dev tenants count as their own domain) tells us
when one turns up for the first time, which usually means it is new. That is
used only to decide which borderline names get their page checked first; it
never flags anything by itself.

Real sites renew their certificates at least every ~60 days, so once the
memory covers that long, an established domain will have been seen. Until
then everything looks new, which leaves the page-check order as it was.

The memory is two Bloom filters (generations). A domain counts as seen if
either holds it; new domains go into the current one. When the current one is
ROTATE_AFTER old, the other is cleared and becomes current, so the memory
always reaches back between one and two ROTATE_AFTER periods and slowly
forgets domains that stopped renewing (a dropped domain re-registered later
looks new again).

It lives in a private directory (the Actions cache in CI), never on the dist
branch: it is ours to use, not to publish.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
from collections.abc import Iterable
from pathlib import Path

BITS = 1 << 30                      # per generation: 128 MiB, ~3% false "seen" at 150M domains
HASHES = 5
ROTATE_AFTER = dt.timedelta(days=60)
WARM_AFTER = dt.timedelta(days=60)  # until then, "new" mostly means "new to us"


def _iso(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(s: str) -> dt.datetime:
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


class SeenDomains:
    def __init__(self, path: Path, now: dt.datetime, *, bits: int = BITS) -> None:
        self.path, self.now, self.bits = path, now, bits
        meta_file = path / "meta.json"
        meta = json.loads(meta_file.read_text(encoding="utf-8")) if meta_file.is_file() else {}
        if meta.get("bits") != bits:
            meta = {}                                 # new, or resized: start over
        self.since = meta.get("since", _iso(now))    # when the memory first started
        self.current = meta.get("current", "a")
        self.started = meta.get("started", {"a": _iso(now), "b": None})
        self.gens = {g: self._load(g) if meta else bytearray(bits // 8) for g in ("a", "b")}
        self.rotated = False
        if now - _parse(self.started[self.current]) >= ROTATE_AFTER:
            self.current = "b" if self.current == "a" else "a"
            self.gens[self.current] = bytearray(bits // 8)
            self.started[self.current] = _iso(now)
            self.rotated = True

    def _load(self, g: str) -> bytearray:
        f = self.path / f"gen-{g}.bin"
        data = bytearray(f.read_bytes()) if f.is_file() else bytearray()
        return data if len(data) == self.bits // 8 else bytearray(self.bits // 8)

    def _positions(self, domain: str) -> list[int]:
        h = hashlib.blake2b(domain.encode("utf-8"), digest_size=16).digest()
        a, b = int.from_bytes(h[:8], "little"), int.from_bytes(h[8:], "little") | 1
        return [(a + i * b) % self.bits for i in range(HASHES)]

    def _has(self, gen: bytearray, pos: list[int]) -> bool:
        return all(gen[p >> 3] & (1 << (p & 7)) for p in pos)

    def add(self, domains: Iterable[str]) -> set[str]:
        """Remember these domains; return the ones not seen before."""
        new: set[str] = set()
        cur = self.gens[self.current]
        old = self.gens["b" if self.current == "a" else "a"]
        for d in set(domains):
            pos = self._positions(d)
            if self._has(cur, pos):
                continue
            if not self._has(old, pos):
                new.add(d)
            for p in pos:
                cur[p >> 3] |= 1 << (p & 7)
        return new

    @property
    def warm(self) -> bool:
        return self.now - _parse(self.since) >= WARM_AFTER

    def estimate(self) -> int:
        """Approximate number of domains in the current generation."""
        ones = int.from_bytes(self.gens[self.current], "little").bit_count()
        if ones >= self.bits:
            return -1
        return round(-self.bits / HASHES * math.log(1 - ones / self.bits))

    def save(self) -> None:
        self.path.mkdir(parents=True, exist_ok=True)
        for g, data in self.gens.items():
            tmp = self.path / f"gen-{g}.tmp"
            tmp.write_bytes(data)
            tmp.replace(self.path / f"gen-{g}.bin")
        meta = {"bits": self.bits, "since": self.since, "current": self.current, "started": self.started}
        tmp = self.path / "meta.tmp"
        tmp.write_text(json.dumps(meta, indent=1) + "\n", encoding="utf-8")
        tmp.replace(self.path / "meta.json")
