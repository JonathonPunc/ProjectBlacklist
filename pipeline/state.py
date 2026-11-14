"""Build state kept on the dist branch between runs.

state/state.json holds when each source was last fetched, entry counts for the
sanity gates, and first/last-seen times for live feeds. state/snapshots/ keeps
the last good copy of each mirror feed. All of it is data we already publish,
so it's fine for it to be public.
"""

from __future__ import annotations

import datetime as dt
import gzip
import json
from pathlib import Path

VERSION = 1


def _iso(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(s: str) -> dt.datetime:
    return dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)


class State:
    def __init__(self, dist: Path) -> None:
        self.dir = dist / "state"
        self.path = self.dir / "state.json"
        data = json.loads(self.path.read_text(encoding="utf-8")) if self.path.is_file() else {}
        if data and data.get("version") != VERSION:
            raise ValueError(f"{self.path}: unsupported state version {data.get('version')}")
        self.fetched: dict[str, str] = data.get("fetched", {})
        self.source_counts: dict[str, int] = data.get("source_counts", {})
        self.build_counts: dict[str, int] = data.get("build_counts", {})
        self.build_sources: dict[str, list[str]] = data.get("build_sources", {})
        self.seen: dict[str, dict[str, list[str]]] = data.get("seen", {})

    # -- fetch times --------------------------------------------------------
    def last_fetch(self, source: str) -> dt.datetime | None:
        s = self.fetched.get(source)
        return _parse(s) if s else None

    def mark_fetched(self, source: str, now: dt.datetime) -> None:
        self.fetched[source] = _iso(now)

    # -- live feeds ---------------------------------------------------------
    def observe(self, source: str, hosts: set[str], now: dt.datetime) -> None:
        seen = self.seen.setdefault(source, {})
        stamp = _iso(now)
        for h in hosts:
            seen.setdefault(h, [stamp, stamp])[1] = stamp

    def expire(self, source: str, ttl: dt.timedelta, now: dt.datetime) -> int:
        seen = self.seen.get(source, {})
        dead = [h for h, (_, last) in seen.items() if now - _parse(last) > ttl]
        for h in dead:
            del seen[h]
        return len(dead)

    def live_hosts(self, source: str) -> set[str]:
        return set(self.seen.get(source, {}))

    # -- mirror snapshots ---------------------------------------------------
    def _snap(self, source: str) -> Path:
        return self.dir / "snapshots" / f"{source}.txt.gz"

    def save_snapshot(self, source: str, hosts: set[str], now: dt.datetime) -> None:
        p = self._snap(source)
        p.parent.mkdir(parents=True, exist_ok=True)
        body = f"# fetched {_iso(now)}\n" + "\n".join(sorted(hosts)) + "\n"
        tmp = p.with_suffix(".tmp")
        with gzip.open(tmp, "wt", encoding="utf-8", compresslevel=9) as f:
            f.write(body)
        tmp.replace(p)

    def load_snapshot(self, source: str) -> tuple[set[str], dt.datetime] | None:
        p = self._snap(source)
        if not p.is_file():
            return None
        with gzip.open(p, "rt", encoding="utf-8") as f:
            first = f.readline()
            if not first.startswith("# fetched "):
                return None
            when = _parse(first.split()[2])
            return {ln.strip() for ln in f if ln.strip()}, when

    # -- persistence --------------------------------------------------------
    def save(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        data = {"version": VERSION, "fetched": self.fetched, "source_counts": self.source_counts,
                "build_counts": self.build_counts, "build_sources": self.build_sources,
                "seen": self.seen}
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        tmp.replace(self.path)
