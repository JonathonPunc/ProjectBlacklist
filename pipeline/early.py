"""Early warning: spot brand-lookalike hosts in new TLS certificates.

Each run reads the certificates logged since the last run (pipeline.ct),
scores every hostname (pipeline.lookalike), and:

  score >= FLAG      flagged straight away
  score == FLAG - 1  borderline: its home page is checked (pipeline.pagecheck),
                     now and on later runs for up to a day, and flagged if the
                     page asks for a password or secret and names the brand

Flagged hosts stay listed for TTL. To measure how well this works, each run
also notes when a flagged host later shows up in one of the other feeds
(phishunt, CERT Polska, HaGeZi, ...) and how much earlier we had it. Hosts
that never show up there aren't necessarily wrong: those feeds miss plenty.

State lives in state/early-warning.json on the dist branch.
"""

from __future__ import annotations

import datetime as dt
import json
import statistics
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from . import ct, pagecheck
from .fetch import FetchError, Getter, cached
from .seen import SeenDomains
from .hosts import ancestors, normalize
from .lookalike import FLAG, Detector

LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json"
# Tiled logs that publish names tiles. Each Let's Encrypt certificate is in one
# or both of these, so reading both catches about half again as many as one.
LOG_FAMILIES = ("Let's Encrypt Willow", "Let's Encrypt Sycamore")
# GitHub starts scheduled runs late or not at all when it's busy, so a run may
# find several hours of certificates waiting. It reads them for up to
# CT_BUDGET, saving its place as it goes; the next run carries on from there.
# Only a backlog beyond MAX_TILES (about 12 hours of Let's Encrypt) is skipped.
MAX_TILES = 48_000                # per log (~12M certificates); beyond it, skip ahead
CT_BUDGET = dt.timedelta(minutes=15)
CT_CHUNK = 1_000                  # tiles read from one log before switching to the next
CT_WORKERS = 16
PAGE_CHECKS = 3_000               # per run; about an hour's borderline names plus re-checks
PAGE_WORKERS = 128
RECHECK_AFTER = dt.timedelta(minutes=50)  # just under the hourly run, which often starts late
MAX_TRIES = 3
PENDING_FOR = dt.timedelta(days=1)
TTL = dt.timedelta(days=14)


def _iso(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(s: str) -> dt.datetime:
    return dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)


def select_logs(log_list: dict, now: dt.datetime) -> list[ct.Log]:
    """Usable shards of LOG_FAMILIES that can hold a certificate issued now."""
    horizon = now + dt.timedelta(days=400)
    out = []
    for op in log_list.get("operators", []):
        for log in op.get("tiled_logs", []):
            desc = log.get("description", "")
            if not desc.startswith(LOG_FAMILIES) or "usable" not in log.get("state", {}):
                continue
            ti = log.get("temporal_interval", {})
            try:
                start = dt.datetime.fromisoformat(ti["start_inclusive"].replace("Z", "+00:00"))
                end = dt.datetime.fromisoformat(ti["end_exclusive"].replace("Z", "+00:00"))
            except (KeyError, ValueError):
                continue
            if end > now and start < horizon:
                out.append(ct.Log(desc, log["monitoring_url"].rstrip("/")))
    return sorted(out, key=lambda lg: lg.name)


@dataclass
class Result:
    hosts: set[str]
    notes: list[str] = field(default_factory=list)
    stats: dict = field(default_factory=dict)


class EarlyWarning:
    def __init__(self, *, dist: Path, cache: Path, get: Getter, detector: Detector,
                 now: dt.datetime, page_get: pagecheck.PageGetter | None = None,
                 clock: Callable[[], float] = time.monotonic, seen: SeenDomains | None = None) -> None:
        self.path = dist / "state" / "early-warning.json"
        self.cache, self.get, self.det, self.now = cache, get, detector, now
        self.page_get = page_get or pagecheck.fetch_page
        self.clock = clock
        self.seen = seen                              # optional memory of domains seen before
        data = json.loads(self.path.read_text(encoding="utf-8")) if self.path.is_file() else {}
        self.cursors: dict[str, int] = data.get("cursors", {})
        self.pending: dict[str, dict] = data.get("pending", {})
        self.flagged: dict[str, dict] = data.get("flagged", {})

    # -- certificates -------------------------------------------------------
    def _new_names(self, notes: list[str]) -> tuple[set[str], int]:
        raw, how = cached(LOG_LIST_URL, self.cache / "ct-log-list.json",
                          max_age=dt.timedelta(days=1), now=self.now, get=self.get)
        logs = select_logs(json.loads(raw), self.now)
        if not logs:
            notes.append("no Certificate Transparency logs selected")
        names: set[str] = set()
        certs = 0
        work: list[list] = []                         # [log, next entry, end]
        for log in logs:
            try:
                size = ct.checkpoint_size(self.get(f"{log.url}/checkpoint").decode("utf-8", "replace"))
            except (FetchError, ValueError) as exc:
                notes.append(f"{log.name}: {exc}")
                continue
            end = size // ct.TILE * ct.TILE
            start = self.cursors.get(log.url)
            if start is None or start > end:
                self.cursors[log.url] = end           # new log: start from now, don't backfill
                notes.append(f"{log.name}: starting at entry {end:,}")
                continue
            if end - start > MAX_TILES * ct.TILE:
                skipped = end - MAX_TILES * ct.TILE - start
                start = end - MAX_TILES * ct.TILE
                self.cursors[log.url] = start
                notes.append(f"{log.name}: fell behind, skipped {skipped:,} certificates")
            if start < end:
                work.append([log, start, end])
        # Take the logs in turns, a chunk at a time, so running out of time
        # leaves each one partly read rather than one read and one untouched.
        deadline = self.clock() + CT_BUDGET.total_seconds()
        while work and self.clock() < deadline:
            for w in list(work):
                log, pos, end = w
                stop = min(end, pos + CT_CHUNK * ct.TILE)
                try:
                    for _, ns in ct.read_names(log, pos, stop, self.get, workers=CT_WORKERS):
                        certs += 1
                        names.update(ns)
                except (FetchError, ValueError) as exc:
                    notes.append(f"{log.name}: {exc}; will retry from entry {pos:,}")
                    work.remove(w)
                    continue
                self.cursors[log.url] = w[1] = stop
                if stop >= end:
                    work.remove(w)
                if self.clock() >= deadline:
                    break
        left = sum(end - pos for _, pos, end in work)
        if left:
            notes.append(f"out of time: {left:,} certificates left for the next run")
        # Drop cursors for shards that have left the list.
        live = {lg.url for lg in logs}
        self.cursors = {u: c for u, c in self.cursors.items() if u in live}
        return names, certs

    # -- page checks --------------------------------------------------------
    def _terms(self, brand: str) -> list[str]:
        b = next((b for b in self.det.brands if b.name == brand), None)
        if b is None:
            return [brand.lower()]
        return [brand.lower(), *b.strong, *b.weak]

    def _owned(self, host: str) -> bool:
        reg = self.det.psl.registrable(host, private=False)
        return self.det.owns(reg) if reg else False

    def _check_pages(self, notes: list[str]) -> int:
        due = [h for h, p in self.pending.items()
               if p["tries"] == 0
               or (p["tries"] < MAX_TRIES and self.now - _parse(p["last"]) >= RECHECK_AFTER)]
        # First checks before re-checks, then names on domains we had never
        # seen a certificate for (likely just registered), newest first: a
        # phishing page is usually up in its first hours, and a name waits at
        # most PENDING_FOR. A name with no domain-memory answer counts as new.
        due = sorted(due, key=lambda h: (self.pending[h]["tries"] > 0,
                                         self.pending[h].get("new_domain") is False,
                                         -_parse(self.pending[h]["first"]).timestamp()))[:PAGE_CHECKS]
        if not due:
            return 0
        with ThreadPoolExecutor(PAGE_WORKERS) as pool:
            pages = list(pool.map(self.page_get, due))
        for host, page in zip(due, pages):
            p = self.pending[host]
            p["tries"] += 1
            p["last"] = _iso(self.now)
            if page is None:
                continue
            kind, why = pagecheck.verdict(page, self._terms(p["brand"]), self._owned)
            if kind == "phish":
                self._flag(host, p["score"] + 2, p["reasons"] + [why], first=p["first"])
                del self.pending[host]
            elif kind == "brand-site":
                del self.pending[host]
        return len(due)

    # -- bookkeeping --------------------------------------------------------
    def _rescore(self) -> None:
        """Apply detector changes to names already held, not just new ones.

        A name now on a brand's own domain (one added to brands.toml, say) is
        dropped. A name flagged on its name alone that no longer scores FLAG
        goes back for a page check, unless another feed has since listed it."""
        self.pending = {h: p for h, p in self.pending.items() if self.det.score(h) is not None}
        for host, f in list(self.flagged.items()):
            s = self.det.score(host)
            if s is None:
                del self.flagged[host]
            elif (s.score < FLAG and not f.get("confirmed")
                  and not any(r.startswith("page asks") for r in f.get("reasons", []))):
                del self.flagged[host]
                if s.score == FLAG - 1:
                    self.pending[host] = {"first": _iso(self.now), "last": _iso(self.now), "tries": 0,
                                          "score": s.score, "reasons": s.reasons, "brand": s.brand}

    def _flag(self, host: str, score: int, reasons: list[str], *, first: str | None = None) -> None:
        if host not in self.flagged:
            self.flagged[host] = {"first": first or _iso(self.now), "flagged": _iso(self.now),
                                  "score": score, "reasons": reasons}

    def confirm(self, others: dict[str, set[str]]) -> None:
        """Record when a flagged host first shows up in another feed."""
        for host, f in self.flagged.items():
            if f.get("confirmed"):
                continue
            names = [host, *ancestors(host)]
            for sid, hosts in others.items():
                if any(n in hosts for n in names):
                    f["confirmed"] = {"at": _iso(self.now), "by": sid}
                    break

    def _stats(self) -> dict:
        flagged = list(self.flagged.values())
        conf = [f for f in flagged if f.get("confirmed")]
        lead = [(_parse(f["confirmed"]["at"]) - _parse(f["flagged"])).total_seconds() / 3600 for f in conf]
        return {"listed": len(flagged), "pending page check": len(self.pending),
                "later seen in other feeds": len(conf),
                "median hours ahead": round(statistics.median(lead), 1) if lead else None}

    def run(self) -> Result:
        notes: list[str] = []
        self._rescore()
        names, certs = self._new_names(notes)
        hosts = {normalize(n[2:] if n.startswith("*.") else n) for n in names}
        hosts.discard(None)
        reg_of: dict[str, str] = {}
        new_regs: set[str] = set()
        if self.seen is not None:
            for h in hosts:
                r = self.det.psl.registrable(h)
                if r:
                    reg_of[h] = r
            new_regs = self.seen.add(reg_of.values())
        new_flags = new_pending = 0
        for h in hosts:
            if h in self.flagged:
                continue
            s = self.det.score(h)
            if s is None:
                continue
            if s.score >= FLAG:
                self._flag(h, s.score, s.reasons)
                self.pending.pop(h, None)
                new_flags += 1
            elif s.score == FLAG - 1 and h not in self.pending:
                self.pending[h] = {"first": _iso(self.now), "last": _iso(self.now), "tries": 0,
                                   "score": s.score, "reasons": s.reasons, "brand": s.brand}
                if h in reg_of:
                    self.pending[h]["new_domain"] = reg_of[h] in new_regs
                new_pending += 1
        before = len(self.flagged)
        checked = self._check_pages(notes)
        by_page = len(self.flagged) - before
        # Expire.
        self.flagged = {h: f for h, f in self.flagged.items() if self.now - _parse(f["flagged"]) <= TTL}
        self.pending = {h: p for h, p in self.pending.items()
                        if p["tries"] < MAX_TRIES and self.now - _parse(p["first"]) <= PENDING_FOR}
        notes.insert(0, f"{certs:,} new certificates, {len(hosts):,} names: {new_flags} flagged by name, "
                        f"{new_pending} borderline, {checked} pages checked, {by_page} flagged by page")
        if self.seen is not None:
            regs = set(reg_of.values())
            warm = "" if self.seen.warm else " (still warming up: most look new for the first 60 days)"
            notes.append(f"domain memory: {len(new_regs):,} of {len(regs):,} domains seen for the first time"
                         f"{warm}; about {self.seen.estimate():,} remembered"
                         + ("; started a new generation" if self.seen.rotated else ""))
        return Result(set(self.flagged), notes, self._stats())

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = {"cursors": self.cursors, "pending": self.pending, "flagged": self.flagged}
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        tmp.replace(self.path)
        if self.seen is not None:
            self.seen.save()
