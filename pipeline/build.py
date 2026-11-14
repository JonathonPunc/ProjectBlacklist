"""Fetch, filter, gate and publish the lists."""

from __future__ import annotations

import datetime as dt
import io
import shutil
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from licensing import registry as lic

from . import formats
from .feeds import FEEDS, Feed
from .fetch import FetchError, Getter, cached
from .guard import Guard, load_tranco
from .hosts import PublicSuffixList, normalize
from .parse import parse
from .state import State

PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
HOMEPAGE = "https://github.com/JonathonPunc/ProjectBlacklist"
ISSUES = HOMEPAGE + "/issues"
RAW_BASE = "https://raw.githubusercontent.com/JonathonPunc/ProjectBlacklist/dist"
EXPIRES = {"complement": "30 minutes", "all-in-one": "8 hours"}
TITLES = {"complement": "ProjectBlacklist complement", "all-in-one": "ProjectBlacklist all-in-one"}

# Sanity gates
MIN_ENTRIES = 50
BUILD_SWING = 0.30          # a build may not grow or shrink more than this between runs
SMALL_BUILD = 1_000         # below this size, allow a larger swing
SMALL_SWING = 0.75
# The all-in-one list is mostly HaGeZi TIF, which HaGeZi already publishes in
# dnsmasq, Unbound and RPZ form. Re-hosting those at 70-95 MiB each, three times
# a day, isn't worth the churn, so all-in-one ships the formats most people use.
BUILD_FORMATS = {"all-in-one": ("abp", "domains", "hosts")}

MAX_FILE = 95 * 1024 * 1024  # GitHub refuses files over 100 MiB
WARN_FILE = 50 * 1024 * 1024


@dataclass
class SourceReport:
    id: str
    how: str = ""                      # fetched | not due | snapshot | local | unavailable
    raw: int = 0
    kept: int = 0
    dropped: Counter = field(default_factory=Counter)
    notes: list[str] = field(default_factory=list)


@dataclass
class BuildReport:
    id: str
    entries: int = 0
    previous: int | None = None
    published: bool = False
    failure: str = ""
    note: str = ""
    files: dict[str, int] = field(default_factory=dict)


@dataclass
class Report:
    sources: dict[str, SourceReport] = field(default_factory=dict)
    builds: dict[str, BuildReport] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    reference: dict[str, str] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return all(b.published for b in self.builds.values())


def load_domain_file(path: Path) -> set[str]:
    out = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            host = normalize(line)
            if not host:
                raise ValueError(f"{path}: not a valid domain: {line!r}")
            out.add(host)
    return out


class Builder:
    def __init__(self, *, repo: Path, dist: Path, cache: Path, get: Getter,
                 now: dt.datetime | None = None, registry: lic.Registry | None = None,
                 min_entries: int = MIN_ENTRIES, allow_swing: bool = False) -> None:
        self.repo, self.dist, self.cache, self.get = repo, dist, cache, get
        self.min_entries = min_entries
        self.allow_swing = allow_swing
        self.now = now or dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        self.reg = registry or lic.load()
        self.report = Report()

    # -- reference data -----------------------------------------------------
    def _guard(self) -> Guard:
        psl_bytes, how = cached(PSL_URL, self.cache / "public_suffix_list.dat",
                                max_age=dt.timedelta(days=1), now=self.now, get=self.get)
        self.report.reference["Public Suffix List"] = how
        zbytes, how = cached(TRANCO_URL, self.cache / "tranco-top-1m.csv.zip",
                             max_age=dt.timedelta(days=1), now=self.now, get=self.get)
        self.report.reference["Tranco"] = how
        with zipfile.ZipFile(io.BytesIO(zbytes)) as z:
            csv_name = next(n for n in z.namelist() if n.endswith(".csv"))
            tranco = load_tranco(z.read(csv_name).decode("utf-8", "replace"))
        allow = load_domain_file(self.repo / "data" / "allow.txt")
        return Guard(PublicSuffixList(psl_bytes.decode("utf-8")), tranco, allow)

    # -- sources ------------------------------------------------------------
    def _due(self, feed: Feed, state: State) -> bool:
        last = state.last_fetch(feed.source_id)
        return last is None or self.now - last >= feed.min_interval

    def _fetch(self, feed: Feed, src: lic.Source, state: State, rep: SourceReport) -> set[str] | None:
        """Fetch and parse; None (with a note) if the fetch or a health check fails."""
        try:
            text = self.get(src.url).decode("utf-8", "replace")
        except FetchError as exc:
            rep.notes.append(f"fetch failed: {exc}")
            return None
        parsed = parse(text, feed.fmt)
        if parsed.junk_ratio > feed.max_junk:
            rep.notes.append(f"rejected: {parsed.junk_ratio:.0%} of lines didn't parse")
            return None
        if not parsed.entries:
            rep.notes.append("fetch returned no entries")
            return None
        prev = state.source_counts.get(feed.source_id)
        if feed.swing_limit is not None and prev:
            change = abs(len(parsed.entries) - prev) / prev
            if change > feed.swing_limit:
                rep.notes.append(f"rejected: {prev} -> {len(parsed.entries)} entries "
                                 f"({change:.0%} change, limit {feed.swing_limit:.0%})")
                return None
        state.mark_fetched(feed.source_id, self.now)
        state.source_counts[feed.source_id] = len(parsed.entries)
        return parsed.entries

    def _collect(self, feed: Feed, src: lic.Source, state: State) -> set[str] | None:
        rep = self.report.sources.setdefault(src.id, SourceReport(src.id))
        if feed.kind == "local":
            rep.how = "local"
            return load_domain_file(self.repo / feed.path)
        if not src.url:
            raise ValueError(f"source {src.id}: registry has no url to fetch")
        due = self._due(feed, state)
        fresh = self._fetch(feed, src, state, rep) if due else None
        if feed.kind == "live":
            if fresh is not None:
                state.observe(src.id, fresh, self.now)
                rep.how = "fetched"
            else:
                rep.how = "not due" if not due else "kept previous"
            gone = state.expire(src.id, feed.ttl or dt.timedelta(0), self.now)
            if gone:
                rep.notes.append(f"{gone} hosts expired after {feed.ttl}")
            return state.live_hosts(src.id)
        # mirror
        if fresh is not None:
            state.save_snapshot(src.id, fresh, self.now)
            rep.how = "fetched"
            return fresh
        snap = state.load_snapshot(src.id)
        if snap and self.now - snap[1] <= feed.max_stale:
            rep.how = "not due" if not due else "snapshot"
            rep.notes.append(f"using copy from {snap[1]:%Y-%m-%d %H:%M} UTC")
            return snap[0]
        rep.how = "unavailable"
        self.report.warnings.append(f"{src.id}: no usable copy, left out of this run")
        return None

    # -- builds -------------------------------------------------------------
    def _header(self, build: str) -> list[str]:
        b = self.reg.builds[build]
        return [
            f"Title: {TITLES.get(build, build)}",
            f"Description: {b.description}",
            f"Homepage: {HOMEPAGE}",
            f"Expires: {EXPIRES.get(build, '1 day')}",
            f"Last modified: {self.now:%d %b %Y %H:%M} UTC",
            f"Version: {self.now:%Y.%m%d.%H%M}",
            *lic.header_lines(self.reg, build),
            f"Report false positives: {ISSUES}",
        ]

    def _gate(self, build: str, hosts: set[str], present: list[str], state: State, rep: BuildReport) -> str:
        if len(hosts) < self.min_entries:
            return f"only {len(hosts)} entries (minimum {self.min_entries})"
        prev = state.build_counts.get(build)
        before = set(state.build_sources.get(build, ()))
        added = sorted(set(present) - before)
        if before and added and before <= set(present):
            # A source joined (or came back) and none went missing: growth is expected.
            rep.note = f"swing check skipped: new source(s) {', '.join(added)}"
        elif self.allow_swing:
            rep.note = "swing check skipped: --allow-swing"
        elif prev:
            limit = SMALL_SWING if prev < SMALL_BUILD else BUILD_SWING
            change = abs(len(hosts) - prev) / prev
            if change > limit:
                return f"{prev} -> {len(hosts)} entries ({change:.0%} change, limit {limit:.0%})"
        return ""

    def _write(self, build: str, hosts: set[str], guard: Guard, rep: BuildReport) -> str:
        """Write a build into a temp dir, verify every file, then swap it into place."""
        tmp = self.dist / f".tmp-{build}"
        shutil.rmtree(tmp, ignore_errors=True)
        lic.stage(self.reg, build, tmp)            # LICENSE + NOTICE; refuses if licensing fails
        header = self._header(build)
        serial = int(self.now.timestamp())
        prepared = formats.prepare(hosts)
        wanted = {"wildcard": set(prepared["wildcard"]), "exact": hosts}
        for fmt in build_formats(build):
            name = formats.FILES[fmt]
            text = formats.render(fmt, prepared, header, serial)
            listed = formats.read_back(fmt, text)
            want = wanted["wildcard" if fmt in formats.WILDCARD else "exact"]
            if listed != want:
                shutil.rmtree(tmp, ignore_errors=True)
                return f"{name} doesn't read back as written ({len(listed)} vs {len(want)})"
            hit = sorted(a for a in guard.allow if formats.blocks(fmt, listed, a))
            if hit:
                shutil.rmtree(tmp, ignore_errors=True)
                return f"{name} would block allowlisted {', '.join(hit[:5])}"
            data = text.encode("utf-8")
            if len(data) > MAX_FILE:
                shutil.rmtree(tmp, ignore_errors=True)
                return f"{name} is {len(data) >> 20} MiB, over GitHub's limit"
            if len(data) > WARN_FILE:
                self.report.warnings.append(f"{build}/{name} is {len(data) >> 20} MiB")
            (tmp / name).write_bytes(data)
            rep.files[name] = len(data)
        final = self.dist / build
        old = self.dist / f".old-{build}"
        shutil.rmtree(old, ignore_errors=True)
        if final.exists():
            final.rename(old)
        tmp.rename(final)
        shutil.rmtree(old, ignore_errors=True)
        return ""

    def run(self, builds: list[str]) -> Report:
        errors, warnings = lic.check(self.reg)
        if errors:
            raise ValueError("licensing check failed:\n  " + "\n  ".join(errors))
        self.report.warnings += warnings
        unknown = [b for b in builds if b not in self.reg.builds]
        if unknown:
            raise ValueError(f"unknown build(s): {', '.join(unknown)}")
        sources = {s.id: s for b in builds for s in self.reg.feeding(b)}
        missing = sorted(set(sources) - set(FEEDS))
        if missing:
            raise ValueError(f"approved sources with no pipeline settings: {', '.join(missing)}")

        self.dist.mkdir(parents=True, exist_ok=True)
        state = State(self.dist)
        guard = self._guard()

        kept: dict[str, set[str]] = {}
        for sid, src in sources.items():
            feed = FEEDS[sid]
            hosts = self._collect(feed, src, state)
            rep = self.report.sources[sid]
            if hosts is None:
                continue
            rep.raw = len(hosts)
            ok = set()
            for h in hosts:
                why = guard.reason(h, feed.tranco_limit)
                if why:
                    rep.dropped[why] += 1
                else:
                    ok.add(h)
            rep.kept = len(ok)
            kept[sid] = ok

        for build in builds:
            rep = self.report.builds[build] = BuildReport(build, previous=state.build_counts.get(build))
            hosts: set[str] = set()
            for s in self.reg.feeding(build):
                hosts |= kept.get(s.id, set())
            present = sorted(s.id for s in self.reg.feeding(build) if s.id in kept)
            rep.entries = len(hosts)
            rep.failure = self._gate(build, hosts, present, state, rep) or self._write(build, hosts, guard, rep)
            if not rep.failure:
                rep.published = True
                state.build_counts[build] = len(hosts)
                state.build_sources[build] = present

        state.save()
        (self.dist / "README.md").write_text(dist_readme(self.reg, state, self.now), encoding="utf-8")
        return self.report


def build_formats(build: str) -> tuple[str, ...]:
    return BUILD_FORMATS.get(build, tuple(formats.FILES))


def dist_readme(reg: lic.Registry, state: State, now: dt.datetime) -> str:
    lines = [
        "# ProjectBlacklist lists",
        "",
        f"Generated by the build pipeline in [{HOMEPAGE}]({HOMEPAGE}); don't edit this branch.",
        "Entries are suspected malicious or phishing hosts, not confirmed verdicts.",
        "",
        f"Last run: {now:%Y-%m-%d %H:%M} UTC",
        "",
    ]
    for bid, b in reg.builds.items():
        lines += [f"## {bid} ({b.license})", "", b.description, ""]
        if bid in state.build_counts:
            lines += [f"Entries: {state.build_counts[bid]:,}", ""]
        lines += ["| Format | URL |", "| --- | --- |"]
        for fmt in build_formats(bid):
            lines.append(f"| {formats.SYNTAX[fmt]} | {RAW_BASE}/{bid}/{formats.FILES[fmt]} |")
        lines += ["", "Sources: " + "; ".join(s.name for s in reg.feeding(bid)), ""]
    return "\n".join(lines)


def _escape(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def annotations(report: Report) -> list[str]:
    """GitHub workflow commands for a run. Annotations show on a run's page to
    anyone, signed in or not; the step summary and logs need a signed-in user."""
    out = []
    for s in report.sources.values():
        line = f"{s.id}: {s.how}, {s.kept:,} kept of {s.raw:,}"
        if s.notes:
            line += " - " + "; ".join(s.notes)
        out.append(f"::notice title=Source::{_escape(line)}")
    for b in report.builds.values():
        if b.published:
            out.append(f"::notice title=Build::{_escape(f'{b.id}: {b.entries:,} entries, passed')}")
        else:
            out.append(f"::error title=Build::{_escape(f'{b.id}: {b.entries:,} entries, NOT published: {b.failure}')}")
    out += [f"::warning title=Warning::{_escape(w)}" for w in report.warnings]
    return out


def summary(report: Report) -> str:
    """Markdown summary of a run, for logs and the GitHub step summary."""
    out = ["## Sources", "", "| Source | How | Raw | Kept | Dropped | Notes |", "| --- | --- | --- | --- | --- | --- |"]
    for s in report.sources.values():
        dropped = ", ".join(f"{k} {v}" for k, v in sorted(s.dropped.items())) or "-"
        out.append(f"| {s.id} | {s.how} | {s.raw:,} | {s.kept:,} | {dropped} | {'; '.join(s.notes) or '-'} |")
    out += ["", "## Builds", "", "| Build | Entries | Previous | Result |", "| --- | --- | --- | --- |"]
    for b in report.builds.values():
        prev = f"{b.previous:,}" if b.previous is not None else "-"
        result = "published" if b.published else f"NOT published: {b.failure}"
        if b.note:
            result += f" ({b.note})"
        out.append(f"| {b.id} | {b.entries:,} | {prev} | {result} |")
    if report.reference:
        out += ["", "Reference data: " + "; ".join(f"{k} {v}" for k, v in report.reference.items())]
    if report.warnings:
        out += ["", "## Warnings", "", *(f"- {w}" for w in report.warnings)]
    return "\n".join(out) + "\n"
