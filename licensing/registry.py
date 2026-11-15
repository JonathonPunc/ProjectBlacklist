"""Source registry and licence rules for ProjectBlacklist.

Every upstream feed the pipeline may touch is declared in ``sources.toml`` with
its licence, its status and the builds it may feed. ``check`` refuses any
combination that would put data into a build whose licence can't carry it.
``sync`` regenerates the files derived from the registry (NOTICE and the source
table in LICENSING.md) and ``check`` fails if they have drifted.

The build pipeline calls ``stage`` for each build it publishes: it re-runs the
check, writes the build's LICENSE and NOTICE next to the list files, and returns
the header lines every published list must carry.
"""

from __future__ import annotations

import datetime as dt
import shutil
import tomllib
from dataclasses import dataclass
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent
ROOT = PACKAGE.parent
REGISTRY_PATH = PACKAGE / "sources.toml"
# Licence texts the pipeline ships with built lists. They are kept apart from
# LICENSES/, which REUSE reserves for the licences of files in this repo, and
# are named LICENSE-<SPDX id>.txt so REUSE recognises them as licence files.
TEXTS_DIR = PACKAGE / "texts"
NOTICE_PATH = ROOT / "NOTICE"
LICENSING_DOC = ROOT / "LICENSING.md"
TABLE_START = "<!-- sources:start -->"
TABLE_END = "<!-- sources:end -->"

# Which source licences each build licence can carry. Kept short on purpose: a
# licence that isn't listed is refused until someone checks it and adds it.
COMPATIBLE: dict[str, frozenset[str]] = {
    "CC0-1.0": frozenset({"CC0-1.0", "Unlicense", "PDDL-1.0"}),
    "GPL-3.0-only": frozenset({
        "CC0-1.0", "Unlicense", "PDDL-1.0",
        "MIT", "ISC", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0",
        # The FSF lists CC BY 4.0 as GPLv3-compatible; CC BY-SA 4.0 is
        # one-way compatible with GPLv3.
        "CC-BY-4.0", "CC-BY-SA-4.0",
        "GPL-3.0-only", "GPL-3.0-or-later",
    }),
}

# Licences whose own terms require their notice to travel with copies.
NOTICE_REQUIRED = frozenset({
    "MIT", "ISC", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0",
    "CC-BY-4.0", "CC-BY-SA-4.0", "GPL-3.0-only", "GPL-3.0-or-later",
})

LICENSE_URLS = {
    "CC0-1.0": "https://creativecommons.org/publicdomain/zero/1.0/",
    "GPL-3.0-only": "https://www.gnu.org/licenses/gpl-3.0.html",
}

STATUSES = ("approved", "pending", "excluded", "internal")
REVERIFY_AFTER = dt.timedelta(days=365)

# Every published list says this, whatever its sources. phishunt's terms
# require it, and it is true of every feed we use.
SUSPECTED_LINE = "Entries are suspected malicious or phishing hosts, not confirmed verdicts."


@dataclass(frozen=True)
class Build:
    id: str
    license: str
    description: str


@dataclass(frozen=True)
class Source:
    id: str
    name: str
    status: str
    license: str
    builds: tuple[str, ...]
    homepage: str
    terms_url: str
    url: str
    verified: object  # dt.date when valid; anything else is reported by check()
    attribution: str
    conditions: tuple[str, ...]
    requests: tuple[str, ...]
    notes: str
    report_url: str = ""       # where to report a wrongly listed entry


@dataclass(frozen=True)
class CustomLicense:
    """Terms that aren't an SPDX licence, declared in sources.toml."""
    id: str
    name: str
    url: str
    compatible_with: tuple[str, ...]
    notice_required: bool
    summary: str


@dataclass(frozen=True)
class Registry:
    builds: dict[str, Build]
    sources: tuple[Source, ...]
    licenses: dict[str, CustomLicense]

    def compatible(self, build_license: str, source_license: str) -> bool:
        if source_license in COMPATIBLE.get(build_license, ()):
            return True
        custom = self.licenses.get(source_license)
        return custom is not None and build_license in custom.compatible_with

    def needs_notice(self, license_id: str) -> bool:
        custom = self.licenses.get(license_id)
        return custom.notice_required if custom else license_id in NOTICE_REQUIRED

    def feeding(self, build_id: str) -> list[Source]:
        """Approved sources whose data goes into ``build_id``."""
        return [s for s in self.sources if s.status == "approved" and build_id in s.builds]


def loads(text: str) -> Registry:
    raw = tomllib.loads(text)
    builds = {
        bid: Build(bid, str(b.get("license", "")), " ".join(str(b.get("description", "")).split()))
        for bid, b in raw.get("builds", {}).items()
    }
    sources = tuple(
        Source(
            id=str(s.get("id", "")),
            name=str(s.get("name", "")),
            status=str(s.get("status", "")),
            license=str(s.get("license", "")),
            builds=tuple(s.get("builds", ())),
            homepage=str(s.get("homepage", "")),
            terms_url=str(s.get("terms_url", "")),
            url=str(s.get("url", "")),
            verified=s.get("verified"),
            attribution=str(s.get("attribution", "")).strip(),
            conditions=tuple(s.get("conditions", ())),
            report_url=str(s.get("report_url", "")),
            requests=tuple(s.get("requests", ())),
            notes=" ".join(str(s.get("notes", "")).split()),
        )
        for s in raw.get("sources", [])
    )
    licenses = {
        lid: CustomLicense(
            id=lid,
            name=str(c.get("name", "")),
            url=str(c.get("url", "")),
            compatible_with=tuple(c.get("compatible_with", ())),
            notice_required=bool(c.get("notice_required", True)),
            summary=" ".join(str(c.get("summary", "")).split()),
        )
        for lid, c in raw.get("licenses", {}).items()
    }
    return Registry(builds, sources, licenses)


def load(path: Path = REGISTRY_PATH) -> Registry:
    return loads(path.read_text(encoding="utf-8"))


def _is_date(value: object) -> bool:
    # tomllib returns datetime.datetime for date-times, which is a date subclass.
    return isinstance(value, dt.date) and not isinstance(value, dt.datetime)


def check(reg: Registry, *, today: dt.date | None = None,
          texts_dir: Path = TEXTS_DIR) -> tuple[list[str], list[str]]:
    """Return (errors, warnings). Any error means the registry can't be published."""
    today = today or dt.date.today()
    errors: list[str] = []
    warnings: list[str] = []

    for b in reg.builds.values():
        if b.license not in COMPATIBLE:
            errors.append(f"build {b.id}: licence {b.license!r} has no compatibility rules")
        if not text_path(b.license, texts_dir).is_file():
            errors.append(f"build {b.id}: missing licence text {text_path(b.license, texts_dir).name}")

    for c in reg.licenses.values():
        where = f"licence {c.id}"
        if not c.id.startswith("LicenseRef-"):
            errors.append(f"{where}: custom terms must use a LicenseRef- id, not an SPDX one")
        if not (c.name and c.url and c.summary):
            errors.append(f"{where}: needs name, url and summary")
        for bl in c.compatible_with:
            if bl not in COMPATIBLE:
                errors.append(f"{where}: compatible_with names {bl!r}, which no build rule knows")

    seen: set[str] = set()
    for s in reg.sources:
        where = f"source {s.id or '<missing id>'}"
        if not s.id:
            errors.append(f"{where}: missing id")
        elif s.id in seen:
            errors.append(f"{where}: duplicate id")
        seen.add(s.id)
        if not s.name:
            errors.append(f"{where}: missing name")
        if s.status not in STATUSES:
            errors.append(f"{where}: status {s.status!r} is not one of {', '.join(STATUSES)}")
        if not s.license:
            errors.append(f"{where}: missing licence")
        if s.verified is not None and not _is_date(s.verified):
            errors.append(f"{where}: verified must be an unquoted TOML date such as 2026-11-14")
        for bid in s.builds:
            if bid not in reg.builds:
                errors.append(f"{where}: unknown build {bid!r}")

        if s.status != "approved":
            if s.builds:
                errors.append(f"{where}: only approved sources may feed builds (status is {s.status})")
            if not s.notes:
                errors.append(f"{where}: {s.status} sources need notes saying why")
            continue

        if not s.terms_url:
            errors.append(f"{where}: approved sources need a terms_url")
        if s.verified is None:
            errors.append(f"{where}: approved sources need a verified date")
        elif _is_date(s.verified):
            if s.verified > today:
                errors.append(f"{where}: verified date {s.verified} is in the future")
            elif today - s.verified > REVERIFY_AFTER:
                warnings.append(f"{where}: terms last checked {s.verified}; read them again")
        if not s.builds:
            warnings.append(f"{where}: approved but feeds no build")
        if reg.needs_notice(s.license) and s.builds and not s.attribution:
            errors.append(f"{where}: {s.license} requires an attribution notice")
        for bid in s.builds:
            b = reg.builds.get(bid)
            if b is None or b.license not in COMPATIBLE:
                continue
            if not reg.compatible(b.license, s.license):
                errors.append(f"{where}: {s.license} data can't go into build {bid} ({b.license})")
            elif (s.license != b.license and s.license in NOTICE_REQUIRED
                  and s.license not in reg.licenses
                  and not text_path(s.license, texts_dir).is_file()):
                errors.append(f"{where}: build {bid} must ship the {s.license} text, "
                              f"but {text_path(s.license, texts_dir).name} is missing")

    for bid in reg.builds:
        if not reg.feeding(bid):
            warnings.append(f"build {bid}: no approved source feeds it")
    return errors, warnings


def text_path(license_id: str, texts_dir: Path | None = None) -> Path:
    """Where the full text of ``license_id`` lives for shipping with builds."""
    return (texts_dir or TEXTS_DIR) / f"LICENSE-{license_id}.txt"


def _license_body(license_id: str, texts_dir: Path) -> str:
    """A licence text for embedding in NOTICE, minus SPDX template placeholders."""
    lines = text_path(license_id, texts_dir).read_text(encoding="utf-8").splitlines()
    kept: list[str] = []
    for ln in lines:
        if "<copyright holders>" in ln or "<year>" in ln:
            continue
        if not ln.strip() and kept and not kept[-1]:
            continue  # don't leave a double blank where a placeholder was
        kept.append(ln.rstrip())
    return "\n".join(kept).strip()


def notice_text(reg: Registry, build_id: str | None = None,
                texts_dir: Path = TEXTS_DIR) -> str:
    """Third-party notices for one build, or for every build when build_id is None."""
    build_ids = [build_id] if build_id else list(reg.builds)
    title = "ProjectBlacklist: third-party notices"
    out = [title, "=" * len(title), "",
           "Generated from licensing/sources.toml by `python -m licensing sync`.",
           "Do not edit by hand.", "", SUSPECTED_LINE, ""]
    embed: list[str] = []
    for bid in build_ids:
        b = reg.builds[bid]
        heading = f"Build: {bid} ({b.license})"
        out += [heading, "-" * len(heading), b.description, ""]
        for s in reg.feeding(bid):
            out.append(f"* {s.name} ({s.license}), {s.homepage}")
            out += [f"  {ln}" if ln.strip() else "" for ln in s.attribution.splitlines()]
            out += [f"  Condition: {c}" for c in s.conditions]
            out += [f"  Requested: {q}" for q in s.requests]
            out.append("")
            if s.license in NOTICE_REQUIRED and s.license != b.license and s.license not in embed:
                embed.append(s.license)
    for lic in embed:
        heading = f"{lic} licence text"
        out += [heading, "-" * len(heading), "", _license_body(lic, texts_dir), ""]
    return "\n".join(out).rstrip() + "\n"


def header_lines(reg: Registry, build_id: str) -> list[str]:
    """Comment lines (without the comment prefix) every published list must start with."""
    b = reg.builds[build_id]
    sources = "; ".join(f"{s.name} ({s.license})" for s in reg.feeding(build_id))
    return [
        f"License: {b.license} ({LICENSE_URLS.get(b.license, 'see LICENSE')})",
        f"Sources: {sources}",
        SUSPECTED_LINE,
        "Licence and third-party notices: see LICENSE and NOTICE next to this file.",
    ]


def stage(reg: Registry, build_id: str, outdir: Path, *,
          texts_dir: Path = TEXTS_DIR, today: dt.date | None = None) -> list[str]:
    """Write LICENSE and NOTICE for a build into outdir and return its header lines.

    Refuses to stage anything while the registry has errors, so a build can't
    be published with data its licence can't carry.
    """
    if build_id not in reg.builds:
        raise KeyError(f"unknown build {build_id!r}")
    errors, _ = check(reg, today=today, texts_dir=texts_dir)
    if errors:
        raise ValueError("licensing check failed:\n  " + "\n  ".join(errors))
    b = reg.builds[build_id]
    outdir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(text_path(b.license, texts_dir), outdir / "LICENSE")
    (outdir / "NOTICE").write_text(notice_text(reg, build_id, texts_dir), encoding="utf-8")
    return header_lines(reg, build_id)


def _md(text: str) -> str:
    return text.replace("|", "\\|")


def sources_table(reg: Registry) -> str:
    rows = ["| Source | Status | Licence | Feeds | Notes |", "| --- | --- | --- | --- | --- |"]
    order = {status: i for i, status in enumerate(STATUSES)}
    for s in sorted(reg.sources, key=lambda s: (order.get(s.status, 99), s.name.lower())):
        name = f"[{_md(s.name)}]({s.homepage})" if s.homepage else _md(s.name)
        feeds = ", ".join(f"`{b}`" for b in s.builds) or "none"
        rows.append(f"| {name} | {s.status} | `{s.license}` | {feeds} | {_md(s.notes)} |")
    return "\n".join(rows)


def _doc_with_table(doc: str, table: str) -> str:
    start, end = doc.find(TABLE_START), doc.find(TABLE_END)
    if start == -1 or end == -1 or end < start:
        raise ValueError(f"LICENSING.md needs {TABLE_START} and {TABLE_END} markers")
    return doc[: start + len(TABLE_START)] + "\n" + table + "\n" + doc[end:]


def _derived(reg: Registry, texts_dir: Path, notice_path: Path, doc_path: Path) -> dict[Path, str]:
    return {
        notice_path: notice_text(reg, None, texts_dir),
        doc_path: _doc_with_table(doc_path.read_text(encoding="utf-8"), sources_table(reg)),
    }


def stale_files(reg: Registry, *, texts_dir: Path = TEXTS_DIR,
                notice_path: Path = NOTICE_PATH, doc_path: Path = LICENSING_DOC) -> list[Path]:
    """Derived files that don't match what ``sync`` would write."""
    stale = []
    for path, want in _derived(reg, texts_dir, notice_path, doc_path).items():
        if not path.is_file() or path.read_text(encoding="utf-8") != want:
            stale.append(path)
    return stale


def sync(reg: Registry, *, texts_dir: Path = TEXTS_DIR,
         notice_path: Path = NOTICE_PATH, doc_path: Path = LICENSING_DOC) -> list[Path]:
    """Rewrite NOTICE and the LICENSING.md source table. Returns the files changed."""
    changed = []
    for path, want in _derived(reg, texts_dir, notice_path, doc_path).items():
        if not path.is_file() or path.read_text(encoding="utf-8") != want:
            path.write_text(want, encoding="utf-8")
            changed.append(path)
    return changed
