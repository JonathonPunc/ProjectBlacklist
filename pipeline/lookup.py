"""Where does a host come from? Used to answer false-positive reports.

    python -m pipeline lookup --dist dist example.com
    python -m pipeline lookup --dist dist --issue-body body.md

Reads the published lists and saved source copies on the dist branch, and
says which builds block the host, which sources list it, and where each
source's maintainers want wrong entries reported.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from licensing import registry as lic

from .feeds import FEEDS
from .hosts import ancestors, normalize
from .state import State

ISSUE_FIELD = re.compile(r"^###\s*Domain\s*$\s*(\S+)", re.I | re.M)


def extract_domain(body: str) -> str | None:
    """The domain from an issue form's "Domain" field, or the first thing in
    the text that reads as a hostname."""
    m = ISSUE_FIELD.search(body)
    if m:
        host = normalize(m.group(1))
        if host:
            return host
    for token in re.split(r"[\s<>()\[\]\"'`,]+", body):
        if "." in token:
            host = normalize(token)
            if host and not host.replace(".", "").isdigit():
                return host
    return None


def _read_list(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    out = set()
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and line[0] not in "#![":
                out.add(line.removeprefix("||").removesuffix("^"))
    return out


OWN = ("projectblacklist", "ct-lookalikes")


def lookup(host: str, *, dist: Path, repo: Path, reg: lic.Registry | None = None,
           kind: str = "false-positive") -> str:
    """Markdown answer for an issue. kind is "false-positive" (a site we block
    wrongly) or "missed" (a site someone thinks we should block)."""
    reg = reg or lic.load()
    names = [host, *ancestors(host)]
    out = [f"### Lookup for `{host}`", ""]

    allow = _read_list(repo / "data" / "allow.txt")
    hit = next((n for n in names if n in allow), None)
    if hit:
        out += [f"`{hit}` is on our allowlist (`data/allow.txt`), so none of our lists block "
                f"`{host}`. If it's still blocked, another list you use has it.", ""]

    blocked = []
    for build in reg.builds:
        exact = _read_list(dist / build / "domains.txt")
        wild = _read_list(dist / build / "abp.txt")
        if host in exact:
            blocked.append(f"**{build}** lists it")
        else:
            parent = next((n for n in names if n in wild), None)
            if parent:
                blocked.append(f"**{build}** blocks it through `{parent}` (Adblock-style lists cover subdomains)")
    out += (["Our published lists:", "", *(f"- {b}" for b in blocked), ""] if blocked
            else ["None of our published lists block it right now.", ""])

    state = State(dist)
    rows = []
    sources = {s.id: s for s in reg.sources}
    for sid, feed in FEEDS.items():
        src = sources.get(sid)
        if src is None:
            continue
        if feed.kind == "local":
            entries = _read_list(repo / feed.path)
        elif feed.kind == "live":
            entries = state.live_hosts(sid)
        elif feed.kind == "detector":
            ew = json.loads((dist / "state" / "early-warning.json").read_text(encoding="utf-8")) \
                if (dist / "state" / "early-warning.json").is_file() else {}
            flagged = ew.get("flagged", {})
            match = next((n for n in names if n in flagged), None)
            if match:
                why = "; ".join(flagged[match].get("reasons", []))
                rows.append((src, match, f"flagged by our detector: {why}"))
            continue
        else:
            snap = state.load_snapshot(sid)
            entries = snap[0] if snap else set()
        match = next((n for n in names if n in entries), None)
        if match:
            rows.append((src, match, ""))

    if kind == "missed":
        if rows:
            out += ["Sources that already list it: " + ", ".join(s.name for s, _, _ in rows) + ".", ""]
        if blocked:
            out += ["Thanks: it's already covered, so there's nothing more to do.", ""]
        else:
            out += ["It isn't in our lists yet. A maintainer will look at it; confirmed sites go "
                    "into `data/block.txt` and are published within minutes of that change.", "",
                    "Reporting it to the [Anti-Phishing Working Group](https://www.antiphishing.org/report-phishing) "
                    "also gets it to browsers and the brand being impersonated.", ""]
        out.append("<sub>Entries are suspected malicious or phishing hosts, not confirmed verdicts. "
                   "This reply was generated automatically.</sub>")
        return "\n".join(out) + "\n"

    if rows:
        out += ["Sources that list it:", "", "| Source | Entry | Where to report it |", "| --- | --- | --- |"]
        for src, match, why in rows:
            if src.id in OWN:
                where = "this issue"
            else:
                where = f"[report here]({src.report_url})" if src.report_url else "-"
            entry = f"`{match}`" + (f" ({why})" if why else "")
            out.append(f"| {src.name} | {entry} | {where} |")
        upstream = [s for s, _, _ in rows if s.id not in OWN]
        out.append("")
        if upstream:
            out.append("Its maintainers ask for reports to go to them: fixing it there fixes it "
                       "for everyone who uses their list, and our copy follows on the next update. "
                       "Please report it at the link above too.")
            out.append("")
    else:
        out += ["No source we use lists it now. If it was blocked earlier, it has since expired "
                "or been removed upstream.", ""]

    out += ["A maintainer can unblock it here straight away by adding it to `data/allow.txt`; "
            "the lists are rebuilt within minutes of that change.",
            "",
            "<sub>Entries are suspected malicious or phishing hosts, not confirmed verdicts. "
            "This reply was generated automatically.</sub>"]
    return "\n".join(out) + "\n"

