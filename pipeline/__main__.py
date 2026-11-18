"""Command line:

    python -m pipeline build [--builds complement,early-warning,all-in-one]
    python -m pipeline lookup --dist dist (example.com | --issue-body FILE)
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .build import Builder, annotations, summary
from .fetch import http_get

ROOT = Path(__file__).resolve().parent.parent


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m pipeline", description="Build the ProjectBlacklist lists.")
    sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="fetch sources and write the lists into the dist directory")
    b.add_argument("--builds", default="complement",
                   help="comma-separated builds to write (default: complement)")
    b.add_argument("--dist", type=Path, default=ROOT / "dist", help="output directory (the dist branch)")
    b.add_argument("--cache", type=Path, default=ROOT / ".cache",
                   help="private cache for reference data (never published)")
    b.add_argument("--seen", type=Path, default=None,
                   help="private directory for the early-warning memory of domains already seen "
                        "(optional; without it, page checks are ordered by time only)")
    b.add_argument("--allow-swing", action="store_true",
                   help="publish even if a build changed size more than the gate allows")
    lk = sub.add_parser("lookup", help="say which lists and sources contain a host")
    lk.add_argument("domain", nargs="?", help="host to look up")
    lk.add_argument("--issue-body", type=Path, help="read the host from an issue's text instead")
    lk.add_argument("--dist", type=Path, default=ROOT / "dist", help="checked-out dist branch")
    lk.add_argument("--kind", choices=("false-positive", "missed"), default="false-positive",
                    help="wrongly blocked site, or a site we should block")
    args = p.parse_args(argv)

    if args.cmd == "lookup":
        from .lookup import extract_domain, lookup
        text = args.issue_body.read_text(encoding="utf-8") if args.issue_body else (args.domain or "")
        host = extract_domain(text)
        if not host:
            print("I couldn't find a domain name in this report. Please edit it to put the domain "
                  "(for example `login.example.com`) in the Domain field.")
            return 2
        print(lookup(host, dist=args.dist, repo=ROOT, kind=args.kind), end="")
        return 0

    builds = [x.strip() for x in args.builds.split(",") if x.strip()]
    try:
        report = Builder(repo=ROOT, dist=args.dist, cache=args.cache, get=http_get,
                         allow_swing=args.allow_swing, seen=args.seen).run(builds)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    text = summary(report)
    print(text)
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print("\n".join(annotations(report)))
    step = os.environ.get("GITHUB_STEP_SUMMARY")
    if step:
        with open(step, "a", encoding="utf-8") as f:
            f.write(text)
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
