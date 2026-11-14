"""Command line: python -m pipeline build [--builds complement,all-in-one]."""

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
    b.add_argument("--allow-swing", action="store_true",
                   help="publish even if a build changed size more than the gate allows")
    args = p.parse_args(argv)

    builds = [x.strip() for x in args.builds.split(",") if x.strip()]
    try:
        report = Builder(repo=ROOT, dist=args.dist, cache=args.cache, get=http_get,
                         allow_swing=args.allow_swing).run(builds)
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
