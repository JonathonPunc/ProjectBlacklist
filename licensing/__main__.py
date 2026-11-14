"""Command line: python -m licensing {check,sync,stage}."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import registry


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m licensing", description="Manage ProjectBlacklist licensing.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    chk = sub.add_parser("check", help="validate the source registry and derived files")
    chk.add_argument("--strict", action="store_true", help="treat warnings as errors")
    sub.add_parser("sync", help="regenerate NOTICE and the source table in LICENSING.md")
    stg = sub.add_parser("stage", help="write a build's LICENSE and NOTICE into a directory and print its header lines")
    stg.add_argument("build", help="build id, e.g. complement")
    stg.add_argument("outdir", type=Path, help="the build's output directory")
    args = parser.parse_args(argv)

    reg = registry.load()

    if args.cmd == "check":
        errors, warnings = registry.check(reg)
        errors += [f"{p.relative_to(registry.ROOT)} is out of date; run `python -m licensing sync`"
                   for p in registry.stale_files(reg)]
        for w in warnings:
            print(f"warning: {w}")
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        failed = bool(errors) or (args.strict and bool(warnings))
        print(f"licensing check {'FAILED' if failed else 'ok'}: "
              f"{len(reg.sources)} sources, {len(reg.builds)} builds, "
              f"{len(errors)} errors, {len(warnings)} warnings")
        return 1 if failed else 0

    if args.cmd == "sync":
        errors, _ = registry.check(reg)
        if errors:
            for e in errors:
                print(f"error: {e}", file=sys.stderr)
            print("not syncing until the registry is valid", file=sys.stderr)
            return 1
        changed = registry.sync(reg)
        for p in changed:
            print(f"wrote {p.relative_to(registry.ROOT)}")
        if not changed:
            print("already in sync")
        return 0

    if args.cmd == "stage":
        try:
            lines = registry.stage(reg, args.build, args.outdir)
        except (KeyError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print("\n".join(lines))
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
