"""How much of a held-out phishing feed would a built list block?

    python scripts/coverage.py --list dist/complement/abp.txt --urls held-out.txt

--urls is a file of URLs or host names from a feed the list does NOT ingest
(otherwise the result is meaningless). Check that feed's terms before using it,
and don't commit its data here.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pipeline import formats  # noqa: E402
from pipeline.hosts import classify  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--list", type=Path, required=True, help="a built list file (any of our formats)")
    p.add_argument("--urls", type=Path, required=True, help="held-out URLs or hosts, one per line")
    args = p.parse_args()

    fmt = next((f for f, name in formats.FILES.items() if args.list.name == name), None)
    if fmt is None:
        p.error(f"--list must be one of: {', '.join(formats.FILES.values())}")
    listed = formats.read_back(fmt, args.list.read_text(encoding="utf-8"))

    hosts, ips = [], 0
    for line in args.urls.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        host, kind = classify(line.split()[0])
        if host:
            hosts.append(host)
        elif kind == "ip":
            ips += 1
    if not hosts:
        p.error("no usable hosts in --urls")
    hit = sum(formats.blocks(fmt, listed, h) for h in hosts)
    print(f"{args.list}: blocks {hit} of {len(hosts)} held-out hosts ({100 * hit / len(hosts):.1f}%)")
    if ips:
        print(f"({ips} bare-IP URLs skipped: DNS lists can't block those)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
