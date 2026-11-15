"""How the pipeline handles each source.

Licensing decides *whether* a source may feed a build (licensing/sources.toml);
this file decides *how* it is fetched and filtered. A source's URL comes from
the registry, so there is one place to change it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta


@dataclass(frozen=True)
class Feed:
    source_id: str
    fmt: str                          # urls | domains | abp | hosts (see pipeline.parse)
    kind: str                         # live | mirror | local | detector
    path: str = ""                    # local feeds: file in this repo
    # Never fetch more often than this: politeness, and maintainers' stated cadence.
    min_interval: timedelta = timedelta(hours=1)
    # live feeds: keep a host this long after the feed last listed it.
    ttl: timedelta | None = None
    # mirror feeds: if a fetch fails or isn't due, reuse the last good copy up to this age.
    max_stale: timedelta = timedelta(days=2)
    # Drop hosts on a domain ranked this high or higher in Tranco (0 = no check).
    # Shared-hosting tenants (foo.pages.dev) are never dropped by this rule.
    tranco_limit: int = 10_000
    # Reject a mirror fetch whose entry count moves more than this vs the last good one.
    swing_limit: float | None = 0.3
    # Reject a fetch where more than this share of lines don't parse (an HTML error page, say).
    max_junk: float = 0.10


FEEDS: dict[str, Feed] = {f.source_id: f for f in (
    # Our own decisions. Not checked against Tranco: a human chose each entry.
    Feed("projectblacklist", "domains", "local", path="data/block.txt", tranco_limit=0, swing_limit=None),
    # A live feed of currently suspected phishing URLs. Entries vanish from it
    # quickly, so we keep each host for 14 days after it was last listed. It is
    # unvetted, so any host on a Tranco top-1M domain is dropped.
    Feed("phishunt", "urls", "live", min_interval=timedelta(minutes=10), ttl=timedelta(days=14),
         tranco_limit=1_000_000, swing_limit=None, max_junk=0.25),
    # Curated lists that manage their own entry lifetimes: mirror them as published.
    # CERT Polska entries stay listed for 6 months upstream, so an old copy is still useful.
    Feed("cert-pl", "domains", "mirror", min_interval=timedelta(hours=1), max_stale=timedelta(days=30)),
    # HaGeZi's list header says "Expires: 8 hours".
    Feed("hagezi-tif", "abp", "mirror", min_interval=timedelta(hours=8), max_stale=timedelta(days=7)),
    Feed("phishing-database", "domains", "mirror", min_interval=timedelta(hours=8), max_stale=timedelta(days=7)),
    # Our early-warning detector (pipeline.early): brand lookalikes in new TLS
    # certificates. It manages its own 14-day lifetime. Unvetted, so it gets
    # the same top-1M popular-site check as phishunt.
    Feed("ct-lookalikes", "names", "detector", min_interval=timedelta(0),
         tranco_limit=1_000_000, swing_limit=None),
)}
