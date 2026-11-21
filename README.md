# ProjectBlacklist

Fast, carefully filtered DNS blocklists of suspected phishing and malware
hosts, for Pi-hole, AdGuard Home, uBlock Origin, dnsmasq, Unbound and any
resolver that takes a Response Policy Zone.

Entries are **suspected** malicious or phishing hosts, not confirmed verdicts.
If something you trust is blocked, [report it](https://github.com/JonathonPunc/ProjectBlacklist/issues/new?template=false-positive.yml):
a bot replies within minutes with where the entry came from, and an unblock is
published within minutes of a maintainer adding it to the allowlist.

## Which list?

| List | What's in it | Rebuilt | Licence |
| --- | --- | --- | --- |
| **complement** | Fresh feeds only (phishunt, CERT Polska, our own entries). Small and quick to refresh. Meant to run *alongside* [HaGeZi TIF](https://github.com/hagezi/dns-blocklists). | hourly | CC0 (public domain) |
| **all-in-one** | complement plus HaGeZi TIF, PhishDestroy's Destroylist and Phishing.Database, for one URL that covers it all. Large (~1.7 million entries), so Adblock, hosts and plain-domain formats only. | every 8 hours | GPL-3.0 |
| **early-warning** *(experimental)* | Hosts whose brand-new TLS certificates look like a brand's login page (`paypal-login-verify.com`, `fасebook` written with Cyrillic letters), often before anyone has reported them. Expect more mistakes than the other lists. | hourly | CC0 (public domain) |

Use **complement** if you already run HaGeZi TIF, or want something light.
Use **all-in-one** if you want a single list.
Add **early-warning** on top of either if you'd rather block a few safe sites
than let new phishing through, and don't mind [reporting](https://github.com/JonathonPunc/ProjectBlacklist/issues/new?template=false-positive.yml)
the odd mistake.

> [!WARNING]
> **early-warning is experimental.** Its entries are picked automatically from
> new certificates, with no human review, and some will be legitimate sites
> (a brand's new campaign domain, a fan site, a security researcher's test
> page). Don't make it the only list on a network where a wrongly blocked site
> is costly, such as a school or a business, unless someone there can unblock
> sites quickly. Every early-warning file starts with the same warning.

## URLs

These are the complement URLs. For early-warning, replace `complement` with
`early-warning` (every format). For the bigger list, replace it with
`all-in-one` in the Adblock, hosts or plain-domain URL; those are the formats
all-in-one comes in. For dnsmasq, Unbound or RPZ, use complement together with
HaGeZi's own TIF in that format.

| Use with | URL |
| --- | --- |
| Pi-hole v6, AdGuard Home, uBlock Origin | `https://raw.githubusercontent.com/JonathonPunc/ProjectBlacklist/dist/complement/abp.txt` |
| hosts file, Pi-hole v5 | `https://raw.githubusercontent.com/JonathonPunc/ProjectBlacklist/dist/complement/hosts.txt` |
| Plain domain list | `https://raw.githubusercontent.com/JonathonPunc/ProjectBlacklist/dist/complement/domains.txt` |
| dnsmasq | `https://raw.githubusercontent.com/JonathonPunc/ProjectBlacklist/dist/complement/dnsmasq.conf` |
| Unbound | `https://raw.githubusercontent.com/JonathonPunc/ProjectBlacklist/dist/complement/unbound.conf` |
| BIND / Knot / PowerDNS (RPZ) | `https://raw.githubusercontent.com/JonathonPunc/ProjectBlacklist/dist/complement/rpz.zone` |

The Adblock, dnsmasq, Unbound and RPZ files block each listed host **and its
subdomains**. The hosts and plain-domain files match **exact names only**,
which is how Pi-hole reads plain lines, so prefer the Adblock file on Pi-hole v6.

## Setting it up

**[Step-by-step setup guide](https://jonathonpunc.github.io/ProjectBlacklist/)**: pick your list and
where you use it (Pi-hole, AdGuard Home, Brave, uBlock Origin, AdGuard, pfSense, OPNsense,
Technitium, dnsmasq, Unbound, BIND and more) and it shows the exact steps and URLs, plus
optional ad and adult-content lists. The short version:

- **Pi-hole v6:** add the Adblock URL under *Lists*, then run `pihole -g`.
  Pi-hole only refreshes its lists once a week by default, which is too slow
  for phishing. Refresh more often with a cron job, e.g. every 6 hours:
  `0 */6 * * * pihole -g`.
- **AdGuard Home:** *Filters → DNS blocklists → Add blocklist → Add a custom
  list*, paste the Adblock URL, and set the filter update interval to 1 hour.
- **uBlock Origin:** *Dashboard → Filter lists → Import*, paste the Adblock URL.
- **dnsmasq / Unbound / RPZ:** download the file on a schedule (e.g. `curl`
  from cron) and include it in your config. The Unbound file starts its own
  `server:` clause, so it can be included anywhere.

## Ads, trackers and adult content

These lists are about phishing and malware only. Blocking ads or adult content
is a household choice rather than a safety one, and good lists for both already
exist. We link to them rather than copy them, so their maintainers keep
getting the reports and update stats they rely on:

| To block | List | URL |
| --- | --- | --- |
| Ads and trackers | HaGeZi Multi PRO | `https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt` |
| Ads and trackers | oisd big | `https://big.oisd.nl` |
| Adult content | HaGeZi NSFW | `https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nsfw.txt` |
| Adult content | oisd nsfw | `https://nsfw.oisd.nl` |

All four are Adblock-format and work in Pi-hole v6, AdGuard Home and uBlock
Origin. Each project offers other formats too; see
[HaGeZi](https://github.com/hagezi/dns-blocklists) and [oisd](https://oisd.nl).
DNS blocking works per site, so adult-content lists can't filter mixed sites
such as Reddit or X without blocking them entirely.

## How the early-warning list works

> [!WARNING]
> Experimental: see the warning under [Which list?](#which-list) before using it.

Every publicly trusted TLS certificate is published in
[Certificate Transparency](https://certificate.transparency.dev/) logs within
minutes of being issued, and a phishing site needs one before it can show the
padlock. Every hour we read the hostnames from the certificates Let's
Encrypt issued since the last run (about 1.8 million) and score each one
([`pipeline/lookalike.py`](pipeline/lookalike.py)) for looking like one of the
brands in [`data/brands.toml`](data/brands.toml):

- the brand's name, even disguised (`paypa1`, `pay-pal`, Cyrillic look-alike
  letters) or with one typo (`micros0ft`, `netfiix`);
- the brand's real domain carried inside another name
  (`paypal.com.account-check.top`);
- words phishing names use (`login`, `verify`, `wallet`, `refund`), and
  top-level domains with far-above-average abuse.

Names that score high are listed straight away. Borderline ones get their home
page checked, now and over the next day, and are listed only if the page asks
for a password or a secret (card number, recovery phrase) and names the brand.
Names on domains we have never seen a certificate for (most likely just
registered) are checked first; the detector remembers every domain it has seen
for at least 60 days, privately, and uses that only to order the checks.
Hosts on a brand's own domains, popular sites and the allowlist are never
listed. Entries stay for 14 days.

Each run also records when an early-warning host later shows up in one of the
other feeds, and how many hours earlier we had it; the numbers are in each
run's summary. A host that never shows up there isn't necessarily a mistake,
because those feeds miss plenty, so it's a lower bound on how often we're right.

## How it's built

A scheduled GitHub Action ([`publish.yml`](.github/workflows/publish.yml))
fetches the sources, filters them, and force-pushes the result to the `dist`
branch. Pushing build changes to any other branch runs a trial build against the
live sources and publishes nothing. Before anything is published:

- **Shared platforms stay safe.** The [Public Suffix List](https://publicsuffix.org/)
  identifies platforms such as `pages.dev` or `github.io`. A phishing site at
  `evil.pages.dev` is blocked, never `pages.dev` itself.
- **Popular sites are protected.** Hosts on the [Tranco](https://tranco-list.eu/)
  top 10,000 sites are dropped. Unvetted live feeds are held to the top million.
- **An allowlist is enforced.** [`data/allow.txt`](data/allow.txt) names things
  that must never be blocked (OS updates, connectivity checks, DNS resolvers,
  where these lists are served from). Every file is checked against it.
- **Sanity gates stop bad builds.** A source that returns an error page, or whose
  size jumps or collapses, is set aside and its last good copy used instead. A
  build that changes by more than 30% isn't published.
- **Stale entries expire.** Hosts from the live phishunt feed are kept for 14
  days after they were last reported; early-warning hosts for 14 days.
- **Sources are fetched politely,** never more often than their maintainers ask.

## Licensing

Code is MIT. The complement and early-warning lists and our own data are CC0. The all-in-one list
is GPL-3.0 because it includes HaGeZi's GPL-3.0 list. Every built list carries
its own `LICENSE` and `NOTICE`. See [LICENSING.md](LICENSING.md) for which
sources are used, which aren't, and why.

## Development

Python 3.12, standard library only.

```
python -m unittest discover -s tests -v                 # tests (no network)
python -m licensing check                               # licence rules
python -m pipeline build --builds complement,early-warning --dist /tmp/dist --cache /tmp/cache
python -m pipeline lookup --dist /tmp/dist example.com  # which list and source has it
python scripts/coverage.py --list /tmp/dist/complement/abp.txt --urls held-out.txt
```

See [CONTRIBUTING.md](CONTRIBUTING.md) before sending entries or code.
