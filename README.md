# ProjectBlacklist

Fast, carefully filtered DNS blocklists of suspected phishing and malware
hosts, for Pi-hole, AdGuard Home, uBlock Origin, dnsmasq, Unbound and any
resolver that takes a Response Policy Zone.

Entries are **suspected** malicious or phishing hosts, not confirmed verdicts.
If something you trust is blocked, [open an issue](https://github.com/JonathonPunc/ProjectBlacklist/issues).

## Which list?

| List | What's in it | Rebuilt | Licence |
| --- | --- | --- | --- |
| **complement** | Fresh feeds only (phishunt, CERT Polska, our own entries). Small and quick to refresh. Meant to run *alongside* [HaGeZi TIF](https://github.com/hagezi/dns-blocklists). | every 30 minutes | CC0 (public domain) |
| **all-in-one** | complement plus HaGeZi TIF and Phishing.Database, for one URL that covers it all. Large (~1.5 million entries), so Adblock, hosts and plain-domain formats only. | every 8 hours | GPL-3.0 |

Use **complement** if you already run HaGeZi TIF, or want something light.
Use **all-in-one** if you want a single list.

## URLs

These are the complement URLs. For the bigger list, replace `complement` with
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
  days after they were last reported.
- **Sources are fetched politely,** never more often than their maintainers ask.

## Licensing

Code is MIT. The complement list and our own data are CC0. The all-in-one list
is GPL-3.0 because it includes HaGeZi's GPL-3.0 list. Every built list carries
its own `LICENSE` and `NOTICE`. See [LICENSING.md](LICENSING.md) for which
sources are used, which aren't, and why.

## Development

Python 3.12, standard library only.

```
python -m unittest discover -s tests -v                 # tests (no network)
python -m licensing check                               # licence rules
python -m pipeline build --builds complement --dist /tmp/dist --cache /tmp/cache
python scripts/coverage.py --list /tmp/dist/complement/abp.txt --urls held-out.txt
```

See [CONTRIBUTING.md](CONTRIBUTING.md) before sending entries or code.
