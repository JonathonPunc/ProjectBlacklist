# Licensing

ProjectBlacklist uses three licences, one for each kind of thing it publishes.

| What | Licence | Text | Why |
| --- | --- | --- | --- |
| Code, docs and config in this repo | MIT | [`LICENSE`](LICENSE) | It's all ours, so the most permissive common licence. |
| `complement` list, our own data under `data/`, and the source registry | CC0 1.0 (public domain) | [`LICENSES/CC0-1.0.txt`](LICENSES/CC0-1.0.txt) | A security list does the most good when anyone can use it, commercial resolvers and firewall vendors included, with no paperwork. |
| `all-in-one` list | GPL-3.0-only | [`licensing/texts/LICENSE-GPL-3.0-only.txt`](licensing/texts/LICENSE-GPL-3.0-only.txt) | It includes HaGeZi TIF, which is GPL-3.0, so the combined list has to be GPL-3.0 too. |

The built lists live on the `dist` branch. Each build directory carries its own
`LICENSE` and `NOTICE`, written by the pipeline from the texts in
[`licensing/texts/`](licensing/texts/), so a copied file never travels without
its terms. `LICENSES/` holds only the licences of files in this repo.
[`REUSE.toml`](REUSE.toml) is the machine-readable version of the table above,
and CI runs `reuse lint` to keep it accurate.

## What can go into each build

A source's licence decides which builds it can feed:

- **`complement` (CC0)** takes only public-domain data: CC0, Unlicense, PDDL,
  and our own entries. Anything with an attribution, notice or share-alike
  condition can't go in, because CC0 promises users there are no conditions.
- **`all-in-one` (GPL-3.0)** also takes GPL-compatible licences: MIT, BSD, ISC,
  Apache-2.0, CC BY 4.0, CC BY-SA 4.0 and GPL-3.0. Each one's notice is copied
  into `NOTICE`.
- **Non-commercial, no-derivatives and "no redistribution" terms go in
  neither.** That's why URLhaus and OpenPhish are excluded.

These rules live in code (`licensing/registry.py`), and CI runs
`python -m licensing check` on every push. A source in the wrong build, a
missing attribution, or a NOTICE that has drifted from the registry fails the
check, and the pipeline's `stage` step refuses to publish while it fails.

## Respecting list maintainers

We use other people's lists, so we go beyond what their licences require:

- **Credit every source**, including the ones whose licence doesn't ask for it.
  Every list header names its sources, and `NOTICE` credits each one.
- **Honour their requests.** Anything a maintainer asks for that their licence
  doesn't require (fetch cadence, where false positives should go) is recorded
  as `requests` in the registry and printed in `NOTICE`.
- **Send false positives upstream.** If an entry came from someone else's list,
  we report it to them as well as removing it here.
- **Fetch politely.** Never more often than a list says it changes, and always
  with a User-Agent that links back to this repository.
- **Stop when asked.** If a maintainer asks us not to use their list, we remove
  it, even if the licence would let us keep it.

## Every list says "suspected"

Every published list and `NOTICE` says that entries are *suspected* malicious
or phishing hosts, not confirmed verdicts. phishunt's terms require this for
its data, and it's true of every feed we use. Keep the same wording on any
website or lookup page built on these lists.

## Sources

The registry, [`licensing/sources.toml`](licensing/sources.toml), is the source
of truth. This table is generated from it: edit the registry, then run
`python -m licensing sync`.

<!-- sources:start -->
| Source | Status | Licence | Feeds | Notes |
| --- | --- | --- | --- | --- |
| [CERT Polska Warning List](https://cert.pl/en/warning-list/) | approved | `LicenseRef-CERT-PL-Data-Usage-Policy` | `complement`, `all-in-one` | Government-run (NASK-PIB) list, mostly Polish-targeted phishing but it also catches global brands. Entries expire after 6 months upstream. hole.cert.pl was often unreachable on 2026-11-14, so the pipeline keeps its last good copy. |
| [HaGeZi Threat Intelligence Feeds](https://github.com/hagezi/dns-blocklists) | approved | `GPL-3.0-only` | `all-in-one` | HaGeZi states GPL-3.0 without an 'or later' grant, so we treat it as GPL-3.0-only. This is what forces the all-in-one build to be GPL-3.0. |
| [PhishDestroy Destroylist (primary)](https://github.com/phishdestroy/destroylist) | approved | `MIT` | `all-in-one` | Domains PhishDestroy finds with its own parsers and reports to registrars before listing. Broader than phishing alone (crypto and investment scams too) and aggressive: on 2026-11-17, 532 of 231,195 entries were Tranco top-1M sites, including maya.ph, kasserver.com and antispamcloud.com. The feed therefore gets the strict top-1M popular-site check (pipeline/feeds.py). |
| [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database) | approved | `MIT` | `all-in-one` | MIT requires its copyright and permission notice in copies, so this source can't go into the CC0 build. Caveat: Phishing.Database does not list its upstream feeds, so we rely on its MIT grant as published. |
| [phishunt.io](https://phishunt.io/) | approved | `CC0-1.0` | `complement`, `all-in-one` | ToS section 7 releases the feed data under CC0 1.0; attribution is appreciated but not required. phishunt itself aggregates Certificate Transparency logs and third-party feeds. |
| [ProjectBlacklist curated data](https://github.com/JonathonPunc/ProjectBlacklist) | approved | `CC0-1.0` | `complement`, `all-in-one` | Entries and allowlist decisions kept in this repository under data/. Contributions are accepted under CC0-1.0 (see CONTRIBUTING.md). |
| [ProjectBlacklist early-warning detector](https://github.com/JonathonPunc/ProjectBlacklist) | approved | `CC0-1.0` | `early-warning` | Our own judgements (pipeline/early.py) about hostnames in public Certificate Transparency logs, released under CC0-1.0. The logs publish certificates so that anyone can monitor them; neither the Let's Encrypt CT page nor the static CT API spec sets usage terms, rate limits or licence conditions for readers (checked 2026-11-15). Borderline hosts' home pages are fetched once or a few times to look for a login form. |
| [PhishTank](https://phishtank.org/) | pending | `LicenseRef-Unclear` | none | The dump downloads without a key, but new accounts have been closed since 2020. The site footer cites CC BY-SA 2.5 and we found no data-specific terms (the terms-of-use URL redirects to the home page). Share-alike data can't go into the CC0 build. Next step: ask Cisco Talos, which runs PhishTank, in writing. |
| [malware-filter urlhaus-filter](https://gitlab.com/malware-filter/urlhaus-filter) | excluded | `CC0-1.0` | none | Labelled CC0 and MIT, but it is built from the URLhaus database dump, whose terms forbid derivative works without consent. A downstream label can't grant rights the upstream never gave. |
| [oisd big](https://oisd.nl/) | excluded | `GPL-3.0-only` | none | The licence is fine (GPL-3.0), but this is an ad and tracker list: 397 of its entries are Tranco top-10k sites such as googlesyndication.com. Out of scope for a malware and phishing list. |
| [OpenPhish community feed](https://openphish.com/) | excluded | `LicenseRef-OpenPhish-Terms` | none | Terms forbid use for detection, threat intelligence or customer protection without prior written consent. That bars using it even only to corroborate entries, not just redistributing it. |
| [The Block List Project: phishing](https://github.com/blocklistproject/Lists) | excluded | `Unlicense` | none | The licence is fine (public domain), but it blocked 0.1% of live phishing in our 2026-11-14 measurement, so it isn't worth its false positives. |
| [URLhaus (abuse.ch)](https://urlhaus.abuse.ch/) | excluded | `LicenseRef-abusech-Terms` | none | Needs a free Auth-Key; the terms allow not-for-profit use only (section 3.1) and forbid derivative works without express consent (section 7.3). Unauthenticated downloads now return 410 Gone. Reconsider only with written consent from abuse.ch. |
| [Public Suffix List](https://publicsuffix.org/) | internal | `MPL-2.0` | none | Used to find registrable domains and shared-hosting suffixes; fetched at build time and never shipped. If it is ever vendored into this repo, keep it unmodified: MPL-2.0 is file-level copyleft. |
| [Tranco top sites list](https://tranco-list.eu/) | internal | `LicenseRef-Tranco` | none | Used only as an allowlist guard; never shipped. Built from Cisco Umbrella, Majestic (CC BY 3.0), Farsight, CrUX (CC BY-SA 4.0) and Cloudflare Radar (CC BY-NC 4.0). Because of the non-commercial component, revisit this if the project ever becomes commercial. |
<!-- sources:end -->

## Custom terms

Some sources publish their own terms instead of a standard licence. Those are
declared under `[licenses]` in the registry with a `LicenseRef-` id, a summary,
and the build licences they can go into. CERT Polska's data usage policy is one:
it allows any use and doesn't require attribution, so it can go into the CC0
build, as long as we never imply that CERT Polska endorses this project.

## Adding or changing a source

1. Read both the licence **and** the terms of use. They can disagree: phishunt
   is CC0, yet its terms still say how to describe the data, and
   urlhaus-filter is labelled CC0 but built from data whose terms forbid that.
2. Add an entry to `licensing/sources.toml` with `status`, an SPDX `license`
   (or `LicenseRef-*` for custom terms), `terms_url`, today's `verified` date,
   `attribution` for any licence that requires a notice, and `conditions` for
   any obligations in the terms.
3. Only `approved` sources may list `builds`. If the terms are unclear, mark it
   `pending` and say what's missing in `notes`.
4. Run `python -m licensing sync`, then `python -m licensing check`.

Terms change (abuse.ch's did in 2025), so `check` warns once a source's
`verified` date is a year old. Read the terms again and update the date.

## Open items

- **abuse.ch (URLhaus):** ask for written consent to include URLhaus data in a
  free public list. Their terms forbid derivative works without it. Contact:
  https://www.spamhaus.com/abuse-ch/#contact-us
- **PhishTank (Cisco Talos):** ask which licence covers the data dumps. The FAQ
  allows commercial and non-commercial use of the API but says nothing about
  redistribution, and the site footer cites CC BY-SA 2.5, which would rule out
  the CC0 build. Contact: https://phishtank.org/contact.php

Keep any consent you receive somewhere permanent (not in this public repo), and
note it in the source's `notes` with the date and who granted it.
- **Phishing.Database** doesn't say which feeds it pulls from. We rely on its
  MIT grant as published.

This is a good-faith reading of each source's published terms, not legal
advice. If the project ever earns money, or a company wants to license the
data formally, have a lawyer check the sources first.
