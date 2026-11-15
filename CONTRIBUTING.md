# Contributing

Thanks for helping. Please read this first: it decides what we can accept.

## Licensing of contributions

By opening a pull request you agree that:

- **Code, docs and config** you contribute are licensed under the
  [MIT License](LICENSE).
- **List data** you contribute (new entries, allowlist or false-positive
  decisions, anything under `data/`) is dedicated to the public domain under
  [CC0 1.0](LICENSES/CC0-1.0.txt). It has to be, because that data goes into
  the CC0 `complement` build.
- You have the right to contribute it. Don't paste entries copied from another
  blocklist or feed: those come with their source's terms. To suggest a new
  source, open an issue instead and we'll check its terms (see
  [LICENSING.md](LICENSING.md)).

## Wrongly blocked and missed sites

Use the issue forms: [wrongly blocked](https://github.com/JonathonPunc/ProjectBlacklist/issues/new?template=false-positive.yml)
or [missed site](https://github.com/JonathonPunc/ProjectBlacklist/issues/new?template=missed-site.yml).
Within a few minutes a bot ([`triage.yml`](.github/workflows/triage.yml))
replies with which of our lists block the domain, which sources list it, and
where each source's maintainers take reports. Entries are *suspected*
malicious or phishing hosts, not verdicts, and we'd rather fix a wrong one
quickly.

For maintainers, handling a report:

1. **Wrongly blocked:** add the domain to [`data/allow.txt`](data/allow.txt)
   with the issue number, e.g. `shop.example.com  # issue #12: real shop`,
   and push to `main`. Any change under `data/` publishes every list within
   minutes. If the bot says the entry came from another list, report it there
   too (it links to where): that fixes it for everyone who uses that list, and
   the maintainers asked for it.
2. **Early-warning mistakes** usually mean the detector needs teaching, not
   just an allowlist entry. A brand's real domain goes in its `domains` in
   [`data/brands.toml`](data/brands.toml). An ordinary word mistaken for a brand
   (like `finance` for Binance) goes in `not_brands`.
3. **Missed site:** if you've confirmed it, add it to
   [`data/block.txt`](data/block.txt) with a reason and push to `main`. Entries
   there skip the popular-site check, so be sure.

## Before you push

```
python -m licensing check
python -m unittest discover -s tests -v
```

If you changed `licensing/sources.toml`, run `python -m licensing sync` first
so `NOTICE` and the table in `LICENSING.md` match the registry.
