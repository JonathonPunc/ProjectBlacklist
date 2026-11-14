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

## False positives

If a site you trust is blocked, open an issue with the exact domain, the build
it appears in, and why it's legitimate. Entries are *suspected* malicious or
phishing hosts, not verdicts, and we'd rather fix a wrong one quickly.

## Before you push

```
python -m licensing check
python -m unittest discover -s tests -v
```

If you changed `licensing/sources.toml`, run `python -m licensing sync` first
so `NOTICE` and the table in `LICENSING.md` match the registry.
