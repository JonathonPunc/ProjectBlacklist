"""Score hostnames for looking like a brand's login or payment page.

Signals, all from the name alone (no network):

  brand     a distinctive brand name appears (paypal, coinbase), even
            disguised: 0->o, 1->l, rn->m, vv->w, hyphens, look-alike Unicode
  typo      a distinctive brand name with one typo (paypai, netfiix)
  word      a brand that is also an ordinary word appears as a whole word
            (chase-login, not purchased)
  embeds    the hostname carries a real brand domain it isn't on
            (paypal.com.secure-check.top, login-microsoftonline-com.xyz)
  keyword   words phishing names use: login, verify, wallet, refund
  tld       a top-level domain with far-above-average abuse

Hosts on a domain a brand owns are never scored. Brands, keywords and TLDs
live in data/brands.toml.
"""

from __future__ import annotations

import re
import tomllib
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

from .hosts import PublicSuffixList

FLAG = 4          # publish at this score or above
SCORES = {"brand": 3, "typo": 3, "word": 1, "embeds": 2, "idn": 1, "tld": 1}
MAX_KEYWORDS = 2

# Letters other scripts use to imitate Latin ones (Cyrillic, Greek, others).
_CONFUSABLE = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
    "ј": "j", "ԁ": "d", "һ": "h", "ӏ": "l", "ѕ": "s", "ԛ": "q", "ԝ": "w", "ɡ": "g",
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "τ": "t", "κ": "k", "ι": "i", "ε": "e",
    "ı": "i", "ł": "l", "ø": "o", "đ": "d", "ħ": "h", "ŀ": "l", "ß": "ss",
})
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g"})
_LEET_I = str.maketrans({"1": "i", "0": "o"})
_ALNUM = "abcdefghijklmnopqrstuvwxyz0123456789"


@dataclass(frozen=True)
class Brand:
    name: str
    strong: tuple[str, ...]
    word_start: tuple[str, ...]
    weak: tuple[str, ...]
    domains: tuple[str, ...]


@dataclass
class Score:
    host: str
    score: int = 0
    brand: str = ""
    reasons: list[str] = field(default_factory=list)

    def add(self, points: int, reason: str) -> None:
        self.score += points
        self.reasons.append(reason)


def _decode_idn(label: str) -> tuple[str, bool]:
    if not label.startswith("xn--"):
        return label, False
    try:
        text = label[4:].encode("ascii").decode("punycode")
    except (UnicodeError, ValueError):
        return label, False
    text = unicodedata.normalize("NFKD", text.lower().translate(_CONFUSABLE))
    text = "".join(c for c in text if not unicodedata.combining(c))
    return "".join(c for c in text if c in _ALNUM or c == "-"), True


SHORT = 4          # strong names this short only match at the start of a word


def _typos(word: str) -> set[str]:
    """Strings one edit away from word, keeping its first letter: swap,
    replace, insert, or delete an inner letter. Typosquats nearly always keep
    the first letter, and allowing it to change turns icloud into vcloud."""
    out = set()
    for i in range(1, len(word) + 1):
        if i < len(word) - 1:
            out.add(word[:i] + word[i + 1:])
        if i < len(word):
            for c in _ALNUM:
                out.add(word[:i] + c + word[i + 1:])
        if i < len(word) - 1:
            out.add(word[:i] + word[i + 1] + word[i] + word[i + 2:])
        for c in _ALNUM:
            out.add(word[:i] + c + word[i:])
    out.discard(word)
    return out


class Detector:
    def __init__(self, config: dict, psl: PublicSuffixList) -> None:
        self.psl = psl
        self.brands = [Brand(b["name"], tuple(b.get("strong", ())), tuple(b.get("word_start", ())),
                             tuple(b.get("weak", ())), tuple(b.get("domains", ())))
                       for b in config["brand"]]
        self.keywords = {k.replace("-", "") for k in config.get("keywords", ())}
        self.risky_tlds = set(config.get("risky_tlds", ()))
        self.tunnel_words = set(config.get("tunnel_words", ()))
        nb = sorted(config.get("not_brands", ()), key=len, reverse=True)
        self._not_brands = re.compile("|".join(map(re.escape, nb))) if nb else None
        self.owned = {d for b in self.brands for d in b.domains}
        strong = {t.replace("-", ""): b.name for b in self.brands for t in b.strong}
        self.strong = strong
        starts = {t for b in self.brands for t in b.word_start}
        self.short = {t: n for t, n in strong.items() if len(t) <= SHORT or t in starts}
        longer = [t for t in strong if t not in self.short]
        self._strong_re = re.compile("|".join(sorted(map(re.escape, longer), key=len, reverse=True)))
        self.weak = {t: b.name for b in self.brands for t in b.weak}
        self.typos: dict[str, str] = {}
        for token, brand in strong.items():
            if len(token) >= 6:
                for t in _typos(token):
                    if t not in strong and t not in self.weak and t not in self.keywords:
                        self.typos.setdefault(t, brand)
        # Real domains to look for inside other names: "paypal.com" and "paypal-com".
        embeds = {}
        for b in self.brands:
            for d in b.domains:
                embeds[d] = b.name
                embeds[d.replace(".", "-")] = b.name
        self._embed_re = re.compile(r"(?:^|[.-])(" + "|".join(
            sorted(map(re.escape, embeds), key=len, reverse=True)) + r")(?:[.-]|$)")
        self._embeds = embeds

    @classmethod
    def load(cls, path: Path, psl: PublicSuffixList) -> "Detector":
        return cls(tomllib.loads(path.read_text(encoding="utf-8")), psl)

    def _strong(self, variants: list[str], tokens: set[str]) -> str:
        for t in tokens:
            for short, brand in self.short.items():
                if t.startswith(short):
                    return brand
        for v in variants:
            m = self._strong_re.search(v)
            if m:
                return self.strong[m.group()]
            # pay-pal: the name split by hyphens. Only counts when the match
            # starts and ends on word boundaries, so kintai-cloud doesn't read
            # as icloud, nor di-scordino as discord.
            if "-" in v:
                starts, ends, pos = set(), set(), 0
                for part in v.split("-"):
                    starts.add(pos)
                    pos += len(part)
                    ends.add(pos)
                joined = v.replace("-", "")
                for m in self._strong_re.finditer(joined):
                    if m.start() in starts and m.end() in ends:
                        return self.strong[m.group()]
        return ""

    def score(self, host: str) -> Score | None:
        """Score host, or None if it sits on a domain a brand owns (or is a suffix)."""
        priv, icann = self.psl.suffixes(host)
        reg = self.psl.owner(host, icann)
        if host == priv or reg is None or reg in self.owned:
            return None
        name = host[: -len(priv) - 1]
        s = Score(host)
        labels, idn = [], False
        for label in name.split("."):
            text, was_idn = _decode_idn(label)
            labels.append(text)
            idn |= was_idn
        variants = []
        for label in labels:
            for v in {label, label.translate(_LEET), label.translate(_LEET_I),
                      label.replace("rn", "m").replace("vv", "w")}:
                variants.append(v)
        if self._not_brands:
            variants = [self._not_brands.sub("-", v) for v in variants]
        tokens = {t for v in variants for t in re.split(r"[-_]+", v) if t}
        if any(w in t for t in tokens for w in self.tunnel_words):
            s.reasons.append("VPN or proxy tunnel name, not scored")
            return s

        hit = self._strong(variants, tokens)
        if hit:
            s.add(SCORES["brand"], f"brand {hit}")
        if not hit:
            for t in tokens:
                if t in self.typos:
                    hit = self.typos[t]
                    s.add(SCORES["typo"], f"typo of {hit}")
                    break
        if not hit:
            for t in tokens:
                if t in self.weak:
                    hit = self.weak[t]
                    s.add(SCORES["word"], f"word {hit}")
                    break
        if not hit:
            return s
        s.brand = hit
        if idn:
            s.add(SCORES["idn"], "lookalike letters")
        m = self._embed_re.search(name)
        if m:
            s.add(SCORES["embeds"], f"carries {m.group(1).replace('-', '.')}")
        kws = sorted(t for t in tokens if t in self.keywords)[:MAX_KEYWORDS]
        if kws:
            s.add(len(kws), "words " + ", ".join(kws))
        # A risky TLD only adds weight to a name that already uses phishing words.
        tld = priv.rsplit(".", 1)[-1] if priv else ""
        if kws and tld in self.risky_tlds and self.psl.owner(host, priv) == reg:
            s.add(SCORES["tld"], f".{tld}")
        return s
