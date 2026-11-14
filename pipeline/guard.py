"""Rules that stop the lists from blocking things they mustn't."""

from __future__ import annotations

from .hosts import PublicSuffixList, ancestors

REASONS = ("public-suffix", "allowlist", "popular-site")


class Guard:
    """Decides whether a host may be published.

    * A public suffix (com, co.uk, pages.dev) is never blocked: that would
      block every site under it.
    * Anything on the allowlist (data/allow.txt) is never blocked, nor is any
      parent of it, since blocking a parent blocks its subdomains too. An
      allowlisted domain also covers its own subdomains, but not the tenants of
      a shared platform beneath it: allowing amazonaws.com does not protect
      somebucket.s3.amazonaws.com.
    * A host whose domain is ranked within a feed's Tranco limit is dropped,
      unless it's a tenant of a shared platform (evil.pages.dev stays).
    """

    def __init__(self, psl: PublicSuffixList, tranco: dict[str, int], allow: set[str]) -> None:
        self.psl = psl
        self.tranco = tranco
        self.allow = set(allow)
        self._allow_parents = {p for a in self.allow for p in ancestors(a)}
        self._owner = {a: psl.registrable(a, private=True) for a in self.allow}

    def allowed(self, host: str) -> bool:
        """True if blocking host would block an allowlisted name."""
        if host in self.allow or host in self._allow_parents:
            return True
        owner = None
        for parent in ancestors(host):
            if parent in self.allow:
                if owner is None:
                    owner = self.psl.registrable(host, private=True)
                if owner == self._owner[parent]:
                    return True
        return False

    def reason(self, host: str, tranco_limit: int) -> str | None:
        """Why host must be dropped, or None if it may be published."""
        priv, icann = self.psl.suffixes(host)
        if host == priv:
            return "public-suffix"
        if self.allowed(host):
            return "allowlist"
        if tranco_limit:
            reg = self.psl.owner(host, icann)
            shared = self.psl.owner(host, priv) != reg
            rank = self.tranco.get(reg) if reg and not shared else None
            if rank is not None and rank <= tranco_limit:
                return "popular-site"
        return None


def load_tranco(csv_text: str) -> dict[str, int]:
    ranks: dict[str, int] = {}
    for line in csv_text.splitlines():
        rank, _, domain = line.strip().partition(",")
        if domain and rank.isdigit():
            ranks.setdefault(domain.lower().rstrip("."), int(rank))
    if not ranks:
        raise ValueError("Tranco list is empty or unreadable")
    return ranks
