"""Tests for the early-warning detector. No network: CT logs and pages are faked."""

from __future__ import annotations

import datetime as dt
import gzip
import json
import shutil
import struct
import tempfile
import tomllib
import unittest
from pathlib import Path

from pipeline import ct, early, pagecheck
from pipeline.build import PSL_URL, TRANCO_URL, Builder
from pipeline.fetch import FetchError
from pipeline.hosts import PublicSuffixList
from pipeline.lookalike import FLAG, Detector
from tests.test_pipeline import PSL, ROOT, T0, tranco_zip

PSL_PLUS = PSL.replace("// ===END ICANN DOMAINS===", "top\nph\ncom.ph\nme\n// ===END ICANN DOMAINS===")

CONFIG = {
    "keywords": ["login", "verify", "secure", "account", "wallet"],
    "risky_tlds": ["top"],
    "tunnel_words": ["vpn", "vless"],
    "not_brands": ["finance", "enpass", "applied"],
    "brand": [
        {"name": "PayPal", "strong": ["paypal"], "domains": ["paypal.com"]},
        {"name": "Apple", "strong": ["icloud", "appleid"], "word_start": ["icloud"], "weak": ["apple"],
         "domains": ["apple.com", "icloud.com"]},
        {"name": "Discord", "strong": ["discord"], "domains": ["discord.com"]},
        {"name": "Binance", "strong": ["binance"], "domains": ["binance.com"]},
        {"name": "Meta", "strong": ["facebook"], "domains": ["facebook.com"]},
        {"name": "DHL", "strong": ["dhl"], "domains": ["dhl.com"]},
        {"name": "Chase", "weak": ["chase"], "domains": ["chase.com"]},
        {"name": "E-ZPass", "strong": ["ezpass"], "domains": []},
    ],
}


def detector() -> Detector:
    return Detector(CONFIG, PublicSuffixList(PSL_PLUS))


class Lookalike(unittest.TestCase):
    def setUp(self) -> None:
        self.d = detector()

    def score(self, host: str) -> int:
        s = self.d.score(host)
        return s.score if s else -1

    def test_flags_brand_with_phishing_words(self) -> None:
        self.assertGreaterEqual(self.score("paypal-login-verify.com"), FLAG)
        self.assertGreaterEqual(self.score("pay-pal-secure.pages.dev"), FLAG)     # split by a hyphen
        self.assertGreaterEqual(self.score("paypal.com.account-check.top"), FLAG)  # carries the real domain
        self.assertGreaterEqual(self.score("paypa1-login.com"), FLAG)             # 1 for l
        self.assertGreaterEqual(self.score("paypai-login.com"), FLAG)             # typo
        self.assertGreaterEqual(self.score("chase-secure-login.top"), FLAG)       # weak word + evidence

    def test_brand_alone_is_borderline_not_flagged(self) -> None:
        self.assertEqual(self.score("paypal-shop.com"), FLAG - 1)
        self.assertLess(self.score("chase-login.com"), FLAG)

    def test_real_brand_domains_never_scored(self) -> None:
        self.assertIsNone(self.d.score("paypal.com"))
        self.assertIsNone(self.d.score("login.paypal.com"))
        self.assertIsNone(self.d.score("pages.dev"))

    def test_ordinary_words_are_not_brands(self) -> None:
        for host in ("purchased.com", "kintai-cloud.com", "multicloud.com", "di-scordino.com",
                     "finance-login.com", "enpass-login.com", "applied-login.com", "adhlabs.com",
                     "vcloud-login.com"):
            self.assertLess(self.score(host), FLAG - 1, host)

    def test_lookalike_unicode(self) -> None:
        # "fасebook" with a Cyrillic а and с
        host = "fасebook".encode("idna").decode("ascii") + ".ph"
        s = self.d.score(host)
        self.assertIsNotNone(s)
        self.assertGreaterEqual(s.score, FLAG)
        self.assertIn("lookalike letters", s.reasons)

    def test_vpn_tunnel_names_not_scored(self) -> None:
        self.assertEqual(self.score("graph.facebook.com.vlesscf.top"), 0)

    def test_real_config_loads(self) -> None:
        d = Detector.load(ROOT / "data" / "brands.toml", PublicSuffixList(PSL_PLUS))
        self.assertGreater(len(d.brands), 20)
        self.assertGreaterEqual(d.score("paypal-login-verify.com").score, FLAG)


# ---------------------------------------------------------------- CT ---

def leaf(names: list[str], ts: int = 1) -> bytes:
    """A precert TileLeaf whose TBS holds a subjectAltName with these names."""
    gn = b"".join(b"\x82" + bytes([len(n)]) + n.encode() for n in names)
    seq = b"\x30" + bytes([len(gn)]) + gn
    ext = ct.SAN_OID + b"\x04" + bytes([len(seq)]) + seq
    tbs = b"\x30\x00" + ext
    out = struct.pack(">QH", ts, 1) + b"\x00" * 32
    out += len(tbs).to_bytes(3, "big") + tbs + b"\x00\x00"           # TBS, no extensions
    out += (3).to_bytes(3, "big") + b"abc" + b"\x00\x00"             # pre-certificate, empty chain
    return out


class CT(unittest.TestCase):
    def test_tile_path(self) -> None:
        self.assertEqual(ct.tile_path(1234067), "x001/x234/067")
        self.assertEqual(ct.tile_path(5), "005")
        self.assertEqual(ct.tile_path(1000), "x001/000")

    def test_data_tile(self) -> None:
        data = leaf(["a.example.com", "*.b.example.com"], 7) + leaf(["c.example.org"], 8)
        self.assertEqual(list(ct.tile_entries(data)),
                         [(7, ["a.example.com", "*.b.example.com"]), (8, ["c.example.org"])])

    def test_names_tile(self) -> None:
        rows = [{"Timestamp": 5, "Subject": {"CommonName": "x.com"}, "DNS": ["x.com", "www.x.com"]},
                {"Timestamp": 6, "Subject": {"CommonName": "only-cn.com"}}]
        data = "\n".join(json.dumps(r) for r in rows).encode()
        self.assertEqual(list(ct.names_entries(data)), [(5, ["x.com", "www.x.com"]), (6, ["only-cn.com"])])

    def test_checkpoint(self) -> None:
        self.assertEqual(ct.checkpoint_size("log.example/2027h1\n1234\nhash=\n\n— sig\n"), 1234)
        with self.assertRaises(ValueError):
            ct.checkpoint_size("<html>")


# ---------------------------------------------------------- pagecheck ---

class PageCheck(unittest.TestCase):
    owned = staticmethod(lambda h: h.endswith("paypal.com"))

    def test_login_form_naming_brand(self) -> None:
        page = pagecheck.Page("x.top", '<title>PayPal: Log in</title><input type="password" name=p>')
        self.assertEqual(pagecheck.verdict(page, ["paypal"], self.owned)[0], "phish")

    def test_secret_phrase(self) -> None:
        page = pagecheck.Page("x.top", "<p>Enter your MetaMask secret recovery phrase</p>")
        self.assertEqual(pagecheck.verdict(page, ["metamask"], self.owned)[0], "phish")

    def test_redirect_to_real_brand(self) -> None:
        page = pagecheck.Page("www.paypal.com", "")
        self.assertEqual(pagecheck.verdict(page, ["paypal"], self.owned)[0], "brand-site")

    def test_needs_both_signals(self) -> None:
        self.assertEqual(pagecheck.verdict(pagecheck.Page("x.top", "<p>PayPal accepted here</p>"),
                                           ["paypal"], self.owned)[0], "none")
        self.assertEqual(pagecheck.verdict(pagecheck.Page("x.top", '<input type="password">'),
                                           ["paypal"], self.owned)[0], "none")


# -------------------------------------------------------------- early ---

LOG_URL = "https://mon.example-ct.test/2027h1"


def log_list(desc: str = "Let's Encrypt Willow2027h1") -> bytes:
    return json.dumps({"operators": [{"name": "Let's Encrypt", "tiled_logs": [{
        "description": desc, "monitoring_url": LOG_URL + "/", "state": {"usable": {}},
        "temporal_interval": {"start_inclusive": "2026-12-16T00:00:00Z",
                              "end_exclusive": "2027-06-17T00:00:00Z"}}]}]}).encode()


def names_tile(names_per_entry: list[list[str]]) -> bytes:
    lines = [json.dumps({"Timestamp": 1, "DNS": ns}) for ns in names_per_entry]
    lines += [json.dumps({"Timestamp": 1, "DNS": ["filler.example.com"]})] * (ct.TILE - len(lines))
    return gzip.compress("\n".join(lines).encode())


class FakeCT:
    def __init__(self) -> None:
        self.size = 2 * ct.TILE + 10
        self.tiles: dict[int, bytes] = {}
        self.pages: dict[str, pagecheck.Page | None] = {}
        self.calls: list[str] = []
        self.page_calls: list[str] = []

    def get(self, u: str) -> bytes:
        self.calls.append(u)
        if u == early.LOG_LIST_URL:
            return log_list()
        if u == PSL_URL:
            return PSL_PLUS.encode()
        if u == TRANCO_URL:
            return tranco_zip()
        if u == f"{LOG_URL}/checkpoint":
            return f"example\n{self.size}\nhash\n".encode()
        prefix = f"{LOG_URL}/tile/names/"
        if u.startswith(prefix):
            index = int(u[len(prefix):].replace("x", "").replace("/", ""))
            if index in self.tiles:
                return self.tiles[index]
            return names_tile([])
        raise FetchError(f"{u}: HTTP 404")

    def page(self, host: str) -> pagecheck.Page | None:
        self.page_calls.append(host)
        return self.pages.get(host)


class EarlyWarningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.dist, self.cache = self.tmp / "dist", self.tmp / "cache"
        self.web = FakeCT()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp)

    def ew(self, now: dt.datetime) -> early.EarlyWarning:
        return early.EarlyWarning(dist=self.dist, cache=self.cache, get=self.web.get,
                                  detector=detector(), now=now, page_get=self.web.page)

    def run_once(self, now: dt.datetime) -> early.Result:
        e = self.ew(now)
        r = e.run()
        e.save()
        return r

    def test_select_logs(self) -> None:
        logs = early.select_logs(json.loads(log_list()), T0)
        self.assertEqual([lg.url for lg in logs], [LOG_URL])
        self.assertEqual(early.select_logs(json.loads(log_list("Some Other Log")), T0), [])
        far = T0 + dt.timedelta(days=365 * 2)
        self.assertEqual(early.select_logs(json.loads(log_list()), far), [])     # expired shard

    def test_first_run_starts_at_the_head_without_backfill(self) -> None:
        r = self.run_once(T0)
        self.assertEqual(r.hosts, set())
        self.assertFalse(any("/tile/" in u for u in self.web.calls))
        state = json.loads((self.dist / "state" / "early-warning.json").read_text())
        self.assertEqual(state["cursors"][LOG_URL], 2 * ct.TILE)

    def test_flags_by_name_and_by_page(self) -> None:
        self.run_once(T0)
        self.web.size = 4 * ct.TILE + 3
        self.web.tiles[2] = names_tile([["paypal-login-verify.com"], ["*.paypal-shop.com", "paypal-shop.com"],
                                        ["paypal.com"], ["ordinary.org"]])
        self.web.tiles[3] = names_tile([["facebook-gifts.com"]])
        self.web.pages["paypal-shop.com"] = pagecheck.Page(
            "paypal-shop.com", "<title>PayPal</title><input type='password'>")
        self.web.pages["facebook-gifts.com"] = pagecheck.Page("facebook-gifts.com", "<p>hello</p>")
        r = self.run_once(T0 + dt.timedelta(minutes=30))
        self.assertEqual(r.hosts, {"paypal-login-verify.com", "paypal-shop.com"})
        self.assertNotIn("/tile/names/004", " ".join(self.web.calls))     # partial tile skipped
        state = json.loads((self.dist / "state" / "early-warning.json").read_text())
        self.assertEqual(state["cursors"][LOG_URL], 4 * ct.TILE)
        self.assertIn("facebook-gifts.com", state["pending"])                # checked again later
        self.assertIn("names paypal", state["flagged"]["paypal-shop.com"]["reasons"][-1])

    def test_pending_rechecked_then_dropped(self) -> None:
        self.run_once(T0)
        self.web.size = 3 * ct.TILE
        self.web.tiles[2] = names_tile([["facebook-gifts.com"]])
        t = T0 + dt.timedelta(minutes=30)
        self.run_once(t)
        self.run_once(t + dt.timedelta(minutes=30))                          # too soon to re-check
        self.assertEqual(self.web.page_calls.count("facebook-gifts.com"), 1)
        self.run_once(t + dt.timedelta(hours=2))
        self.run_once(t + dt.timedelta(hours=4))
        self.assertEqual(self.web.page_calls.count("facebook-gifts.com"), 3)
        state = json.loads((self.dist / "state" / "early-warning.json").read_text())
        self.assertNotIn("facebook-gifts.com", state["pending"])

    def test_confirmation_and_expiry(self) -> None:
        self.run_once(T0)
        self.web.size = 3 * ct.TILE
        self.web.tiles[2] = names_tile([["paypal-login-verify.com"]])
        t = T0 + dt.timedelta(minutes=30)
        self.run_once(t)
        e = self.ew(t + dt.timedelta(hours=5))
        e.run()
        e.confirm({"phishunt": {"paypal-login-verify.com"}})
        self.assertEqual(e._stats()["later seen in other feeds"], 1)
        self.assertEqual(e._stats()["median hours ahead"], 5.0)
        e.save()
        r = self.run_once(t + early.TTL + dt.timedelta(hours=1))
        self.assertEqual(r.hosts, set())

    def test_log_failure_keeps_cursor(self) -> None:
        self.run_once(T0)
        self.web.size = 3 * ct.TILE
        real = self.web.get

        def broken(u: str) -> bytes:
            if "/tile/" in u:
                raise FetchError(f"{u}: HTTP 503")
            return real(u)
        self.web.get = broken
        r = self.run_once(T0 + dt.timedelta(minutes=30))
        self.assertTrue(any("will retry" in n for n in r.notes))
        state = json.loads((self.dist / "state" / "early-warning.json").read_text())
        self.assertEqual(state["cursors"][LOG_URL], 2 * ct.TILE)


class BuilderIntegration(unittest.TestCase):
    def test_early_warning_build_publishes_small_list(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        try:
            web = FakeCT()
            dist, cache = tmp / "dist", tmp / "cache"
            Builder(repo=ROOT, dist=dist, cache=cache, get=web.get, now=T0,
                    page_get=web.page).run(["early-warning"])
            web.size = 3 * ct.TILE
            web.tiles[2] = names_tile([["paypal-login-verify.com"]])
            rep = Builder(repo=ROOT, dist=dist, cache=cache, get=web.get, now=T0 + dt.timedelta(minutes=30),
                          page_get=web.page).run(["early-warning"])
            self.assertTrue(rep.builds["early-warning"].published, rep.builds["early-warning"].failure)
            text = (dist / "early-warning" / "domains.txt").read_text()
            self.assertIn("\npaypal-login-verify.com\n", text)
            self.assertIn("License: CC0-1.0", text)
            self.assertEqual(rep.early["listed"], 1)
        finally:
            shutil.rmtree(tmp)

    def test_brands_file_is_valid(self) -> None:
        cfg = tomllib.loads((ROOT / "data" / "brands.toml").read_text())
        names = [b["name"] for b in cfg["brand"]]
        self.assertEqual(len(names), len(set(names)))
        for b in cfg["brand"]:
            self.assertTrue(b.get("strong") or b.get("weak"), b["name"])
            for t in b.get("word_start", ()):
                self.assertIn(t, b.get("strong", ()), b["name"])


if __name__ == "__main__":
    unittest.main()
