"""Pipeline tests. No network: every fetch goes to an in-memory fake."""

from __future__ import annotations

import datetime as dt
import io
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path

from licensing import registry as lic
from pipeline import formats
from pipeline.build import PSL_URL, TRANCO_URL, Builder, BuildReport, Report, SourceReport, annotations, build_formats
from pipeline.fetch import FetchError
from pipeline.guard import Guard, load_tranco
from pipeline.hosts import PublicSuffixList, ancestors, classify, normalize
from pipeline.parse import parse
from pipeline.state import State

ROOT = Path(__file__).resolve().parent.parent
T0 = dt.datetime(2026, 11, 14, 12, 0, tzinfo=dt.timezone.utc)

PSL = """// ===BEGIN ICANN DOMAINS===
com
net
org
pl
dev
io
uk
co.uk
*.ck
!www.ck
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
pages.dev
github.io
githubusercontent.com
blogspot.com
s3.amazonaws.com
// ===END PRIVATE DOMAINS===
"""
TRANCO_CSV = "1,google.com\n2,amazonaws.com\n3,github.com\n500,popular.com\n500000,midsite.com\n"


def tranco_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("top-1m.csv", TRANCO_CSV)
    return buf.getvalue()


def url(source_id: str) -> str:
    return next(s.url for s in lic.load().sources if s.id == source_id)


PHISHUNT = """https://evil-login.com/account/verify
https://bad.pages.dev/login
http://192.0.2.7/kit/
https://www.midsite.com/wp-content/phish/
https://secure.popular.com/x
https://pages.dev/
https://accounts.google.com.evil-login.com/
"""
CERT_PL = "pl-scam.pl\nevil-login.com\nbank-pl-weryfikacja.pl\n"
TIF = """[Adblock Plus]
! Title: fixture
||tif-bad.com^
||midsite.com^
||google.com^
||sub.tif-bad.com^
@@||allowed.example^
||modifier.com^$important
"""
PHISHDB = "phishdb-bad.net\nbit-ly-login.net\n"


class FakeWeb:
    def __init__(self) -> None:
        self.pages: dict[str, bytes | Exception] = {
            PSL_URL: PSL.encode(), TRANCO_URL: tranco_zip(),
            url("phishunt"): PHISHUNT.encode(), url("cert-pl"): CERT_PL.encode(),
            url("hagezi-tif"): TIF.encode(), url("phishing-database"): PHISHDB.encode(),
        }
        self.calls: list[str] = []

    def get(self, u: str) -> bytes:
        self.calls.append(u)
        page = self.pages.get(u)
        if page is None:
            raise FetchError(f"{u}: HTTP 404")
        if isinstance(page, Exception):
            raise page
        return page


# --------------------------------------------------------------- hosts ---

class Hosts(unittest.TestCase):
    def test_normalise(self) -> None:
        cases = {
            "Example.COM.": "example.com",
            "https://User@Login.Example.com:8443/path?q=1": "login.example.com",
            "example.com:80": "example.com",
            "bücher.example": "xn--bcher-kva.example",
            "under_score.example.com": "under_score.example.com",
        }
        for raw, want in cases.items():
            self.assertEqual(normalize(raw), want, raw)

    def test_rejects(self) -> None:
        self.assertEqual(classify("192.0.2.1")[1], "ip")
        self.assertEqual(classify("http://[2001:db8::1]/x")[1], "ip")
        for bad in ("localhost", "-bad.com", "bad-.com", ".lead.com", "a..b.com", "x" * 64 + ".com", "1.2.3", "<html>"):
            self.assertIsNone(normalize(bad), bad)

    def test_ancestors(self) -> None:
        self.assertEqual(ancestors("a.b.example.com"), ["b.example.com", "example.com"])
        self.assertEqual(ancestors("example.com"), [])


class Suffixes(unittest.TestCase):
    psl = PublicSuffixList(PSL)

    def test_registrable(self) -> None:
        p = self.psl
        self.assertEqual(p.registrable("www.example.co.uk"), "example.co.uk")
        self.assertEqual(p.registrable("evil.pages.dev"), "evil.pages.dev")
        self.assertEqual(p.registrable("evil.pages.dev", private=False), "pages.dev")
        self.assertIsNone(p.registrable("pages.dev"))
        self.assertEqual(p.registrable("a.b.foo.ck"), "b.foo.ck")      # *.ck wildcard
        self.assertEqual(p.registrable("a.www.ck"), "www.ck")          # !www.ck exception

    def test_shared_and_suffix(self) -> None:
        p = self.psl
        self.assertTrue(p.is_shared("evil.pages.dev"))
        self.assertFalse(p.is_shared("www.example.com"))
        self.assertTrue(p.is_public_suffix("pages.dev"))
        self.assertTrue(p.is_public_suffix("co.uk"))
        self.assertFalse(p.is_public_suffix("example.co.uk"))


# --------------------------------------------------------------- parse ---

class Parsing(unittest.TestCase):
    def test_abp(self) -> None:
        r = parse(TIF, "abp")
        self.assertEqual(r.entries, {"tif-bad.com", "midsite.com", "google.com", "sub.tif-bad.com"})
        self.assertEqual(r.skipped, 2)   # @@ allow rule, $modifier rule
        self.assertEqual(r.rejected, 0)

    def test_hosts_and_domains(self) -> None:
        r = parse("# c\n0.0.0.0 a.com b.com # tail\n127.0.0.1 c.com\n1.2.3.4 d.com\n", "hosts")
        self.assertEqual(r.entries, {"a.com", "b.com", "c.com"})
        self.assertEqual(r.rejected, 1)
        r = parse("x.com # why\n\ny.net\nnot a domain\n", "domains")
        self.assertEqual(r.entries, {"x.com", "y.net"})
        self.assertEqual(r.rejected, 1)

    def test_urls_skip_ips(self) -> None:
        r = parse(PHISHUNT, "urls")
        self.assertIn("bad.pages.dev", r.entries)
        self.assertEqual(r.skipped, 1)

    def test_html_error_page_is_junk(self) -> None:
        r = parse("<html>\n<head><title>502 Bad Gateway</title></head>\n<body>oops</body>\n</html>\n", "domains")
        self.assertEqual(r.entries, set())
        self.assertEqual(r.junk_ratio, 1.0)


# --------------------------------------------------------------- guard ---

class Guarding(unittest.TestCase):
    def setUp(self) -> None:
        self.g = Guard(PublicSuffixList(PSL), load_tranco(TRANCO_CSV),
                       {"google.com", "amazonaws.com", "connectivitycheck.gstatic.com"})

    def test_rules(self) -> None:
        g = self.g
        self.assertEqual(g.reason("pages.dev", 10_000), "public-suffix")
        self.assertEqual(g.reason("google.com", 0), "allowlist")
        self.assertEqual(g.reason("mail.google.com", 0), "allowlist")
        self.assertEqual(g.reason("gstatic.com", 0), "allowlist")          # parent of an allowed name
        self.assertIsNone(g.reason("bucket.s3.amazonaws.com", 10_000))       # tenant, not Amazon
        self.assertEqual(g.reason("secure.popular.com", 10_000), "popular-site")
        self.assertIsNone(g.reason("midsite.com", 10_000))
        self.assertEqual(g.reason("www.midsite.com", 1_000_000), "popular-site")
        self.assertIsNone(g.reason("evil.github.io", 1_000_000))            # tenant of a ranked platform
        self.assertIsNone(g.reason("evil-login.com", 1_000_000))
        self.assertIsNone(g.reason("www.midsite.com", 0))                   # 0 = no Tranco check


# ------------------------------------------------------------- formats ---

class Formats(unittest.TestCase):
    hosts = {"a.example.com", "example.com", "evil.pages.dev", "x.org"}

    def test_round_trip(self) -> None:
        for fmt in formats.FILES:
            text = formats.render(fmt, self.hosts, ["Title: t", "License: CC0-1.0"], 1234)
            want = formats.minimise(self.hosts) if fmt in formats.WILDCARD else self.hosts
            self.assertEqual(formats.read_back(fmt, text), want, fmt)
            self.assertIn("License: CC0-1.0", text, fmt)
            self.assertIn(f"Entries: {len(want)}", text, fmt)

    def test_minimise_and_semantics(self) -> None:
        self.assertEqual(formats.minimise(self.hosts), {"example.com", "evil.pages.dev", "x.org"})
        self.assertTrue(formats.blocks("abp", {"example.com"}, "deep.a.example.com"))
        self.assertFalse(formats.blocks("hosts", {"example.com"}, "a.example.com"))

    def test_all_in_one_skips_the_huge_formats(self) -> None:
        self.assertEqual(build_formats("all-in-one"), ("abp", "domains", "hosts"))
        self.assertEqual(build_formats("complement"), tuple(formats.FILES))

    def test_rpz_lists_name_and_wildcard(self) -> None:
        text = formats.render("rpz", {"evil.com"}, [], 1)
        self.assertIn("\nevil.com CNAME .\n*.evil.com CNAME .\n", text)
        self.assertTrue(text.startswith("$TTL 300\n@ IN SOA"))

    def test_unbound_has_server_clause(self) -> None:
        self.assertIn('server:\nlocal-zone: "evil.com." always_nxdomain', formats.render("unbound", {"evil.com"}, [], 1))


# --------------------------------------------------------------- state ---

class States(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)

    def test_live_ttl(self) -> None:
        s = State(self.dir)
        s.observe("f", {"a.com", "b.com"}, T0)
        s.observe("f", {"b.com"}, T0 + dt.timedelta(days=10))
        self.assertEqual(s.expire("f", dt.timedelta(days=14), T0 + dt.timedelta(days=15)), 1)
        self.assertEqual(s.live_hosts("f"), {"b.com"})
        self.assertEqual(s.seen["f"]["b.com"][0], "2026-11-14T12:00:00Z")  # first seen kept

    def test_snapshot_and_persistence(self) -> None:
        s = State(self.dir)
        s.save_snapshot("m", {"x.com", "y.com"}, T0)
        s.mark_fetched("m", T0)
        s.save()
        s2 = State(self.dir)
        self.assertEqual(s2.load_snapshot("m"), ({"x.com", "y.com"}, T0))
        self.assertEqual(s2.last_fetch("m"), T0)


# --------------------------------------------------------------- build ---

class Build(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.dist, self.cache = self.tmp / "dist", self.tmp / "cache"
        self.web = FakeWeb()

    def run_build(self, builds=("complement", "all-in-one"), now=T0, **kw):
        b = Builder(repo=ROOT, dist=self.dist, cache=self.cache, get=self.web.get, now=now, min_entries=1, **kw)
        return b.run(list(builds))

    def listed(self, build: str, fmt: str = "domains") -> set[str]:
        return formats.read_back(fmt, (self.dist / build / formats.FILES[fmt]).read_text())

    def test_first_run_publishes_both_builds(self) -> None:
        report = self.run_build()
        self.assertTrue(report.ok, report.builds)
        comp, aio = self.listed("complement"), self.listed("all-in-one")
        self.assertEqual(comp, {"evil-login.com", "bad.pages.dev", "accounts.google.com.evil-login.com",
                                "pl-scam.pl", "bank-pl-weryfikacja.pl"})
        self.assertTrue(comp <= aio)
        self.assertLessEqual({"tif-bad.com", "sub.tif-bad.com", "midsite.com", "phishdb-bad.net"}, aio)
        for never in ("google.com", "pages.dev", "secure.popular.com", "www.midsite.com"):
            self.assertNotIn(never, comp | {h for h in aio if h != "midsite.com"})
        self.assertNotIn("google.com", aio)
        self.assertNotIn("sub.tif-bad.com", self.listed("all-in-one", "abp"))  # minimised away

    def test_files_carry_licence_and_wording(self) -> None:
        self.run_build()
        for build, licence in (("complement", "CC0-1.0"), ("all-in-one", "GPL-3.0-only")):
            d = self.dist / build
            self.assertEqual((d / "LICENSE").read_text(), lic.text_path(licence).read_text())
            self.assertIn("suspected", (d / "NOTICE").read_text())
            names = {formats.FILES[f] for f in build_formats(build)}
            self.assertEqual({p.name for p in d.iterdir()} - {"LICENSE", "NOTICE"}, names)
            for name in names:
                text = (d / name).read_text()
                self.assertIn(f"License: {licence}", text, name)
                self.assertIn(lic.SUSPECTED_LINE, text, name)
        self.assertIn("raw.githubusercontent.com", (self.dist / "README.md").read_text())

    def test_respects_fetch_intervals(self) -> None:
        self.run_build()
        self.web.calls.clear()
        report = self.run_build(now=T0 + dt.timedelta(minutes=30))
        self.assertTrue(report.ok)
        self.assertIn(url("phishunt"), self.web.calls)                 # every 10 minutes
        self.assertNotIn(url("hagezi-tif"), self.web.calls)            # Expires: 8 hours
        self.assertNotIn(url("phishing-database"), self.web.calls)
        self.assertEqual(report.sources["hagezi-tif"].how, "not due")
        self.assertIn("tif-bad.com", self.listed("all-in-one"))         # from the snapshot

    def test_live_feed_keeps_hosts_for_ttl(self) -> None:
        self.run_build(["complement"])
        self.web.pages[url("phishunt")] = b"https://other-phish.com/x\n"
        self.run_build(["complement"], now=T0 + dt.timedelta(hours=1))
        self.assertIn("evil-login.com", self.listed("complement"))      # still within 14 days
        self.run_build(["complement"], now=T0 + dt.timedelta(days=15))
        comp = self.listed("complement")
        self.assertNotIn("bad.pages.dev", comp)                          # expired
        self.assertIn("other-phish.com", comp)

    def test_failed_or_junk_fetch_falls_back_to_snapshot(self) -> None:
        self.run_build(["complement"])
        self.web.pages[url("cert-pl")] = b"<html>\n<body>502 Bad Gateway</body>\n</html>\n"
        report = self.run_build(["complement"], now=T0 + dt.timedelta(hours=2))
        self.assertIn("didn't parse", " ".join(report.sources["cert-pl"].notes))
        self.assertEqual(report.sources["cert-pl"].how, "snapshot")
        self.assertIn("pl-scam.pl", self.listed("complement"))
        self.web.pages[url("cert-pl")] = FetchError("timed out")
        report = self.run_build(["complement"], now=T0 + dt.timedelta(days=31))  # past max_stale (30 days)
        self.assertEqual(report.sources["cert-pl"].how, "unavailable")
        self.assertTrue(any("cert-pl" in w for w in report.warnings))

    def test_header_names_only_sources_used_this_run(self) -> None:
        def sources_line(build: str) -> str:
            text = (self.dist / build / "domains.txt").read_text()
            return next(ln for ln in text.splitlines() if ln.startswith("# Sources:"))
        self.web.pages[url("phishing-database")] = FetchError("HTTP Error 503")
        report = self.run_build(["all-in-one"])
        self.assertTrue(report.ok, report.builds)
        self.assertNotIn("Phishing.Database", sources_line("all-in-one"))
        self.assertIn("CERT Polska", sources_line("all-in-one"))
        self.assertIn("Phishing.Database", (self.dist / "all-in-one" / "NOTICE").read_text())  # still credited

    def test_mirror_swing_is_rejected(self) -> None:
        self.run_build(["complement"])
        self.web.pages[url("cert-pl")] = b"pl-scam.pl\n" + b"".join(f"new{i}.pl\n".encode() for i in range(50))
        report = self.run_build(["complement"], now=T0 + dt.timedelta(hours=2))
        self.assertIn("change", " ".join(report.sources["cert-pl"].notes))
        self.assertNotIn("new1.pl", self.listed("complement"))

    def test_build_swing_keeps_previous_files(self) -> None:
        self.run_build(["complement"])
        before = (self.dist / "complement" / "abp.txt").read_text()
        b = Builder(repo=ROOT, dist=self.dist, cache=self.cache, get=self.web.get,
                    now=T0 + dt.timedelta(hours=2), min_entries=100)
        report = b.run(["complement"])
        self.assertFalse(report.ok)
        self.assertIn("minimum", report.builds["complement"].failure)
        self.assertEqual((self.dist / "complement" / "abp.txt").read_text(), before)

    def test_new_source_may_grow_the_build(self) -> None:
        self.web.pages[url("cert-pl")] = FetchError("timed out")    # never reachable at first
        self.web.pages[url("phishunt")] = b"".join(f"https://p{i}.com/\n".encode() for i in range(60))
        self.run_build(["complement"])
        self.web.pages[url("cert-pl")] = b"".join(f"pl{i}.pl\n".encode() for i in range(500))
        report = self.run_build(["complement"], now=T0 + dt.timedelta(hours=2))
        self.assertTrue(report.ok, report.builds["complement"].failure)
        self.assertIn("new source(s) cert-pl", report.builds["complement"].note)

    def test_lost_source_still_trips_the_gate(self) -> None:
        self.web.pages[url("cert-pl")] = b"".join(f"pl{i}.pl\n".encode() for i in range(500))
        self.run_build(["complement"])
        self.web.pages[url("cert-pl")] = FetchError("timed out")
        report = self.run_build(["complement"], now=T0 + dt.timedelta(days=31))   # past max_stale
        self.assertFalse(report.ok)
        self.assertIn("change", report.builds["complement"].failure)
        forced = Builder(repo=ROOT, dist=self.dist, cache=self.cache, get=self.web.get,
                         now=T0 + dt.timedelta(days=31, hours=1), min_entries=1, allow_swing=True).run(["complement"])
        self.assertTrue(forced.ok)

    def test_approved_source_without_settings_is_refused(self) -> None:
        reg = lic.load()
        extra = lic.Source(id="new-feed", name="New", status="approved", license="CC0-1.0",
                           builds=("complement",), homepage="https://x.example", terms_url="https://x.example/t",
                           url="https://x.example/feed", verified=dt.date(2026, 11, 1), attribution="",
                           conditions=(), requests=(), notes="")
        reg2 = lic.Registry(reg.builds, reg.sources + (extra,), reg.licenses)
        with self.assertRaisesRegex(ValueError, "no pipeline settings: new-feed"):
            Builder(repo=ROOT, dist=self.dist, cache=self.cache, get=self.web.get, now=T0,
                    registry=reg2, min_entries=1).run(["complement"])


class Annotations(unittest.TestCase):
    def test_one_line_each_and_escaped(self):
        r = Report()
        r.sources["cert-pl"] = SourceReport("cert-pl", "unavailable", notes=["fetch failed: 50% \ndown"])
        r.builds["complement"] = BuildReport("complement", entries=625, published=True)
        r.builds["all-in-one"] = BuildReport("all-in-one", entries=9, failure="too small")
        r.warnings.append("cert-pl: no usable copy")
        lines = annotations(r)
        self.assertEqual(len(lines), 4)
        self.assertTrue(all(line.startswith("::") and "\n" not in line for line in lines))
        self.assertIn("50%25 %0Adown", lines[0])
        self.assertTrue(lines[1].startswith("::notice title=Build::complement: 625"))
        self.assertTrue(lines[2].startswith("::error title=Build::all-in-one"))
        self.assertTrue(lines[3].startswith("::warning"))


if __name__ == "__main__":
    unittest.main()
