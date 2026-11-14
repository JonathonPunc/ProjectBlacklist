"""Tests for the licence registry and its rules (stdlib unittest only)."""

from __future__ import annotations

import datetime as dt
import shutil
import tempfile
import unittest
from pathlib import Path

from licensing import registry as r

TODAY = dt.date(2026, 11, 14)

BUILDS = """
[builds.complement]
license = "CC0-1.0"
description = "c"

[builds.all-in-one]
license = "GPL-3.0-only"
description = "a"
"""


def source(**fields: object) -> str:
    base: dict[str, object] = {
        "id": "s1", "name": "Source One", "status": "approved", "license": "CC0-1.0",
        "builds": ["complement"], "homepage": "https://example.org/",
        "terms_url": "https://example.org/terms", "verified": "2026-11-01",
    }
    base.update(fields)
    lines = ["[[sources]]"]
    for key, value in base.items():
        if value is None:
            continue
        if key == "verified":
            lines.append(f"verified = {value}")          # bare TOML date
        elif isinstance(value, list):
            lines.append(f"{key} = [{', '.join(repr(v).replace(chr(39), chr(34)) for v in value)}]")
        else:
            lines.append(f'{key} = """{value}"""')
    return "\n".join(lines) + "\n"


def errors_for(*sources: str) -> list[str]:
    errors, _ = r.check(r.loads(BUILDS + "\n".join(sources)), today=TODAY)
    return errors


class RealRegistry(unittest.TestCase):
    def test_registry_is_valid(self) -> None:
        errors, _ = r.check(r.load())
        self.assertEqual(errors, [])

    def test_derived_files_are_in_sync(self) -> None:
        stale = r.stale_files(r.load())
        self.assertEqual(stale, [], "run `python -m licensing sync`")

    def test_complement_only_takes_public_domain_sources(self) -> None:
        reg = r.load()
        for s in reg.feeding("complement"):
            self.assertIn(s.license, r.COMPATIBLE["CC0-1.0"], s.id)

    def test_excluded_sources_feed_nothing(self) -> None:
        for s in r.load().sources:
            if s.status != "approved":
                self.assertEqual(s.builds, (), s.id)

    def test_every_build_has_its_licence_text(self) -> None:
        for b in r.load().builds.values():
            self.assertTrue(r.text_path(b.license).is_file(), b.license)

    def test_shipped_texts_match_repo_licence_texts(self) -> None:
        # A licence used both in this repo (LICENSES/) and in builds
        # (licensing/texts/) must be the same text in both places.
        for repo_text in (r.ROOT / "LICENSES").glob("*.txt"):
            shipped = r.text_path(repo_text.stem)
            if shipped.is_file():
                self.assertEqual(shipped.read_text(), repo_text.read_text(), repo_text.stem)


class Drift(unittest.TestCase):
    def test_hand_edited_notice_is_caught(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        notice, doc = tmp / "NOTICE", tmp / "LICENSING.md"
        shutil.copyfile(r.NOTICE_PATH, notice)
        shutil.copyfile(r.LICENSING_DOC, doc)
        reg = r.load()
        self.assertEqual(r.stale_files(reg, notice_path=notice, doc_path=doc), [])
        notice.write_text(notice.read_text() + "hand edit\n")
        self.assertEqual(r.stale_files(reg, notice_path=notice, doc_path=doc), [notice])
        self.assertEqual(r.sync(reg, notice_path=notice, doc_path=doc), [notice])
        self.assertEqual(r.stale_files(reg, notice_path=notice, doc_path=doc), [])

    def test_missing_table_markers_rejected(self) -> None:
        with self.assertRaises(ValueError):
            r._doc_with_table("no markers here", "| table |")


class Rules(unittest.TestCase):
    def test_valid_minimal_source(self) -> None:
        self.assertEqual(errors_for(source()), [])

    def test_mit_data_cannot_enter_cc0_build(self) -> None:
        errs = errors_for(source(license="MIT", attribution="(c) someone"))
        self.assertTrue(any("can't go into build complement" in e for e in errs), errs)

    def test_mit_data_can_enter_gpl_build_with_attribution(self) -> None:
        self.assertEqual(errors_for(source(license="MIT", builds=["all-in-one"], attribution="(c) someone")), [])

    def test_notice_licence_needs_attribution(self) -> None:
        errs = errors_for(source(license="MIT", builds=["all-in-one"]))
        self.assertTrue(any("requires an attribution" in e for e in errs), errs)

    def test_non_commercial_licence_refused_everywhere(self) -> None:
        for build in ("complement", "all-in-one"):
            errs = errors_for(source(license="CC-BY-NC-4.0", builds=[build], attribution="x"))
            self.assertTrue(any("can't go into build" in e for e in errs), (build, errs))

    def test_unapproved_source_cannot_feed_builds(self) -> None:
        errs = errors_for(source(status="pending", notes="terms unclear"))
        self.assertTrue(any("only approved sources" in e for e in errs), errs)

    def test_unapproved_source_needs_notes(self) -> None:
        errs = errors_for(source(status="excluded", builds=[]))
        self.assertTrue(any("need notes" in e for e in errs), errs)

    def test_unknown_build(self) -> None:
        errs = errors_for(source(builds=["nope"]))
        self.assertTrue(any("unknown build" in e for e in errs), errs)

    def test_bad_status(self) -> None:
        errs = errors_for(source(status="maybe"))
        self.assertTrue(any("is not one of" in e for e in errs), errs)

    def test_duplicate_ids(self) -> None:
        errs = errors_for(source(), source())
        self.assertTrue(any("duplicate id" in e for e in errs), errs)

    def test_approved_needs_terms_and_date(self) -> None:
        errs = errors_for(source(terms_url=None, verified=None))
        self.assertTrue(any("terms_url" in e for e in errs), errs)
        self.assertTrue(any("verified date" in e for e in errs), errs)

    def test_quoted_date_rejected(self) -> None:
        errs = errors_for(source(verified='"2026-11-01"'))
        self.assertTrue(any("unquoted TOML date" in e for e in errs), errs)

    def test_future_date_rejected(self) -> None:
        errs = errors_for(source(verified="2027-01-01"))
        self.assertTrue(any("in the future" in e for e in errs), errs)

    def test_old_verification_only_warns(self) -> None:
        reg = r.loads(BUILDS + source(verified="2025-01-01"))
        errors, warnings = r.check(reg, today=TODAY)
        self.assertEqual(errors, [])
        self.assertTrue(any("read them again" in w for w in warnings), warnings)

    def test_build_licence_without_rules(self) -> None:
        reg = r.loads('[builds.x]\nlicense = "WTFPL"\n' + source(builds=["x"]))
        errors, _ = r.check(reg, today=TODAY)
        self.assertTrue(any("no compatibility rules" in e for e in errors), errors)


class Staging(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)

    def test_stage_writes_licence_notice_and_header(self) -> None:
        reg = r.load()
        for build in reg.builds.values():
            out = self.tmp / build.id
            header = r.stage(reg, build.id, out)
            self.assertEqual((out / "LICENSE").read_text(), r.text_path(build.license).read_text())
            notice = (out / "NOTICE").read_text()
            self.assertIn(r.SUSPECTED_LINE, notice)
            self.assertIn(r.SUSPECTED_LINE, header)
            self.assertTrue(header[0].startswith(f"License: {build.license}"))
            for s in reg.feeding(build.id):
                self.assertIn(s.name, notice)
                self.assertIn(s.name, header[1])

    def test_all_in_one_notice_carries_mit_text(self) -> None:
        reg = r.load()
        r.stage(reg, "all-in-one", self.tmp)
        notice = (self.tmp / "NOTICE").read_text()
        self.assertIn("Mitchell Krog", notice)
        self.assertIn("Permission is hereby granted", notice)
        self.assertNotIn("<copyright holders>", notice)

    def test_maintainer_requests_reach_the_notice(self) -> None:
        reg = r.load()
        notice = r.notice_text(reg)
        for s in reg.sources:
            if s.status == "approved" and s.builds:
                for q in s.requests:
                    self.assertIn(f"Requested: {q}", notice, s.id)

    def test_complement_notice_has_no_third_party_licence_text(self) -> None:
        r.stage(r.load(), "complement", self.tmp)
        self.assertNotIn("Permission is hereby granted", (self.tmp / "NOTICE").read_text())

    def test_stage_refuses_invalid_registry(self) -> None:
        reg = r.loads(BUILDS + source(license="MIT", attribution="x"))
        with self.assertRaises(ValueError):
            r.stage(reg, "complement", self.tmp, today=TODAY)
        self.assertFalse((self.tmp / "LICENSE").exists())

    def test_stage_unknown_build(self) -> None:
        with self.assertRaises(KeyError):
            r.stage(r.load(), "nope", self.tmp)


if __name__ == "__main__":
    unittest.main()
