#!/usr/bin/env python3
"""Offline unit tests for the public Cyber Alerts feed builder (stdlib unittest)."""

from __future__ import annotations

import importlib.util
import io
import os
import re
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
FIX = Path(__file__).resolve().parent / "fixtures"


def load_builder():
    path = ROOT / "build_feed.py"
    spec = importlib.util.spec_from_file_location("build_feed", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


bf = load_builder()

def _private_host_re(extra_terms: list[str] | None = None):
    """Public-safe patterns only in source. Estate/seat names come from FEED_DENY_TERMS env (CI secret)."""
    parts = [
        r"localhost",
        r"127\.0\.0\.1",
        r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        r"192\.168\.\d{1,3}\.\d{1,3}",
        r"172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}",
    ]
    for term in extra_terms or []:
        term = (term or "").strip()
        if term:
            parts.append(re.escape(term))
    return re.compile(r"(?i)\b(" + "|".join(parts) + r")\b")


def _deny_terms_from_env() -> list[str]:
    raw = os.environ.get("FEED_DENY_TERMS") or os.environ.get("HYGIENE_DENY_TERMS") or ""
    # comma or newline separated; never print
    bits = []
    for chunk in raw.replace("\n", "\n").splitlines():
        bits.extend(p.strip() for p in chunk.split(","))
    return [b for b in bits if b]


PRIVATE_HOST_RE = _private_host_re(_deny_terms_from_env())
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class TestSeverity(unittest.TestCase):
    def test_cvss_mapping(self):
        self.assertEqual(bf.severity_from_cvss(9.8), "critical")
        self.assertEqual(bf.severity_from_cvss(7.0), "high")
        self.assertEqual(bf.severity_from_cvss(4.0), "medium")
        self.assertEqual(bf.severity_from_cvss(0.1), "low")
        self.assertIsNone(bf.severity_from_cvss(None))

    def test_ghsa_moderate_maps_to_medium(self):
        self.assertEqual(bf.severity_from_ghsa("moderate"), "medium")
        self.assertEqual(bf.severity_from_ghsa("CRITICAL"), "critical")

    def test_max_severity(self):
        self.assertEqual(bf.max_severity("low", "high"), "high")
        self.assertEqual(bf.max_severity("critical", "high"), "critical")


class TestDedupe(unittest.TestCase):
    def test_prefer_cve_then_ghsa_then_url(self):
        a = bf.empty_item()
        a.update({"cves": ["CVE-2024-1"], "title": "x", "links": ["https://example.com/a"]})
        self.assertEqual(bf.dedupe_key(a), "cve:CVE-2024-1")
        b = bf.empty_item()
        b.update({"ghsa_ids": ["GHSA-aaaa-bbbb-cccc"], "links": ["https://example.com/b"]})
        self.assertEqual(bf.dedupe_key(b), "ghsa:ghsa-aaaa-bbbb-cccc")
        c = bf.empty_item()
        c.update({"title": "Only news", "links": ["https://Example.com/Path/?q=1#frag"]})
        self.assertEqual(bf.dedupe_key(c), "url:https://example.com/Path?q=1")

    def test_collapse_news_into_cve(self):
        kev = bf.empty_item()
        kev.update(
            {
                "id": "CVE-2026-1000",
                "cves": ["CVE-2026-1000"],
                "title": "KEV item",
                "sources": ["CISA KEV"],
                "links": ["https://nvd.nist.gov/vuln/detail/CVE-2026-1000"],
                "severity": "high",
                "summary": "CISA KEV addition",
            }
        )
        news = bf.empty_item()
        news.update(
            {
                "id": "https://news.example/story",
                "cves": ["CVE-2026-1000"],
                "title": "News about CVE-2026-1000",
                "sources": ["BleepingComputer"],
                "links": ["https://news.example/story"],
                "severity": "critical",
                "summary": "Security news",
                "unconfirmed": True,
            }
        )
        out = bf.collapse_news_into_cves([kev, news])
        self.assertEqual(len(out), 1)
        self.assertIn("CISA KEV", out[0]["sources"])
        self.assertIn("BleepingComputer", out[0]["sources"])
        self.assertEqual(out[0]["severity"], "critical")
        self.assertFalse(out[0]["unconfirmed"])


class TestNoCopyRule(unittest.TestCase):
    def test_summary_length_cap(self):
        long_title = "A" * 2000
        s = bf.templated_summary("rss", long_title, "high", ["CVE-2026-1"], False, ["mobile"])
        self.assertLessEqual(len(s), bf.SUMMARY_MAX)
        self.assertNotIn("<p>", s)

    def test_telegram_summary_is_templated(self):
        s = bf.templated_summary(
            "telegram",
            "Something happened",
            None,
            [],
            False,
            ["supply-chain"],
        )
        self.assertIn("unconfirmed", s.lower())
        self.assertLessEqual(len(s), bf.SUMMARY_MAX)


class TestRssValidity(unittest.TestCase):
    def test_write_feed_parses_as_rss20(self):
        items = []
        for i, sev in enumerate(("critical", "high", "medium")):
            it = bf.empty_item()
            it.update(
                {
                    "id": f"CVE-2026-{1000+i}",
                    "title": f"Sample {i}",
                    "sources": ["NVD"],
                    "links": [f"https://nvd.nist.gov/vuln/detail/CVE-2026-{1000+i}"],
                    "published": "2026-11-03T12:00:00Z",
                    "severity": sev,
                    "topics": ["node-python"],
                    "summary": bf.templated_summary(
                        "nvd", f"Sample {i}", sev, [f"CVE-2026-{1000+i}"], False, ["node-python"]
                    ),
                    "cves": [f"CVE-2026-{1000+i}"],
                    "first_seen": "2026-11-03T12:00:00Z",
                }
            )
            items.append(it)
        with tempfile.TemporaryDirectory() as td:
            feed = os.path.join(td, "feed.xml")
            bf.write_feed_xml(feed, items, limit=50)
            tree = ET.parse(feed)
            root = tree.getroot()
            self.assertEqual(root.tag, "rss")
            self.assertEqual(root.attrib.get("version"), "2.0")
            channel = root.find("channel")
            self.assertIsNotNone(channel)
            self.assertEqual(channel.findtext("title"), "Pennview Labs Cyber Alerts")
            self.assertTrue(channel.findtext("link", "").startswith("https://cyberalerts.pennviewlabs.com"))
            found = channel.findall("item")
            self.assertEqual(len(found), 3)
            for item in found:
                self.assertTrue(item.findtext("title"))
                self.assertTrue(item.findtext("guid"))
                self.assertTrue(item.findtext("description"))
                desc = item.findtext("description") or ""
                self.assertLessEqual(len(desc), 2000)
                self.assertNotRegex(desc, PRIVATE_HOST_RE)
                self.assertIsNone(IPV4_RE.search(desc))


class TestPrivateLeakGuard(unittest.TestCase):
    def test_fixture_rss_parse_and_output_clean(self):
        raw = (FIX / "sample_rss.xml").read_bytes()
        entries = bf.RSSParser.parse(raw)
        self.assertGreaterEqual(len(entries), 1)
        items = []
        for e in entries:
            title = bf.strip_html(e.get("title") or "")
            link = e.get("link") or ""
            desc = bf.strip_html(e.get("description") or "")
            # Builder must not put raw long description into summary
            cves, ghsas = bf.extract_ids(f"{title} {desc}")
            topics = bf.detect_topics(f"{title} {desc}")
            it = bf.empty_item()
            it.update(
                {
                    "id": cves[0] if cves else bf.normalize_url(link),
                    "title": title[:240],
                    "sources": ["Fixture"],
                    "links": [link],
                    "published": "2026-11-03T10:00:00Z",
                    "severity": "high",
                    "topics": topics,
                    "summary": bf.templated_summary("rss", title, "high", cves, False, topics),
                    "cves": cves,
                    "ghsa_ids": ghsas,
                    "unconfirmed": not bool(cves or ghsas),
                    "first_seen": "2026-11-03T10:00:00Z",
                }
            )
            items.append(it)
        with tempfile.TemporaryDirectory() as td:
            feed = os.path.join(td, "feed.xml")
            index = os.path.join(td, "index.html")
            bf.write_feed_xml(feed, items)
            bf.write_index_html(index, items)
            bf.write_cname(os.path.join(td, "CNAME"))
            blob = Path(feed).read_text(encoding="utf-8") + Path(index).read_text(encoding="utf-8")
            self.assertIsNone(PRIVATE_HOST_RE.search(blob))
            # no raw IPv4 in public output
            for m in IPV4_RE.finditer(blob):
                self.fail(f"unexpected IPv4 in output: {m.group(0)}")
            # no-copy: fixture has a long unique phrase that must not appear wholesale
            self.assertNotIn("UNIQUE_LONG_ARTICLE_BODY_PHRASE_DO_NOT_COPY", blob)
            self.assertEqual(Path(td, "CNAME").read_text(encoding="utf-8").strip(), "cyberalerts.pennviewlabs.com")


class TestTopics(unittest.TestCase):
    def test_topic_detection(self):
        self.assertIn("ai-agents", bf.detect_topics("prompt injection against an LLM agent"))
        self.assertIn("supply-chain", bf.detect_topics("malicious npm package typosquat", ["npm"]))
        self.assertIn("node-python", bf.detect_topics("x", ["pip"]))



class TestTelegramParser(unittest.TestCase):
    def test_nested_bubble_preserves_link_and_date(self):
        html_doc = """
        <div class="tgme_widget_message js-widget_message" data-post="IntCyberDigest/99">
          <div class="tgme_widget_message_bubble">
            <div class="tgme_widget_message_text js-message_text">Nested bubble CVE-2026-7777 supply-chain note</div>
            <a class="tgme_widget_message_date" href="https://t.me/IntCyberDigest/99">
              <time datetime="2026-11-01T15:30:00+00:00">15:30</time>
            </a>
          </div>
        </div>
        <div class="tgme_widget_message js-widget_message" data-post="IntCyberDigest/100">
          <div class="tgme_widget_message_bubble">
            <div class="tgme_widget_message_text js-message_text">Second post about npm typosquat</div>
            <a class="tgme_widget_message_date" href="https://t.me/IntCyberDigest/100">
              <time datetime="2026-11-02T09:00:00+00:00">09:00</time>
            </a>
          </div>
        </div>
        """
        parser = bf.TelegramHTMLParser()
        parser.feed(html_doc)
        self.assertEqual(len(parser.messages), 2)
        self.assertEqual(parser.messages[0]["link"], "https://t.me/IntCyberDigest/99")
        self.assertEqual(parser.messages[0]["date"], "2026-11-01T15:30:00+00:00")
        self.assertIn("CVE-2026-7777", parser.messages[0]["text"])
        self.assertEqual(parser.messages[1]["link"], "https://t.me/IntCyberDigest/100")
        self.assertEqual(parser.messages[1]["date"], "2026-11-02T09:00:00+00:00")


class TestCrossIdCollapse(unittest.TestCase):
    def test_ghsa_only_news_merges_into_cve_preferred_advisory(self):
        advisory = bf.empty_item()
        advisory.update(
            {
                "id": "CVE-2026-5555",
                "cves": ["CVE-2026-5555"],
                "ghsa_ids": ["GHSA-zzzz-yyyy-xxxx"],
                "title": "Advisory",
                "sources": ["GitHub Advisory"],
                "links": ["https://github.com/advisories/GHSA-zzzz-yyyy-xxxx"],
                "severity": "high",
                "summary": "GitHub advisory",
            }
        )
        news = bf.empty_item()
        news.update(
            {
                "id": "GHSA-zzzz-yyyy-xxxx",
                "ghsa_ids": ["GHSA-zzzz-yyyy-xxxx"],
                "title": "News only knows the GHSA",
                "sources": ["The Hacker News"],
                "links": ["https://example.com/news/ghsa"],
                "severity": "critical",
                "summary": "Security news",
                "unconfirmed": True,
            }
        )
        out = bf.collapse_news_into_cves([advisory, news])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["cves"], ["CVE-2026-5555"])
        self.assertIn("GHSA-zzzz-yyyy-xxxx", out[0]["ghsa_ids"])
        self.assertIn("The Hacker News", out[0]["sources"])
        self.assertEqual(out[0]["severity"], "critical")
        self.assertFalse(out[0]["unconfirmed"])


class TestEmptyFeedGuard(unittest.TestCase):
    def test_all_failed_empty_exits_nonzero(self):
        # Simulate main's guard logic via a tiny driver: monkeypatch collectors.
        import build_feed as mod

        def boom(*_a, **_k):
            return [], "boom failed: offline"

        def boom_rss(*_a, **_k):
            return [], ["RSS BleepingComputer failed: offline"]

        orig = (
            mod.collect_kev,
            mod.collect_ghsa,
            mod.collect_nvd,
            mod.collect_rss,
            mod.collect_telegram,
        )
        try:
            mod.collect_kev = boom
            mod.collect_ghsa = boom
            mod.collect_nvd = lambda *_a, **_k: ([], "NVD failed: offline")
            mod.collect_rss = boom_rss
            mod.collect_telegram = boom
            with tempfile.TemporaryDirectory() as td:
                argv = ["build_feed.py", "--hours", "1", "--outdir", td, "--no-store"]
                old = sys.argv
                sys.argv = argv
                try:
                    rc = mod.main()
                finally:
                    sys.argv = old
                self.assertEqual(rc, 1)
                self.assertFalse(Path(td, "feed.xml").exists())
        finally:
            (
                mod.collect_kev,
                mod.collect_ghsa,
                mod.collect_nvd,
                mod.collect_rss,
                mod.collect_telegram,
            ) = orig




class TestLinkSchemeGuard(unittest.TestCase):
    def test_javascript_link_dropped_from_html_and_rss(self):
        it = bf.empty_item()
        it.update(
            {
                "id": "hostile-1",
                "title": "Hostile link item",
                "links": ["javascript:alert(document.domain)"],
                "summary": "templated",
                "severity": "high",
                "published": "2026-11-03T10:00:00Z",
                "first_seen": "2026-11-03T10:00:00Z",
            }
        )
        with tempfile.TemporaryDirectory() as td:
            feed = os.path.join(td, "feed.xml")
            index = os.path.join(td, "index.html")
            bf.sanitize_item_links([it])
            bf.write_feed_xml(feed, [it])
            bf.write_index_html(index, [it])
            html_blob = Path(index).read_text(encoding="utf-8")
            rss_blob = Path(feed).read_text(encoding="utf-8")
            self.assertNotIn("javascript:", html_blob.lower())
            self.assertNotIn("javascript:", rss_blob.lower())
            self.assertIn('href="#"', html_blob)
            self.assertIn('Content-Security-Policy', html_blob)

    def test_safe_http_url_accepts_only_http_https(self):
        self.assertEqual(bf.safe_http_url("https://example.com/a"), "https://example.com/a")
        self.assertIsNone(bf.safe_http_url("javascript:alert(1)"))
        self.assertIsNone(bf.safe_http_url("data:text/html,hi"))
        self.assertIsNone(bf.safe_http_url("/relative"))


class TestXmlSafeText(unittest.TestCase):
    def test_control_char_stripped_so_feed_still_parses(self):
        it = bf.empty_item()
        dirty = "NVD note with \x01 control and \x07 bell"
        it.update(
            {
                "id": "CVE-2026-0001",
                "title": dirty,
                "links": ["https://nvd.nist.gov/vuln/detail/CVE-2026-0001"],
                "summary": dirty,
                "severity": "medium",
                "published": "2026-11-03T10:00:00Z",
                "first_seen": "2026-11-03T10:00:00Z",
                "cves": ["CVE-2026-0001"],
            }
        )
        with tempfile.TemporaryDirectory() as td:
            feed = os.path.join(td, "feed.xml")
            bf.sanitize_item_links([it])
            bf.write_feed_xml(feed, [it])
            # must parse as XML
            import xml.etree.ElementTree as ET
            ET.parse(feed)
            blob = Path(feed).read_text(encoding="utf-8")
            self.assertNotIn("\x01", blob)
            self.assertNotIn("\x07", blob)


class TestGuidPrecedence(unittest.TestCase):
    def test_id_used_when_links_empty(self):
        it = bf.empty_item()
        it.update(
            {
                "id": "CVE-2026-4242",
                "title": "Has id no links",
                "links": [],
                "summary": "x",
                "severity": "low",
                "published": "2026-11-03T10:00:00Z",
                "first_seen": "2026-11-03T10:00:00Z",
            }
        )
        with tempfile.TemporaryDirectory() as td:
            feed = os.path.join(td, "feed.xml")
            bf.write_feed_xml(feed, [it])
            blob = Path(feed).read_text(encoding="utf-8")
            self.assertIn("<guid", blob)
            self.assertIn("CVE-2026-4242", blob)


class TestDenyTermsEnv(unittest.TestCase):
    def test_env_terms_extend_leak_guard_without_names_in_source(self):
        # Fake terms only — real estate names must not appear in this file.
        os.environ["FEED_DENY_TERMS"] = "fakeseat,otherfake"
        try:
            pat = _private_host_re(_deny_terms_from_env())
            self.assertIsNotNone(pat.search("see fakeseat here"))
            self.assertIsNone(pat.search("innocent text"))
        finally:
            os.environ.pop("FEED_DENY_TERMS", None)
        self.assertIn("FEED_DENY_TERMS", Path(__file__).read_text(encoding="utf-8"))


def _load_checker():
    path = ROOT / "check_deny_terms.py"
    spec = importlib.util.spec_from_file_location("check_deny_terms", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


class TestBuiltSiteDenyCheck(unittest.TestCase):
    def test_hit_in_built_output_fails(self):
        chk = _load_checker()
        with tempfile.TemporaryDirectory() as td:
            Path(td, "feed.xml").write_text("<rss>see FakeSeat here</rss>", encoding="utf-8")
            Path(td, "index.html").write_text("<p>clean</p>", encoding="utf-8")
            os.environ["FEED_DENY_TERMS"] = "fakeseat,\r\notherfake"
            try:
                buf = io.StringIO()
                old = sys.stderr
                sys.stderr = buf
                try:
                    rc = chk.main(["x", td, "--require"])
                finally:
                    sys.stderr = old
                self.assertEqual(rc, 1)
                self.assertNotIn("fakeseat", buf.getvalue().lower())
                Path(td, "feed.xml").write_text("<rss>clean</rss>", encoding="utf-8")
                self.assertEqual(chk.main(["x", td, "--require"]), 0)
            finally:
                os.environ.pop("FEED_DENY_TERMS", None)

    def test_empty_terms_fail_closed_when_required(self):
        chk = _load_checker()
        os.environ.pop("FEED_DENY_TERMS", None)
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(chk.main(["x", td, "--require"]), 1)
            self.assertEqual(chk.main(["x", td]), 0)


class TestPartialFailureGuard(unittest.TestCase):
    def _run(self, kev_items):
        import build_feed as mod

        orig = (mod.collect_kev, mod.collect_ghsa, mod.collect_nvd, mod.collect_rss, mod.collect_telegram)
        try:
            mod.collect_kev = lambda *_a, **_k: (kev_items, None)
            mod.collect_ghsa = lambda *_a, **_k: ([], "GitHub Advisories failed: offline")
            mod.collect_nvd = lambda *_a, **_k: ([], "NVD failed: offline")
            mod.collect_rss = lambda *_a, **_k: ([], ["RSS x failed: offline"])
            mod.collect_telegram = lambda *_a, **_k: ([], "Telegram failed: offline")
            with tempfile.TemporaryDirectory() as td:
                old = sys.argv
                sys.argv = ["build_feed.py", "--hours", "1", "--outdir", td, "--no-store"]
                try:
                    rc = mod.main()
                finally:
                    sys.argv = old
                return rc, Path(td, "feed.xml").exists()
        finally:
            (mod.collect_kev, mod.collect_ghsa, mod.collect_nvd, mod.collect_rss, mod.collect_telegram) = orig

    def test_one_source_ok_but_empty_refuses(self):
        rc, wrote = self._run([])
        self.assertEqual(rc, 1)
        self.assertFalse(wrote)

    def test_partial_failure_below_floor_refuses(self):
        it = bf.empty_item()
        it.update({"id": "CVE-2026-0001", "cves": ["CVE-2026-0001"], "title": "t", "published": "2026-11-01T00:00:00Z"})
        rc, wrote = self._run([it])
        self.assertEqual(rc, 1)
        self.assertFalse(wrote)


class TestShouldFixes(unittest.TestCase):
    def test_news_with_two_ids_folds_both_records(self):
        a = bf.empty_item()
        a.update({"id": "CVE-2026-1111", "cves": ["CVE-2026-1111"], "title": "a", "severity": "high"})
        b = bf.empty_item()
        b.update({"id": "CVE-2026-2222", "cves": ["CVE-2026-2222"], "title": "b", "severity": "critical"})
        news = bf.empty_item()
        news.update({"id": "news", "cves": ["CVE-2026-1111", "CVE-2026-2222"], "title": "news"})
        out = bf.collapse_news_into_cves([a, b, news])
        self.assertEqual(len(out), 1)

    def test_xml_safe_text_keeps_astral_chars(self):
        self.assertEqual(bf.xml_safe_text("ok \U0001F512 \U00020000\x01"), "ok \U0001F512 \U00020000")

if __name__ == "__main__":
    unittest.main()


class TestRound2Fixes(unittest.TestCase):
    def test_escaped_deny_term_still_caught(self):
        chk = _load_checker()
        with tempfile.TemporaryDirectory() as td:
            Path(td, "feed.xml").write_text(
                "<rss>Fake &amp; Seat and Bob&#39;s Box and A&amp;amp;B</rss>", encoding="utf-8"
            )
            for term in ("fake & seat", "bob's box", "a&b"):
                os.environ["FEED_DENY_TERMS"] = term
                try:
                    old = sys.stderr
                    sys.stderr = io.StringIO()
                    try:
                        self.assertEqual(chk.main(["x", td, "--require"]), 1, term)
                    finally:
                        sys.stderr = old
                finally:
                    os.environ.pop("FEED_DENY_TERMS", None)

    def test_rss_parse_error_fails_source(self):
        with self.assertRaises(ET.ParseError):
            bf.RSSParser.parse(b"<rss><channel><item>broken")
        orig = bf.http_get
        try:
            bf.http_get = lambda *_a, **_k: b"<not xml"
            items, errors = bf.collect_rss(bf.now_utc())
        finally:
            bf.http_get = orig
        self.assertEqual(items, [])
        self.assertEqual(len(errors), len(bf.RSS_FEEDS))
        self.assertTrue(all("failed" in e for e in errors))
