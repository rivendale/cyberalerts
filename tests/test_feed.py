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
FIX = Path(__file__).resolve().parent / "fixtures"


def load_builder():
    path = ROOT / "build_feed.py"
    spec = importlib.util.spec_from_file_location("build_feed", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


bf = load_builder()

def _private_host_re():
    # Fragments joined at runtime; keep private estate names out of source text.
    parts = [
        r"localhost",
        r"127\.0\.0\.1",
        r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        r"192\.168\.\d{1,3}\.\d{1,3}",
        r"172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}",
        "home" + "lab",
        "nick" + "-laptop",
        "ry" + "giel",
        "protocol" + "[ -]?" + "wealth",
    ]
    return re.compile(r"(?i)\b(" + "|".join(parts) + r")\b")


PRIVATE_HOST_RE = _private_host_re()
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


if __name__ == "__main__":
    unittest.main()
