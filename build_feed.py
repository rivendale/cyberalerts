#!/usr/bin/env python3
"""Pennview Labs Cyber Alerts — public RSS feed builder.

Fetches public vulnerability and threat sources only, normalizes and dedupes,
and writes feed.xml (RSS 2.0) plus a minimal index.html. Stdlib only.

Usage:
  python3 build_feed.py [--hours 72] [--outdir site]

Public data only. Summaries are templated in our own words. Never copies article
bodies or Telegram posts wholesale. No internal host, stack, or client fields.
"""

from __future__ import annotations

import argparse
import email.utils
import html
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from typing import Any
from xml.dom import minidom

UA = "PennviewLabs-CyberAlerts/1.0 (+https://cyberalerts.pennviewlabs.com; public feed)"
TIMEOUT = 45
SUMMARY_MAX = 280
FEED_LIMIT = 50
DEFAULT_OUTDIR = "site"
TOPICS = [
    "ai-agents",
    "crypto-web3",
    "supply-chain",
    "browsers-playwright",
    "node-python",
    "mobile",
]

TOPIC_RULES: list[tuple[str, list[str]]] = [
    (
        "ai-agents",
        [
            "llm",
            "large language",
            "chatgpt",
            "openai",
            "anthropic",
            "claude",
            "copilot",
            "ai agent",
            "ai-agent",
            "langchain",
            "langflow",
            "autogen",
            "mcp server",
            "model context protocol",
            "prompt injection",
            "huggingface",
            "hugging face",
            "ollama",
            "agentic",
            "ai agents",
            "coding agent",
            "stanza",
            "deepset",
        ],
    ),
    (
        "crypto-web3",
        [
            "bitcoin",
            "ethereum",
            "web3",
            "blockchain",
            "defi",
            "smart contract",
            "crypto wallet",
            "cryptocurrency",
            "solidity",
            " nft",
            "token bridge",
            "metamask",
            "solana",
            "binance",
            "exchange hack",
            "web3 ",
            " crypto ",
            "cryptocurrency",
            "stablecoin",
            "uniswap",
            "openclaw",
        ],
    ),
    (
        "supply-chain",
        [
            "supply chain",
            "supply-chain",
            "typosquat",
            "dependency confusion",
            "malicious package",
            "package registry",
            "npm package",
            "pypi package",
            "compromised package",
            "backdoored",
            "poisoned package",
            "ci/cd",
            "github actions",
            "build pipeline",
            "software supply",
        ],
    ),
    (
        "browsers-playwright",
        [
            "chrome",
            "chromium",
            "firefox",
            "safari",
            "edge browser",
            "playwright",
            "puppeteer",
            "selenium",
            "browser exploit",
            "webkit",
            "v8 engine",
            "renderer rce",
        ],
    ),
    (
        "node-python",
        [
            "node.js",
            "nodejs",
            "npm",
            "npx",
            "express.js",
            "python",
            "pypi",
            "pip ",
            "django",
            "flask",
            "fastapi",
            "uvicorn",
            "typescript",
            "javascript package",
        ],
    ),
    (
        "mobile",
        [
            "android",
            "ios ",
            "iphone",
            "ipad",
            "mobile app",
            "apk ",
            "google play",
            "app store",
            "malware on mobile",
            "imessage",
            "whatsapp",
        ],
    ),
]

RSS_FEEDS = [
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    ("SANS ISC", "https://isc.sans.edu/rssfeed_full.xml"),
    ("Krebs on Security", "https://krebsonsecurity.com/feed/"),
]

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
GHSA_RE = re.compile(r"\bGHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b", re.I)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_iso(s: str | None) -> datetime | None:
    if not s:
        return None
    s = s.strip()
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s)
    except ValueError:
        pass
    try:
        # RFC 2822
        tt = email.utils.parsedate_to_datetime(s)
        if tt.tzinfo is None:
            tt = tt.replace(tzinfo=timezone.utc)
        return tt
    except (TypeError, ValueError, IndexError):
        return None


MAX_DOWNLOAD_BYTES = 5 * 1024 * 1024  # 5 MiB hard cap per response


def safe_http_url(u: str | None) -> str | None:
    """Accept only http(s) URLs. Drop javascript:, data:, and other schemes."""
    if not u:
        return None
    u = str(u).strip()
    if not u:
        return None
    try:
        p = urllib.parse.urlsplit(u)
    except ValueError:
        return None
    if p.scheme.lower() not in ("http", "https"):
        return None
    if not p.netloc:
        return None
    return urllib.parse.urlunsplit((p.scheme.lower(), p.netloc, p.path or "/", p.query, ""))


_XML_CHAR_RE = re.compile(
    r"[^\x09\x0A\x0D\x20-\uD7FF\uE000-\uFFFD\U00010000-\U0010FFFF]",
    flags=re.UNICODE,
)


def xml_safe_text(s: str | None) -> str:
    """Strip characters outside the XML 1.0 Char production."""
    if not s:
        return ""
    return _XML_CHAR_RE.sub("", str(s))


def http_get(url: str, headers: dict | None = None, timeout: int = TIMEOUT) -> bytes:
    h = {"User-Agent": UA, "Accept": "*/*"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, headers=h)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        chunks: list[bytes] = []
        total = 0
        while True:
            block = resp.read(64 * 1024)
            if not block:
                break
            total += len(block)
            if total > MAX_DOWNLOAD_BYTES:
                raise ValueError(f"response exceeds {MAX_DOWNLOAD_BYTES} byte cap for {url}")
            chunks.append(block)
        return b"".join(chunks)


def http_get_json(url: str, headers: dict | None = None) -> Any:
    raw = http_get(url, headers=headers)
    return json.loads(raw.decode("utf-8", errors="replace"))


def normalize_url(u: str) -> str:
    u = (u or "").strip()
    if not u:
        return ""
    p = urllib.parse.urlsplit(u)
    # drop fragment, normalize scheme/host case
    path = p.path.rstrip("/") or "/"
    return urllib.parse.urlunsplit((p.scheme.lower(), p.netloc.lower(), path, p.query, ""))


def severity_from_cvss(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def severity_from_ghsa(s: str | None) -> str | None:
    if not s:
        return None
    s = s.lower()
    if s in ("critical", "high", "medium", "moderate", "low"):
        return "medium" if s == "moderate" else s
    return None


def severity_rank(s: str | None) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get((s or "").lower(), 0)


def max_severity(a: str | None, b: str | None) -> str | None:
    if severity_rank(a) >= severity_rank(b):
        return a or b
    return b or a


def _kw_match(hay: str, kw: str) -> bool:
    """Substring match with light word-boundary care for short/ambiguous tokens."""
    kw = kw.lower()
    hay = hay.lower()
    # multi-word / already spaced phrases: plain substring
    if " " in kw or "-" in kw or len(kw) >= 8:
        return kw in hay
    # short tokens: require non-alnum boundaries
    return re.search(rf"(?<![a-z0-9]){re.escape(kw)}(?![a-z0-9])", hay) is not None


def detect_topics(text: str, ecosystems: list[str] | None = None) -> list[str]:
    t = " " + (text or "").lower() + " "
    # avoid cryptography != crypto/web3
    t_crypto = re.sub(r"cryptograph\w*", " ", t)
    found: list[str] = []
    for topic, kws in TOPIC_RULES:
        pool = t_crypto if topic == "crypto-web3" else t
        if any(_kw_match(pool, k) for k in kws):
            found.append(topic)
    ecos = [e.lower() for e in (ecosystems or [])]
    if any(e in ("npm", "pip", "pypi", "maven", "rubygems", "cargo", "composer", "nuget", "go", "actions") for e in ecos):
        if "supply-chain" not in found:
            found.append("supply-chain")
    if any(e in ("npm", "pip", "pypi") for e in ecos):
        if "node-python" not in found:
            found.append("node-python")
    # preserve order of TOPICS
    return [x for x in TOPICS if x in found]



def extract_ids(text: str) -> tuple[list[str], list[str]]:
    cves = sorted({m.group(0).upper() for m in CVE_RE.finditer(text or "")})
    ghsas = sorted({m.group(0).upper().replace("GHSA-", "GHSA-") for m in GHSA_RE.finditer(text or "")})
    # normalize GHSA to lowercase after prefix? GitHub uses lowercase: GHSA-xxxx-xxxx-xxxx with lowercase hex
    ghsas = sorted({("GHSA-" + g[5:].lower()) if g.upper().startswith("GHSA-") else g for g in ghsas})
    return cves, ghsas


def strip_html(s: str) -> str:
    s = re.sub(r"(?is)<script.*?>.*?</script>", " ", s or "")
    s = re.sub(r"(?is)<style.*?>.*?</style>", " ", s)
    s = re.sub(r"(?s)<[^>]+>", " ", s)
    s = html.unescape(s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def templated_summary(
    kind: str,
    title: str,
    severity: str | None,
    cves: list[str],
    exploited: bool,
    topics: list[str],
) -> str:
    sev = (severity or "unknown").upper()
    idbit = ""
    if cves:
        idbit = f" ({', '.join(cves[:3])})"
    wild = " Reported as exploited in the wild." if exploited else ""
    topicbit = f" Topics: {', '.join(topics)}." if topics else ""
    base = {
        "kev": f"CISA KEV addition{idbit}: {title}. Severity at least HIGH (known exploited).{topicbit}",
        "ghsa": f"GitHub advisory{idbit}: {title}. Severity {sev}.{wild}{topicbit}",
        "nvd": f"NVD published{idbit}: {title}. Severity {sev}.{wild}{topicbit}",
        "rss": f"Security news: {title}.{idbit} Severity {sev if severity else 'n/a'}.{wild}{topicbit}",
        "telegram": f"Public Telegram signal: {title}.{idbit} Treat as unconfirmed until vendor/CVE corroboration.{topicbit}",
    }.get(kind, f"Alert: {title}.{idbit} Severity {sev}.{wild}{topicbit}")
    return base.strip()[:SUMMARY_MAX]


def empty_item() -> dict:
    return {
        "id": "",
        "title": "",
        "sources": [],
        "links": [],
        "published": None,
        "severity": None,
        "exploited_in_wild": False,
        "topics": [],
        "unconfirmed": False,
        "summary": "",
        "first_seen": None,
        "relayed_to": [],
        "cves": [],
        "ghsa_ids": [],
    }


def load_jsonl(path: str) -> list[dict]:
    items = []
    if not os.path.exists(path):
        return items
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return items


def save_jsonl(path: str, items: list[dict]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for it in items:
            f.write(json.dumps(it, ensure_ascii=False) + "\n")


def load_state(path: str) -> dict:
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"sources": {}}


def save_state(path: str, state: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)
        f.write("\n")


def merge_item(existing: dict, new: dict) -> dict:
    out = dict(existing)
    # sources / links union
    out["sources"] = sorted(set(out.get("sources") or []) | set(new.get("sources") or []))
    links = []
    seen = set()
    for L in (out.get("links") or []) + (new.get("links") or []):
        n = normalize_url(L)
        if n and n not in seen:
            seen.add(n)
            links.append(L)
    out["links"] = links
    out["cves"] = sorted(set(out.get("cves") or []) | set(new.get("cves") or []))
    out["ghsa_ids"] = sorted(set(out.get("ghsa_ids") or []) | set(new.get("ghsa_ids") or []))
    out["topics"] = [t for t in TOPICS if t in set(out.get("topics") or []) | set(new.get("topics") or [])]
    out["severity"] = max_severity(out.get("severity"), new.get("severity"))
    out["exploited_in_wild"] = bool(out.get("exploited_in_wild") or new.get("exploited_in_wild"))
    # unconfirmed stays true only if still no CVE/GHSA and both say unconfirmed
    has_id = bool(out["cves"] or out["ghsa_ids"])
    if has_id:
        out["unconfirmed"] = False
    else:
        out["unconfirmed"] = bool(out.get("unconfirmed") and new.get("unconfirmed", True))
    # prefer earlier published
    op = parse_iso(out.get("published"))
    np_ = parse_iso(new.get("published"))
    if op and np_:
        out["published"] = iso(min(op, np_))
    elif np_ and not op:
        out["published"] = new.get("published")
    # keep better title (prefer non-empty longer if existing empty)
    if not out.get("title") and new.get("title"):
        out["title"] = new["title"]
    # prefer more specific summary from authoritative sources
    src_rank = {"CISA KEV": 5, "NVD": 4, "GitHub Advisory": 4}
    er = max((src_rank.get(s, 1) for s in (existing.get("sources") or [])), default=0)
    nr = max((src_rank.get(s, 1) for s in (new.get("sources") or [])), default=0)
    if nr > er and new.get("summary"):
        out["summary"] = new["summary"]
    elif not out.get("summary"):
        out["summary"] = new.get("summary") or ""
    out["first_seen"] = out.get("first_seen") or new.get("first_seen")
    out["relayed_to"] = out.get("relayed_to") or []
    # prefer stable id: CVE > GHSA > existing
    if out["cves"]:
        out["id"] = out["cves"][0]
    elif out["ghsa_ids"]:
        out["id"] = out["ghsa_ids"][0]
    else:
        out["id"] = out.get("id") or new.get("id") or ""
    return out


def dedupe_key(item: dict) -> str:
    if item.get("cves"):
        return "cve:" + sorted(item["cves"])[0].upper()
    if item.get("ghsa_ids"):
        return "ghsa:" + sorted(item["ghsa_ids"])[0].lower()
    if item.get("id") and str(item["id"]).upper().startswith("CVE-"):
        return "cve:" + item["id"].upper()
    if item.get("id") and str(item["id"]).upper().startswith("GHSA-"):
        return "ghsa:" + item["id"].lower()
    links = item.get("links") or []
    if links:
        return "url:" + normalize_url(links[0])
    return "title:" + re.sub(r"\W+", " ", (item.get("title") or "").lower()).strip()[:120]


# ---------- collectors ----------

def collect_kev(cutoff: datetime) -> tuple[list[dict], str | None]:
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        data = http_get_json(url)
    except Exception as e:
        return [], f"CISA KEV failed: {e}"
    vulns = data.get("vulnerabilities") or []
    out = []
    seen_at = now_utc()
    for v in vulns:
        cve = (v.get("cveID") or "").upper()
        if not cve:
            continue
        # dateAdded is YYYY-MM-DD
        added = parse_iso((v.get("dateAdded") or "") + "T00:00:00+00:00")
        # Also include if dueDate recent? Stick to dateAdded within window, OR always keep recent additions
        if added and added < cutoff:
            continue
        title = v.get("vulnerabilityName") or cve
        vendor = v.get("vendorProject") or ""
        product = v.get("product") or ""
        req_action = v.get("requiredAction") or ""
        text = f"{title} {vendor} {product} {v.get('shortDescription','')} {req_action}"
        topics = detect_topics(text)
        item = empty_item()
        item.update(
            {
                "id": cve,
                "title": title,
                "sources": ["CISA KEV"],
                "links": [f"https://nvd.nist.gov/vuln/detail/{cve}", url],
                "published": iso(added) if added else iso(seen_at),
                "severity": "high",  # KEV = at least high; bump critical if ransomware or high-impact wording
                "exploited_in_wild": True,
                "topics": topics,
                "unconfirmed": False,
                "summary": templated_summary("kev", title, "high", [cve], True, topics),
                "first_seen": iso(seen_at),
                "cves": [cve],
                "ghsa_ids": [],
            }
        )
        notes = (v.get("notes") or "") + " " + (v.get("shortDescription") or "")
        if re.search(r"critical|ransomware|remote code", notes, re.I):
            item["severity"] = "critical"
            item["summary"] = templated_summary("kev", title, "critical", [cve], True, topics)
        out.append(item)
    return out, None


def collect_ghsa(cutoff: datetime) -> tuple[list[dict], str | None]:
    # GitHub returns newest first; page until older than cutoff
    out: list[dict] = []
    err = None
    seen_at = now_utc()
    page = 1
    try:
        while page <= 5:
            url = (
                "https://api.github.com/advisories?"
                + urllib.parse.urlencode(
                    {
                        "type": "reviewed",
                        "per_page": "100",
                        "page": str(page),
                    }
                )
            )
            headers = {
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }
            # Prefer gh token if present via env (read-only)
            token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
            if token:
                headers["Authorization"] = f"Bearer {token}"
            batch = http_get_json(url, headers=headers)
            if not isinstance(batch, list) or not batch:
                break
            stop = False
            for a in batch:
                pub = parse_iso(a.get("published_at") or a.get("updated_at"))
                if pub and pub < cutoff:
                    stop = True
                    # still may have newer later? API is published desc typically
                    continue
                if not pub:
                    pub = seen_at
                ghsa = a.get("ghsa_id") or ""
                cve = (a.get("cve_id") or "")
                cves = [cve.upper()] if cve else []
                summary_title = a.get("summary") or ghsa
                sev = severity_from_ghsa(a.get("severity"))
                ecos = []
                for v in a.get("vulnerabilities") or []:
                    pkg = v.get("package") or {}
                    eco = pkg.get("ecosystem")
                    if eco:
                        ecos.append(eco)
                text = f"{summary_title} {a.get('description','')} {' '.join(ecos)}"
                topics = detect_topics(text, ecos)
                # CVSS if present
                cvss = a.get("cvss") or {}
                score = cvss.get("score") if isinstance(cvss, dict) else None
                if score is not None:
                    sev = max_severity(sev, severity_from_cvss(float(score)))
                item = empty_item()
                item.update(
                    {
                        "id": (cves[0] if cves else ghsa),
                        "title": summary_title[:240],
                        "sources": ["GitHub Advisory"],
                        "links": [a.get("html_url") or f"https://github.com/advisories/{ghsa}"],
                        "published": iso(pub),
                        "severity": sev or "medium",
                        "exploited_in_wild": False,
                        "topics": topics,
                        "unconfirmed": False,
                        "summary": templated_summary(
                            "ghsa", summary_title[:200], sev or "medium", cves, False, topics
                        ),
                        "first_seen": iso(seen_at),
                        "cves": cves,
                        "ghsa_ids": [ghsa] if ghsa else [],
                    }
                )
                out.append(item)
            if stop or len(batch) < 100:
                break
            page += 1
            time.sleep(0.4)
    except Exception as e:
        err = f"GitHub Advisories failed: {e}"
    return out, err


def collect_nvd(cutoff: datetime, end: datetime) -> tuple[list[dict], str | None]:
    # NVD API 2.0 without key: ~5 requests / 30s. Keep CVSS >= 7 or topic match.
    out: list[dict] = []
    err = None
    seen_at = now_utc()
    start_s = cutoff.strftime("%Y-%m-%dT%H:%M:%S.000")
    end_s = end.strftime("%Y-%m-%dT%H:%M:%S.000")
    start_index = 0
    page_size = 200
    try:
        while True:
            q = urllib.parse.urlencode(
                {
                    "pubStartDate": start_s,
                    "pubEndDate": end_s,
                    "resultsPerPage": str(page_size),
                    "startIndex": str(start_index),
                }
            )
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{q}"
            # polite delay
            time.sleep(6.5)
            data = http_get_json(url)
            vulns = data.get("vulnerabilities") or []
            total = int(data.get("totalResults") or 0)
            for wrap in vulns:
                cve_obj = wrap.get("cve") or {}
                cve_id = (cve_obj.get("id") or "").upper()
                if not cve_id:
                    continue
                published = parse_iso(cve_obj.get("published"))
                descs = cve_obj.get("descriptions") or []
                desc = ""
                for d in descs:
                    if d.get("lang") == "en":
                        desc = d.get("value") or ""
                        break
                if not desc and descs:
                    desc = descs[0].get("value") or ""
                # CVSS score
                score = None
                metrics = cve_obj.get("metrics") or {}
                for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    arr = metrics.get(key) or []
                    if arr:
                        cvss_data = (arr[0].get("cvssData") or {})
                        score = cvss_data.get("baseScore")
                        if score is not None:
                            score = float(score)
                        break
                sev = severity_from_cvss(score)
                text = f"{cve_id} {desc}"
                topics = detect_topics(text)
                keep = (score is not None and score >= 7.0) or bool(topics)
                if not keep:
                    continue
                exploited = False
                # weakenings / CISA
                for w in cve_obj.get("cisaExploitAdd") and [1] or []:
                    exploited = True
                if cve_obj.get("cisaExploitAdd"):
                    exploited = True
                refs = []
                for r in cve_obj.get("references") or []:
                    u = r.get("url")
                    if u:
                        refs.append(u)
                links = [f"https://nvd.nist.gov/vuln/detail/{cve_id}"] + refs[:3]
                title = desc.split(".")[0][:200] if desc else cve_id
                if len(title) < 12:
                    title = (desc[:200] if desc else cve_id)
                item = empty_item()
                item.update(
                    {
                        "id": cve_id,
                        "title": title,
                        "sources": ["NVD"],
                        "links": links,
                        "published": iso(published) if published else iso(seen_at),
                        "severity": sev or ("high" if score and score >= 7 else "medium"),
                        "exploited_in_wild": exploited,
                        "topics": topics,
                        "unconfirmed": False,
                        "summary": templated_summary(
                            "nvd", title, sev or "high", [cve_id], exploited, topics
                        ),
                        "first_seen": iso(seen_at),
                        "cves": [cve_id],
                        "ghsa_ids": [],
                    }
                )
                out.append(item)
            start_index += page_size
            if start_index >= total or not vulns:
                break
            if start_index > 2000:
                # safety cap for no-key runs
                break
    except Exception as e:
        err = f"NVD failed: {e}"
    return out, err


class RSSParser:
    """Minimal RSS/Atom parser via ElementTree."""

    @staticmethod
    def parse(content: bytes) -> list[dict]:
        items = []
        try:
            root = ET.fromstring(content)
        except ET.ParseError:
            return items
        # strip namespaces for simplicity
        def local(tag: str) -> str:
            return tag.split("}")[-1] if "}" in tag else tag

        root_l = local(root.tag).lower()
        # RSS 2.0
        channels = [c for c in root.iter() if local(c.tag).lower() == "channel"]
        if channels or root_l == "rss":
            for it in root.iter():
                if local(it.tag).lower() != "item":
                    continue
                title = link = desc = pub = guid = ""
                for ch in list(it):
                    ln = local(ch.tag).lower()
                    text = (ch.text or "").strip()
                    if ln == "title":
                        title = text
                    elif ln == "link":
                        link = text or (ch.get("href") or "")
                    elif ln in ("description", "summary", "content"):
                        desc = text
                    elif ln in ("pubdate", "published", "date", "updated"):
                        pub = text
                    elif ln == "guid":
                        guid = text
                items.append(
                    {"title": title, "link": link or guid, "description": desc, "published": pub}
                )
            return items
        # Atom
        for it in root.iter():
            if local(it.tag).lower() != "entry":
                continue
            title = link = desc = pub = ""
            for ch in list(it):
                ln = local(ch.tag).lower()
                text = (ch.text or "").strip()
                if ln == "title":
                    title = text
                elif ln == "link":
                    href = ch.get("href") or text
                    rel = (ch.get("rel") or "alternate").lower()
                    if href and (rel == "alternate" or not link):
                        link = href
                elif ln in ("summary", "content"):
                    desc = text
                elif ln in ("published", "updated"):
                    if not pub or ln == "published":
                        pub = text
            items.append({"title": title, "link": link, "description": desc, "published": pub})
        return items


def collect_rss(cutoff: datetime) -> tuple[list[dict], list[str]]:
    out: list[dict] = []
    errors: list[str] = []
    seen_at = now_utc()
    for name, url in RSS_FEEDS:
        try:
            raw = http_get(url)
            entries = RSSParser.parse(raw)
            for e in entries:
                pub = parse_iso(e.get("published"))
                if pub and pub < cutoff:
                    continue
                if not pub:
                    # if undated, keep but mark published as now (still may be noise)
                    pub = seen_at
                title = strip_html(e.get("title") or "")[:240]
                link = e.get("link") or ""
                desc = strip_html(e.get("description") or "")[:800]
                text = f"{title} {desc}"
                cves, ghsas = extract_ids(text)
                # also from title only for id priority
                topics = detect_topics(text)
                exploited = bool(
                    re.search(
                        r"exploited in the wild|active exploit|being exploited|in the wild|exploited in attacks|actively exploited",
                        text,
                        re.I,
                    )
                )
                sev = None
                if re.search(r"\bcritical\b", text, re.I):
                    sev = "critical"
                elif re.search(r"\bhigh(-|\s)?severity\b|\bsevere\b", text, re.I):
                    sev = "high"
                item = empty_item()
                item_id = cves[0] if cves else (ghsas[0] if ghsas else normalize_url(link) or title[:80])
                item.update(
                    {
                        "id": item_id,
                        "title": title,
                        "sources": [name],
                        "links": [u] if (u := safe_http_url(link)) else [],
                        "published": iso(pub),
                        "severity": sev,
                        "exploited_in_wild": exploited,
                        "topics": topics,
                        "unconfirmed": not bool(cves or ghsas),
                        "summary": templated_summary(
                            "rss", title, sev, cves, exploited, topics
                        ),
                        "first_seen": iso(seen_at),
                        "cves": cves,
                        "ghsa_ids": ghsas,
                    }
                )
                if not item["links"]:
                    continue
                out.append(item)
            time.sleep(0.3)
        except Exception as e:
            errors.append(f"RSS {name} failed: {e}")
    return out, errors


class TelegramHTMLParser(HTMLParser):
    """Parse t.me/s/... preview HTML into {text, link, date} records.

    Outer message containers use class exactly starting with
    ``tgme_widget_message `` (space-separated). Nested widgets such as
    ``tgme_widget_message_bubble`` / ``_text`` must not reset the current
    message. Finalize only when the outer message div closes, after the
    footer link and ``<time datetime>`` have been seen.
    """

    def __init__(self):
        super().__init__()
        self.messages: list[dict] = []
        self._in_text = False
        self._in_date = False
        self._cur: dict | None = None
        self._text_parts: list[str] = []
        self._depth_text = 0
        self._msg_depth = 0

    @staticmethod
    def _is_outer_message(tag: str, cls: str) -> bool:
        if tag != "div":
            return False
        classes = cls.split()
        # Exact token match for the outer widget; ignore nested *_bubble / *_text / *_wrapped
        return "tgme_widget_message" in classes and not any(
            c.startswith("tgme_widget_message_") for c in classes
        )

    def handle_starttag(self, tag, attrs):
        ad = dict(attrs)
        cls = ad.get("class", "")
        if self._is_outer_message(tag, cls):
            self._cur = {
                "text": "",
                "link": (f"https://t.me/{ad['data-post']}" if ad.get("data-post") else ""),
                "date": None,
            }
            self._text_parts = []
            self._msg_depth = 1
            self._in_text = False
            self._depth_text = 0
            return
        if self._cur is None:
            return
        if tag == "div":
            self._msg_depth += 1
        if tag == "a" and "tgme_widget_message_date" in cls.split():
            href = ad.get("href") or ""
            if href:
                self._cur["link"] = href
            self._in_date = True
        if tag == "time":
            dt = ad.get("datetime")
            if dt:
                self._cur["date"] = dt
        if tag == "div" and "tgme_widget_message_text" in cls.split():
            self._in_text = True
            self._depth_text = 1
            self._text_parts = []
        elif self._in_text and tag == "div":
            self._depth_text += 1
        if self._in_text and tag == "br":
            self._text_parts.append("\n")
        if self._in_text and tag == "a":
            href = ad.get("href") or ""
            if href and "t.me/" not in href:
                self._text_parts.append(f" {href} ")

    def handle_endtag(self, tag):
        if self._cur is None:
            return
        if self._in_date and tag == "a":
            self._in_date = False
        if self._in_text and tag == "div":
            self._depth_text -= 1
            if self._depth_text <= 0:
                self._in_text = False
                self._cur["text"] = "".join(self._text_parts).strip()
                self._text_parts = []
        if tag == "div":
            self._msg_depth -= 1
            if self._msg_depth <= 0:
                if self._cur.get("text") or self._cur.get("link"):
                    self.messages.append(self._cur)
                self._cur = None
                self._msg_depth = 0
                self._in_text = False
                self._depth_text = 0

    def handle_data(self, data):
        if self._in_text and self._cur is not None:
            self._text_parts.append(data)


def collect_telegram(cutoff: datetime) -> tuple[list[dict], str | None]:
    url = "https://t.me/s/IntCyberDigest"
    try:
        raw = http_get(url)
    except Exception as e:
        return [], f"Telegram IntCyberDigest failed: {e}"
    html_text = raw.decode("utf-8", errors="replace")
    parser = TelegramHTMLParser()
    try:
        parser.feed(html_text)
    except Exception as e:
        return [], f"Telegram parse failed: {e}"
    # Regex fallback for date+link+text when HTMLParser nesting misses datetime
    if not parser.messages or not any(m.get("date") for m in parser.messages):
        fallback = []
        for block in re.finditer(
            r'class="tgme_widget_message[^"]*"[^>]*?(?:data-post="(?P<post>[^"]+)")?.*?'
            r'class="tgme_widget_message_date"[^>]*href="(?P<href>[^"]+)".*?'
            r'<time[^>]*datetime="(?P<dt>[^"]+)".*?'
            r'class="tgme_widget_message_text[^"]*"[^>]*>(?P<body>.*?)</div>',
            html_text,
            re.S | re.I,
        ):
            body = strip_html(block.group("body"))
            href = block.group("href") or url
            fallback.append({"text": body, "link": href, "date": block.group("dt")})
        if fallback:
            parser.messages = fallback
    out = []
    seen_at = now_utc()
    for m in parser.messages:
        pub = parse_iso(m.get("date"))
        if pub and pub < cutoff:
            continue
        if not pub:
            pub = seen_at
        text = strip_html(m.get("text") or "")
        if not text:
            continue
        # NEVER store wholesale post; derive short title + templated summary only
        title = text.split("\n")[0][:160]
        title = re.sub(r"\s+", " ", title).strip()
        cves, ghsas = extract_ids(text)
        topics = detect_topics(text)
        exploited = bool(
            re.search(r"exploited in the wild|actively exploited|active exploit", text, re.I)
        )
        link = m.get("link") or url
        # Only keep if CVE/GHSA or relevant topics (avoid dumping whole channel)
        if not (cves or ghsas or topics or exploited):
            # keep high-signal keywords
            if not re.search(
                r"vulnerab|rce|zero[- ]day|malware|ransomware|breach|exploit|advisory|patch",
                text,
                re.I,
            ):
                continue
        item = empty_item()
        item_id = cves[0] if cves else (ghsas[0] if ghsas else normalize_url(link))
        item.update(
            {
                "id": item_id,
                "title": title,
                "sources": ["Telegram IntCyberDigest"],
                "links": ([u] if (u := safe_http_url(link)) else []),
                "published": iso(pub),
                "severity": "high" if exploited else None,
                "exploited_in_wild": exploited,
                "topics": topics,
                "unconfirmed": not bool(cves or ghsas),
                "summary": templated_summary(
                    "telegram", title, "high" if exploited else None, cves, exploited, topics
                ),
                "first_seen": iso(seen_at),
                "cves": cves,
                "ghsa_ids": ghsas,
            }
        )
        out.append(item)
    return out, None


def collapse_news_into_cves(items: list[dict]) -> list[dict]:
    """Merge items that share a CVE or GHSA id into one record.

    Advisories that carry both a CVE and a GHSA must still collapse with news
    that mentions only one of those identifiers. Index every known id, not only
    each record's preferred dedupe key.
    """
    records: list[dict] = []
    by_cve: dict[str, int] = {}
    by_ghsa: dict[str, int] = {}

    def _index(idx: int, it: dict) -> None:
        for c in it.get("cves") or []:
            by_cve[c.upper()] = idx
        for g in it.get("ghsa_ids") or []:
            by_ghsa[g.lower()] = idx

    def _find_all(it: dict) -> list[int]:
        hits: list[int] = []
        for c in it.get("cves") or []:
            i = by_cve.get(c.upper())
            if i is not None and i not in hits:
                hits.append(i)
        for g in it.get("ghsa_ids") or []:
            i = by_ghsa.get(g.lower())
            if i is not None and i not in hits:
                hits.append(i)
        # also honor preferred key when id fields were only on .id
        key = dedupe_key(it)
        i = None
        if key.startswith("cve:"):
            i = by_cve.get(key.split(":", 1)[1].upper())
        elif key.startswith("ghsa:"):
            i = by_ghsa.get(key.split(":", 1)[1].lower())
        if i is not None and i not in hits:
            hits.append(i)
        return sorted(hits)

    url_map: dict[str, int] = {}
    dead: set[int] = set()
    for it in items:
        hits = _find_all(it)
        if hits:
            # News that names several ids merges into every matching record,
            # and those records fold into one so an advisory never appears twice.
            keep = hits[0]
            records[keep] = merge_item(records[keep], it)
            for other in hits[1:]:
                records[keep] = merge_item(records[keep], records[other])
                dead.add(other)
            _index(keep, records[keep])
            continue
        key = dedupe_key(it)
        if key.startswith("url:") or key.startswith("title:"):
            if key in url_map:
                idx = url_map[key]
                records[idx] = merge_item(records[idx], it)
                _index(idx, records[idx])
                continue
            url_map[key] = len(records)
        records.append(it)
        _index(len(records) - 1, it)
    return [r for i, r in enumerate(records) if i not in dead]



def sanitize_item_links(items: list[dict]) -> None:
    """Drop non-http(s) links from each item in place."""
    for it in items:
        raw = it.get("links") or []
        it["links"] = [u for u in (safe_http_url(x) for x in raw) if u]
        for key in ("title", "summary", "id"):
            if it.get(key):
                it[key] = xml_safe_text(it[key])


def write_feed_xml(path: str, items: list[dict], limit: int = FEED_LIMIT) -> None:
    # sort by published desc
    def pub_key(it: dict):
        dt = parse_iso(it.get("published")) or parse_iso(it.get("first_seen")) or datetime(1970, 1, 1, tzinfo=timezone.utc)
        return dt

    ranked = sorted(items, key=pub_key, reverse=True)[:limit]
    rss = ET.Element("rss", version="2.0")
    channel = ET.SubElement(rss, "channel")
    ET.SubElement(channel, "title").text = "Pennview Labs Cyber Alerts"
    ET.SubElement(channel, "link").text = "https://cyberalerts.pennviewlabs.com/"
    ET.SubElement(channel, "description").text = (
        "Public vulnerability and threat signals from Pennview Labs. Summaries are original/templated; no full article or Telegram text."
    )
    ET.SubElement(channel, "language").text = "en-us"
    ET.SubElement(channel, "lastBuildDate").text = email.utils.format_datetime(now_utc())

    for it in ranked:
        entry = ET.SubElement(channel, "item")
        title = xml_safe_text(it.get("title") or it.get("id") or "alert")
        ET.SubElement(entry, "title").text = title
        raw_links = it.get("links") or []
        links = [u for u in (safe_http_url(x) for x in raw_links) if u]
        if links:
            ET.SubElement(entry, "link").text = xml_safe_text(links[0])
        guid = ET.SubElement(entry, "guid", isPermaLink="false")
        guid.text = xml_safe_text(str(it.get("id") or (links[0] if links else title)))
        pub = parse_iso(it.get("published"))
        if pub:
            ET.SubElement(entry, "pubDate").text = email.utils.format_datetime(pub)
        # description: own summary + severity + tags; never article text
        sev = it.get("severity") or "unknown"
        topics = it.get("topics") or []
        ids = []
        ids.extend(it.get("cves") or [])
        ids.extend(it.get("ghsa_ids") or [])
        bits = [it.get("summary") or title]
        bits.append(f"Severity: {sev}.")
        if ids:
            bits.append("IDs: " + ", ".join(ids) + ".")
        if it.get("exploited_in_wild"):
            bits.append("Exploited in the wild: yes.")
        if it.get("unconfirmed"):
            bits.append("Unconfirmed claim.")
        if topics:
            bits.append("Topics: " + ", ".join(topics) + ".")
        ET.SubElement(entry, "description").text = xml_safe_text(" ".join(bits))
        ET.SubElement(entry, "category").text = sev
        for t in topics:
            ET.SubElement(entry, "category").text = t
        if it.get("exploited_in_wild"):
            ET.SubElement(entry, "category").text = "exploited-in-wild"
        for src in it.get("sources") or []:
            ET.SubElement(entry, "category").text = f"source:{src}"

    rough = ET.tostring(rss, encoding="utf-8", xml_declaration=True)
    # pretty print
    try:
        pretty = minidom.parseString(rough).toprettyxml(indent="  ", encoding="utf-8")
        # minidom adds extra XML declaration handling
        with open(path, "wb") as f:
            f.write(pretty)
    except Exception:
        with open(path, "wb") as f:
            f.write(rough)

    # validate parse
    ET.parse(path)


def write_index_html(path: str, items: list[dict], limit: int = FEED_LIMIT) -> None:
    """Minimal static landing page pointing at the RSS feed."""

    def pub_key(it: dict):
        dt = (
            parse_iso(it.get("published"))
            or parse_iso(it.get("first_seen"))
            or datetime(1970, 1, 1, tzinfo=timezone.utc)
        )
        return dt

    ranked = sorted(items, key=pub_key, reverse=True)[:limit]
    rows = []
    for it in ranked[:20]:
        title = html.escape(xml_safe_text(it.get("title") or it.get("id") or "alert"))
        sev = html.escape((it.get("severity") or "unknown").lower())
        safe = safe_http_url((it.get("links") or [None])[0])
        link = html.escape(safe) if safe else "#"
        rows.append(
            f'<li><span class="sev {sev}">{sev}</span> <a href="{link}">{title}</a></li>'
        )
    body_list = "\n".join(rows) if rows else "<li>No items in the current window.</li>"
    page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'">
<title>Pennview Labs Cyber Alerts</title>
<meta name="description" content="Public vulnerability and threat RSS feed from Pennview Labs.">
<link rel="alternate" type="application/rss+xml" title="Pennview Labs Cyber Alerts" href="/feed.xml">
<style>
body{{font-family:system-ui,sans-serif;max-width:42rem;margin:2rem auto;padding:0 1rem;line-height:1.5;color:#122}}
a{{color:#064}} h1{{font-size:1.5rem}} .sev{{font-size:.75rem;text-transform:uppercase;margin-right:.4rem}}
.critical{{color:#a00}} .high{{color:#c60}} .medium{{color:#880}} .low{{color:#464}}
ul{{padding-left:1.2rem}} footer{{margin-top:2rem;font-size:.85rem;color:#456}}
</style>
</head>
<body>
<header><h1>Pennview Labs Cyber Alerts</h1>
<p>Public vulnerability and threat signals. Summaries are templated in our own words; we never republish article or Telegram text wholesale.</p>
<p><a href="/feed.xml">RSS feed (feed.xml)</a></p>
</header>
<main>
<h2>Recent items</h2>
<ul>
{body_list}
</ul>
</main>
<footer>
<p>Sources: CISA KEV, GitHub Advisories, NVD CVE API 2.0, BleepingComputer, The Hacker News, SANS ISC, Krebs on Security, and the public Telegram web preview of IntCyberDigest. Public data only.</p>
<p><a href="https://pennviewlabs.com/">Pennview Labs</a></p>
</footer>
</body>
</html>
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(page)


def write_cname(path: str, domain: str = "cyberalerts.pennviewlabs.com") -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(domain + "\n")



def main() -> int:
    ap = argparse.ArgumentParser(description="Pennview Labs Cyber Alerts public feed builder")
    ap.add_argument("--hours", type=float, default=48.0, help="Lookback window in hours")
    ap.add_argument("--outdir", default=DEFAULT_OUTDIR, help="Output directory for feed.xml and index.html")
    ap.add_argument("--no-store", action="store_true", help="Skip store.jsonl persistence (CI/Pages)")
    ap.add_argument(
        "--min-items",
        type=int,
        default=5,
        help="When any source failed, refuse to publish fewer items than this (an empty feed is always refused)",
    )
    args = ap.parse_args()

    outdir = args.outdir
    os.makedirs(outdir, exist_ok=True)
    store_path = os.path.join(outdir, "store.jsonl")
    state_path = os.path.join(outdir, "state.json")
    feed_path = os.path.join(outdir, "feed.xml")
    persist = not args.no_store

    end = now_utc()
    cutoff = end - timedelta(hours=args.hours)
    state = load_state(state_path) if persist else {"sources": {}}
    existing = load_jsonl(store_path) if persist else []
    existing_map: dict[str, dict] = {}
    for it in existing:
        existing_map[dedupe_key(it)] = it

    collected: list[dict] = []
    source_status: dict[str, str] = {}

    print(f"Collecting lookback={args.hours}h cutoff={iso(cutoff)} ...", flush=True)

    # KEV
    items, err = collect_kev(cutoff)
    collected.extend(items)
    source_status["cisa_kev"] = err or f"ok ({len(items)} in window)"
    state.setdefault("sources", {})["cisa_kev"] = {
        "last_run": iso(end),
        "status": "error" if err else "ok",
        "detail": err or f"{len(items)} items",
    }
    print(f"  CISA KEV: {source_status['cisa_kev']}", flush=True)

    # GHSA
    items, err = collect_ghsa(cutoff)
    collected.extend(items)
    source_status["github_advisories"] = err or f"ok ({len(items)} in window)"
    state["sources"]["github_advisories"] = {
        "last_run": iso(end),
        "status": "error" if err else "ok",
        "detail": err or f"{len(items)} items",
    }
    print(f"  GitHub Advisories: {source_status['github_advisories']}", flush=True)

    # NVD
    items, err = collect_nvd(cutoff, end)
    collected.extend(items)
    source_status["nvd"] = err or f"ok ({len(items)} kept)"
    state["sources"]["nvd"] = {
        "last_run": iso(end),
        "status": "error" if err else "ok",
        "detail": err or f"{len(items)} items",
    }
    print(f"  NVD: {source_status['nvd']}", flush=True)

    # RSS
    items, errors = collect_rss(cutoff)
    collected.extend(items)
    if errors:
        source_status["rss"] = f"partial ({len(items)} items); " + "; ".join(errors)
    else:
        source_status["rss"] = f"ok ({len(items)} items)"
    state["sources"]["rss"] = {
        "last_run": iso(end),
        "status": "error" if (errors and not items) else ("partial" if errors else "ok"),
        "detail": source_status["rss"],
    }
    for e in errors:
        print(f"  ! {e}", flush=True)
    print(f"  RSS: {source_status['rss']}", flush=True)

    # Telegram
    items, err = collect_telegram(cutoff)
    collected.extend(items)
    source_status["telegram_intcyberdigest"] = err or f"ok ({len(items)} in window)"
    state["sources"]["telegram_intcyberdigest"] = {
        "last_run": iso(end),
        "status": "error" if err else "ok",
        "detail": err or f"{len(items)} items",
    }
    print(f"  Telegram: {source_status['telegram_intcyberdigest']}", flush=True)

    # collapse / dedupe among new, then merge into store
    collapsed = collapse_news_into_cves(collected)
    new_count = 0
    updated_count = 0
    for it in collapsed:
        k = dedupe_key(it)
        if k in existing_map:
            before = json.dumps(existing_map[k], sort_keys=True)
            existing_map[k] = merge_item(existing_map[k], it)
            after = json.dumps(existing_map[k], sort_keys=True)
            if before != after:
                updated_count += 1
        else:
            existing_map[k] = it
            new_count += 1

    all_items = list(existing_map.values())
    # stable sort
    all_items.sort(
        key=lambda x: parse_iso(x.get("published")) or parse_iso(x.get("first_seen")) or datetime(1970, 1, 1, tzinfo=timezone.utc),
        reverse=True,
    )
    if persist:
        save_jsonl(store_path, all_items)
        state["last_run"] = iso(end)
        state["lookback_hours"] = args.hours
        save_state(state_path, state)
    # Refuse to publish a vacant or thin replacement. With --no-store the
    # previous Pages artifact would otherwise be overwritten, dropping the live
    # site. An empty feed is always refused; if any source failed or was only
    # partial, the item count must also reach --min-items.
    def _source_failed(v: Any) -> bool:
        if isinstance(v, dict):
            v = str(v.get("status", "")) + " " + str(v.get("detail", ""))
        v = str(v).lower()
        return ("failed" in v) or v.startswith("error") or v.startswith("partial")

    failed = [k for k, v in source_status.items() if _source_failed(v)]
    if not all_items or (failed and len(all_items) < args.min_items):
        print(
            f"ERROR: refusing to write feed: items={len(all_items)} "
            f"min_items={args.min_items} failed_sources={len(failed)}",
            flush=True,
        )
        for k, v in source_status.items():
            print(f"  {k}: {v}", flush=True)
        return 1

    sanitize_item_links(all_items)
    write_feed_xml(feed_path, all_items, limit=FEED_LIMIT)
    write_index_html(os.path.join(outdir, "index.html"), all_items, limit=FEED_LIMIT)
    write_cname(os.path.join(outdir, "CNAME"))

    # stats for this run's collapsed set (window)
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    exploited = 0
    for it in collapsed:
        s = (it.get("severity") or "unknown").lower()
        if s not in sev_counts:
            s = "unknown"
        sev_counts[s] += 1
        if it.get("exploited_in_wild"):
            exploited += 1

    print(
        f"SUMMARY new={new_count} updated={updated_count} window_items={len(collapsed)} "
        f"store_total={len(all_items)} exploited={exploited} "
        f"sev={sev_counts} feed={feed_path}",
        flush=True,
    )
    # write a small run report for the parent
    report = {
        "cutoff": iso(cutoff),
        "ended": iso(end),
        "source_status": source_status,
        "new_count": new_count,
        "updated_count": updated_count,
        "window_items": len(collapsed),
        "store_total": len(all_items),
        "severity_counts": sev_counts,
        "exploited_in_wild": exploited,
        "window_ids": [it.get("id") for it in collapsed],
    }
    if persist:
        with open(os.path.join(outdir, "last_run_report.json"), "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
            f.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
