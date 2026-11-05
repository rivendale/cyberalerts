# Cyber Alerts (Pennview Labs)

Public vulnerability and threat **RSS feed**, rebuilt on a schedule from public sources only.

- **Feed:** https://cyberalerts.pennviewlabs.com/feed.xml  
- **Site:** https://cyberalerts.pennviewlabs.com/  
- **Redirect:** https://pennviewlabs.com/cyberalerts → the site above

## What this is

A stdlib Python builder (`build_feed.py`) pulls public advisories and security news, dedupes them, tags severity and topics, and writes:

- `feed.xml` — RSS 2.0 (~50 most recent items)
- `index.html` — minimal landing page
- `CNAME` — `cyberalerts.pennviewlabs.com` (harmless alongside Actions-based Pages)

Summaries are **templated in our own words**. The feed never copies article bodies and never republishes a Telegram post wholesale. There is no field for any private stack, host, client, or personal data.

## Sources (public)

| Source | How |
|--------|-----|
| CISA KEV | `known_exploited_vulnerabilities.json` |
| GitHub Advisory Database | reviewed advisories API |
| NVD CVE API 2.0 | recent publications (public rate limits) |
| RSS | BleepingComputer, The Hacker News, SANS ISC, Krebs on Security |
| Telegram web preview | `https://t.me/s/IntCyberDigest` (HTML preview only) |

## Item shape (in RSS)

Each item includes: title, short templated summary, severity (`critical` / `high` / `medium` / `low`), topic categories (`ai-agents`, `crypto-web3`, `supply-chain`, `browsers-playwright`, `node-python`, `mobile`), CVE/GHSA ids when known, source links, stable `guid`, and an `unconfirmed` flag for claims without a CVE/GHSA.

Deduping: CVE id, else GHSA id, else normalized URL. News that mentions an existing CVE/GHSA collapses into that record.

## Schedule

GitHub Actions runs tests, builds the feed, and deploys to **GitHub Pages** about every two hours. Deploy runs only from `main`. Set repository secret `FEED_DENY_TERMS` (comma/newline deny terms for leak checks; never echo) before the first main deploy — empty fails closed. (`cron: 17 */2 * * *`), plus `workflow_dispatch`.

The deny-term check collapses whitespace in each configured term the same way it collapses the built page (runs of spaces, tabs, and non-breaking spaces become one space) and matches that against the raw and HTML-unescaped text. Item titles and descriptions are XML character data: the builder does not emit nested markup inside item text, and RSS and Telegram HTML is tag-stripped before it is stored. The checker does not strip tags a second time.

## Local use

```bash
python3 build_feed.py --hours 72 --outdir site --no-store
python3 -m unittest discover -s tests -v
```

Python 3.10+. No third-party packages.

## After merge: Pages settings (maintainer)

Do **not** change these from automation. A maintainer should set:

1. **Settings → Pages → Build and deployment → Source:** GitHub Actions  
2. **Custom domain:** `cyberalerts.pennviewlabs.com`  
3. **Enforce HTTPS:** on  

DNS (Cloudflare) is owned by Nick; see the PR for the exact CNAME.

## License / use

Public data aggregation for awareness. Upstream licenses and terms still apply to their content; we only publish short original summaries and links.
