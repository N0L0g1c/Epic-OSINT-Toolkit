# Epic OSINT Toolkit

A comprehensive Open Source Intelligence toolkit with a classic CLI **and** a full-terminal ASCII/ANSI TUI. Built for security researchers, bug bounty hunters, and penetration testers.

## What Makes This Epic?

Inspired by and combining ideas from:
- **Scilla** — DNS / subdomain enumeration  
- **OSGINT** — GitHub intelligence  
- **creepyCrawler** — deep web crawl + extraction  
- **urlhunter** — shortened / exposed URL hunting  
- **TorBot** — dark-web .onion analysis  
- **EmploLeaks** — employees + breach checks  
- **Emora / Profil3r / Sherlock-class** — username matrix  
- Plus: Wayback CDX, BGPView ASN, cloud buckets, takeover fingerprints, favicon/Shodan pivots, EXIF, dork packs

All in one toolkit with **auto target detection**, **entity correlation**, styled reports, and a keyboard-driven split-pane TUI.

---

## Features

### Auto-detect & correlation
- Detect domain, IP, email, phone, username, URL, onion, or company
- Correlate emails, domains, IPs, usernames, and URLs across modules

### Interactive TUI
- Full-terminal layout: **module menu on the left**, feature pane on the right (wide terminals)
- Large **EPIC OSINT TOOLKIT** logo when idle
- Heavy ASCII/ANSI panels, styled intel reports (not raw JSON dumps)
- View / **delete** saved reports from the Reports tab

### Domain intelligence
- DNS: A, AAAA, MX, NS, TXT, CNAME, SOA, PTR  
- Email auth: SPF, DMARC, DKIM selectors  
- DNSSEC: DNSKEY / DS / RRSIG  
- Subdomains: brute-force, crt.sh, HackerTarget  
- WHOIS + SSL certificate analysis  

### IP / ASN / host
- Geo, ISP/org, reverse DNS, proxy/hosting risk (ip-api + BGPView)  
- ASN netblocks, peers, upstreams  
- Optional **Shodan** / **Censys** (API keys)  

### Social & GitHub
- **100+** platform username matrix with soft-404 detection  
- Associated accounts + GitHub profile / orgs / emails / repos  

### Web crawl & URL surface
- creepyCrawler-style crawl, robots/sitemap, dirs, tech detect  
- Emails, phones, social, cloud links, files, comments, tags  
- URL hunter + **Wayback Machine CDX** fallback  
- Paste / GitHub code leak hunt  

### Recon extras
- **Dork generator** — Google / DuckDuckGo / Bing packs by target type  
- **Cloud buckets** — S3, GCS, Azure Blob, DigitalOcean Spaces probes  
- **Takeover checks** — dangling DNS + service fingerprints  
- **Favicon mmh3** — Shodan `http.favicon.hash` pivot  
- **EXIF / metadata** — JPEG EXIF (+ GPS maps link) from URL or local file  

### Email, phone, ports, company, dark web
- Email discover / MX + SMTP RCPT verify / sources  
- Phone E.164, country hints, pivots  
- Port scan + banners (+ optional nmap)  
- Employees (GitHub/GitLab/website) + HIBP leaks  
- .onion analyze/crawl + **Ahmia** directory search (Tor optional)  

### Reporting
- JSON / TXT / HTML on disk  
- TUI shows a colorized, sectioned intel report derived from the same data  

---

## Quick start

```bash
# Linux/Mac
./setup.sh && source venv/bin/activate

# Interactive TUI (recommended)
python osint_toolkit.py

# Auto-detect + full scan
python osint_toolkit.py -t example.com --auto
```

---

## Installation

**Prerequisites:** Python 3.8+, pip

```bash
cd Epic-OSINT-Toolkit
pip install -r requirements.txt
# or
./setup.sh && source venv/bin/activate   # Linux/Mac
# Windows: .\setup.ps1 then .\venv\Scripts\Activate.ps1
```

Optional: Tor running on `127.0.0.1:9050` for dark-web mode; API keys for Shodan, Censys, HIBP, GitHub (higher rate limits).

---

## Usage

### Interactive TUI

```bash
python osint_toolkit.py
python osint_toolkit.py --tui
```

| Key | Action |
|-----|--------|
| ↑ / ↓ (or j/k) | Navigate menu |
| Enter / Space | Open module |
| Space (options) | Toggle flags |
| Esc / q | Back / quit (home) |
| d / D (Reports) | Delete one / delete all |

Wide terminal (≥100×22): left **MODULES** list, right content pane (logo when idle). Narrow terminals use a stacked full-screen layout.

### Classic CLI examples

```bash
# Full / auto
python osint_toolkit.py -t example.com --full
python osint_toolkit.py -t example.com --auto

# Domain stack
python osint_toolkit.py -t example.com --dns --subdomains --emails --ports

# New recon modules
python osint_toolkit.py -t example.com --dorks --buckets --takeover --favicon
python osint_toolkit.py -t 8.8.8.8 --ip --asn
python osint_toolkit.py -t https://example.com/photo.jpg --meta
python osint_toolkit.py -t example.com --wayback --pastes

# People / company
python osint_toolkit.py -t johndoe --type username --social --github
python osint_toolkit.py -t "Acme Corp" --type company --employees --leaks

# Dark web
python osint_toolkit.py -t "example.onion" --type onion --dark-web --tor --onion-search

# Reports
python osint_toolkit.py -t example.com --full --format html -o reports
```

### Command-line options (summary)

```
-t / --target TARGET
--tui
--type {domain,username,ip,url,company,onion,phone,email,auto}
--full · --auto

Modules:
  --dns --subdomains --whois --ssl
  --social --github --crawl --directories --emails
  --urls --urlteam --wayback --pastes
  --ip --asn --phone --ports
  --dorks --buckets --takeover --favicon --meta
  --employees --leaks
  --comprehensive-crawl --robots --sitemap
  --dark-web --onion-search --tor
  --shodan --censys --correlate

Keys / options:
  --github-token --shodan-key --censys-id --censys-secret --hibp-api-key
  --keywords-file --urlteam-date --max-pages --ports-range --depth
  -o/--output -f/--format {json,txt,html} --quiet
```

Run `python osint_toolkit.py --help` for the full list.

---

## Module map

| Module file | Capability |
|-------------|------------|
| `domain_intel.py` | DNS, CT subs, WHOIS, SSL, SPF/DMARC/DKIM, DNSSEC |
| `ip_intel.py` | Geo / risk / rDNS |
| `asn_intel.py` | ASN prefixes / peers / upstreams |
| `social_intel.py` | 100+ username matrix |
| `github_intel.py` | Profile, repos, emails |
| `web_crawler.py` | Crawl / extract / tech |
| `email_intel.py` | Discover / verify / sources |
| `url_hunter.py` | Shorteners + Wayback fallback |
| `wayback_intel.py` | Archive.org CDX |
| `paste_intel.py` | GitHub code + paste dorks |
| `dork_intel.py` | Search-engine dork packs |
| `bucket_intel.py` | Cloud bucket probes |
| `takeover_intel.py` | Takeover fingerprints |
| `favicon_intel.py` | Favicon mmh3 / Shodan pivot |
| `meta_intel.py` | EXIF / metadata |
| `phone_intel.py` | Phone OSINT |
| `port_scanner.py` | Ports / banners |
| `host_intel.py` | Shodan / Censys |
| `employee_intel.py` | Company / HIBP |
| `dark_web_intel.py` | Onion + Ahmia |
| `correlate.py` | Auto-detect + graph |
| `tui.py` / `tui_style.py` | Split-pane ASCII UI + styled reports |
| `report_generator.py` | TXT / HTML / summary |

---

## Output

Reports are written under `reports/` (or `-o`) as JSON, TXT, or HTML. The TUI formats the same JSON into a readable intel report and can delete old `osint_*` files from the Reports tab.

---

## Legal / ethics

Use only on targets you are authorized to investigate. Respect laws, ToS, and rate limits. Optional APIs (Shodan, Censys, HIBP, GitHub) require your own keys.

---

## License

MIT License © 2026 [N0L0g1c](https://github.com/N0L0g1c) — see [LICENSE](LICENSE).

You may use, copy, modify, and distribute this software freely, including commercially, as long as you keep the copyright notice and license text. No warranty is provided; use responsibly and only on targets you are authorized to investigate.
