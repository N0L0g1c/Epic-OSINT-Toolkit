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
- Plus: Wayback CDX, BGPView ASN, cloud buckets, takeover fingerprints, favicon/Shodan pivots, EXIF, dork packs, **Web3 multi-chain OSINT**

All in one toolkit with **auto target detection**, **entity correlation**, styled reports, and a keyboard-driven split-pane TUI.

---

## Features

### Auto-detect & correlation
- Detect domain, IP, email, phone, username, URL, onion, company, or **wallet**
- Correlate emails, domains, IPs, usernames, URLs, and wallets across modules

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
- **EXIF / metadata** — JPEG EXIF (+ GPS) and light PDF Info from URL or local file  
- **Related domains** — CT SANs, live SSL SANs, same-IP neighbors  
- **Passive DNS** — historical host/IP pivots  
- **Abuse / DNSBL** — reputation list checks  
- **JS secrets** — page/JS key & API-path mining  
- **Email accounts** — Holehe-style registration probes  
- **Username perms** — name/email local-part permutations  
- **Image pivots** — reverse-image search URLs  
- **IOC enrich** — optional VirusTotal / OTX (+ public pivots)  
- **Crypto / Web3** — selectable `evm` bucket + independent chains; ENS; privacy-coin OSINT  
- **Screenshots** — headless Chrome/Chromium when installed  
- **Cases + graph** — investigation folders; JSON/GraphML entity graphs  
- **Plugins** — drop-in `modules/plugins/*.py`  

### Email, phone, ports, company, dark web
- Email discover / MX + SMTP RCPT verify / sources  
- Phone E.164, country hints, pivots  
- Port scan + banners (+ optional nmap)  
- Employees (GitHub/GitLab/website) + HIBP leaks  
- .onion analyze/crawl + **Ahmia** directory search (Tor optional)  
- **Tor health** check against the SOCKS proxy  

### Web3 / cryptocurrency

Select **what to query** so you are not sweeping every chain every time:

| Selection | Meaning |
|-----------|---------|
| `auto` (default) | Detected chain only — e.g. ETH mainnet for `0x…`, no L2 sweep |
| `evm` | **One bucket** — all Ethereum-compatible L1/L2s for the same `0x` address |
| Independent | `bitcoin`, `solana`, `near`, `starknet`, `monero`, … (comma-separated) |
| `all` | Everything applicable to the address type |

**EVM bucket members:** Ethereum, BSC, Polygon, Avalanche, Base, Arbitrum, Optimism, zkSync, Blast, Metis, Taiko, Boba, Immutable, Astar, Polygon zkEVM  

**Independent groups:** Bitcoin, Solana, TRON, XRP, Cardano, Dogecoin, Litecoin, Dash, Monero, Zcash, NEAR, Starknet, Polkadot, Filecoin, Stacks, Arweave, Celestia, Nervos, Oasis  

**Notes:**
- ERC-20 / DeFi tokens (UNI, AAVE, …) show under Ethplorer holdings when using Ethereum/`evm`
- Privacy coins: Monero is pivot-only; Zcash `t-addr` is traceable, shielded is not
- Refuses private-key / WIF shaped input
- List groups: `--crypto-chains` · TUI: Web3 menu toggles Auto / EVM / each independent chain

### Reporting
- JSON / TXT / HTML / **Markdown** on disk  
- TUI shows a colorized, sectioned intel report derived from the same data  
- Soft **rate-limit** + rotating User-Agents for polite probing  

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

Optional: Tor on `127.0.0.1:9050` for dark-web mode. API keys (optional): Shodan, Censys, HIBP, GitHub, VirusTotal, OTX, Etherscan.

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
python osint_toolkit.py -t example.com --related --passive-dns --js-secrets --abuse
python osint_toolkit.py -t user@example.com --email-accounts --perms
python osint_toolkit.py -t 8.8.8.8 --ip --asn --ioc --vt-key YOUR_KEY
python osint_toolkit.py -t https://example.com/photo.jpg --meta --image-pivots
python osint_toolkit.py -t example.com --screenshot --graph --format md

# Web3 / crypto (chain selection)
python osint_toolkit.py --crypto-chains
python osint_toolkit.py -t 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 --crypto --chains auto
python osint_toolkit.py -t 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 --crypto --chains evm
python osint_toolkit.py -t vitalik.eth --crypto --chains evm --etherscan-key YOUR_KEY
python osint_toolkit.py -t root.near --crypto --chains near
python osint_toolkit.py -t bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq --crypto --chains bitcoin --pastes --dorks

# Cases / batch / plugins
python osint_toolkit.py --case-create "Op Alpha"
python osint_toolkit.py -t example.com --auto --case CASE_ID
python osint_toolkit.py --batch targets.txt --format json
python osint_toolkit.py --list-plugins
python osint_toolkit.py -t example.com --plugin example_echo
python osint_toolkit.py --tor-check --tor

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
--type {domain,username,ip,url,company,onion,phone,email,wallet,auto}
--full · --auto

Modules:
  --dns --subdomains --whois --ssl
  --social --github --crawl --directories --emails
  --urls --urlteam --wayback --pastes
  --ip --asn --phone --ports
  --dorks --buckets --takeover --favicon --meta
  --email-accounts --perms --related --js-secrets
  --image-pivots --passive-dns --abuse --ioc --crypto --crypto-chains --screenshot
  --graph --plugin --list-plugins --tor-check
  --employees --leaks
  --comprehensive-crawl --robots --sitemap
  --dark-web --onion-search --tor
  --shodan --censys --correlate
  --case --case-create --case-list --batch

Keys / options:
  --chains {auto,all,evm,bitcoin,solana,…}   # comma-separated crypto groups
  --github-token --shodan-key --censys-id --censys-secret --hibp-api-key
  --vt-key --otx-key --etherscan-key --rate-limit
  --keywords-file --urlteam-date --max-pages --ports-range --depth
  -o/--output -f/--format {json,txt,html,md} --quiet
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
| `crypto_intel.py` | Web3: selectable `evm` + independent chains, ENS, privacy OSINT |
| `ioc_intel.py` | VT / OTX enrichment |
| `abuse_intel.py` | DNSBL reputation |
| `passive_dns.py` | Passive DNS |
| `js_secrets.py` | JS / page secret mining |
| `email_accounts.py` | Holehe-style account checks |
| `related_domains.py` | CT / SSL / same-IP |
| `cases.py` / `graph_export.py` | Cases + GraphML |
| `plugins_loader.py` | Drop-in plugins |
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
