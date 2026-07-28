# Quick Start Guide

## Installation (Windows)

1. Open PowerShell in the project directory  
2. Run:
```powershell
.\setup.ps1
.\venv\Scripts\Activate.ps1
```

## Installation (Linux/Mac)

```bash
chmod +x setup.sh
./setup.sh
source venv/bin/activate
```

## Interactive TUI (recommended)

```bash
python osint_toolkit.py
# or
python osint_toolkit.py --tui
```

**Layout (wide terminal):** modules on the **left**, feature pane on the **right** (big logo when idle).

| Key | Action |
|-----|--------|
| ↑↓ / j k | Navigate |
| Enter | Open module |
| Space | Toggle options |
| Esc / q | Back / quit |
| d / D | Delete report / delete all (Reports) |

**Modules:** Auto · Full · Domain · IP · ASN · Related Domains · Typosquats · SaaS Tenants · Company Biz · Person · Packages · Passive DNS · Abuse · IOC · Crypto/Web3 · Social · Perms · GitHub · Crawl · JS Secrets · Screenshot · Emails · Email Accounts · URLs · Wayback · Pastes · Dorks · Buckets · Takeover · Favicon · EXIF/Meta · Image Pivots · Phone · Ports · Shodan/Censys · Employees · Dark Web · Onion Search · Tor Health · Graph · Cases · Plugins · Reports · Settings

## CLI examples

### Auto / full
```bash
python osint_toolkit.py -t example.com --auto
python osint_toolkit.py -t example.com --full
python osint_toolkit.py -t 8.8.8.8 --type ip --full
```

### Domain & infra
```bash
python osint_toolkit.py -t example.com --dns --subdomains --emails --ports
python osint_toolkit.py -t example.com --wayback --pastes --ip --asn
python osint_toolkit.py -t example.com --dorks --buckets --takeover --favicon
python osint_toolkit.py -t example.com --related --passive-dns --js-secrets --abuse
```

### People & company
```bash
python osint_toolkit.py -t johndoe --type username --social --github --perms
python osint_toolkit.py -t user@example.com --email-accounts
python osint_toolkit.py -t "Acme Corp" --type company --employees --leaks --company-biz
python osint_toolkit.py -t "Jane Doe" --type person --person --perms
python osint_toolkit.py -t "+15551234567" --phone
```

### Domain extras
```bash
python osint_toolkit.py -t example.com --saas --typosquat --packages
```

### Web3 / crypto

List selectable groups (`evm` = all Ethereum L1/L2 as **one** choice):

```bash
python osint_toolkit.py --crypto-chains
```

| Flag | Effect |
|------|--------|
| `--chains auto` | Detected chain only (default; fast) |
| `--chains evm` | Sweep ETH + Arb/OP/zkSync/Blast/… for a `0x` address |
| `--chains bitcoin,near` | Independent groups only |
| `--chains all` | Everything applicable |

```bash
python osint_toolkit.py -t 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 --crypto --chains auto
python osint_toolkit.py -t 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 --crypto --chains evm
python osint_toolkit.py -t vitalik.eth --crypto --chains evm --etherscan-key YOUR_KEY
python osint_toolkit.py -t root.near --crypto --chains near
python osint_toolkit.py -t bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq --crypto --chains bitcoin --dorks --pastes
```

In the TUI, open **Web3 / Crypto**, toggle **Auto** / **EVM** / independent chains, then enter the address.

### Meta / dark web / extras
```bash
python osint_toolkit.py -t https://example.com/img.jpg --meta --image-pivots
python osint_toolkit.py -t "example.onion" --type onion --dark-web --tor --onion-search
python osint_toolkit.py --tor-check --tor
python osint_toolkit.py -t example.com --screenshot --graph --format md
```

### Cases, batch, plugins
```bash
python osint_toolkit.py --case-create "Op Alpha"
python osint_toolkit.py -t example.com --auto --case CASE_ID
python osint_toolkit.py --batch targets.txt
python osint_toolkit.py --list-plugins
python osint_toolkit.py -t example.com --plugin example_echo
```

### Optional API keys
```bash
python osint_toolkit.py -t 1.2.3.4 --shodan --shodan-key YOUR_KEY
python osint_toolkit.py -t example.com --pastes --github-token YOUR_TOKEN
python osint_toolkit.py -t "Acme" --type company --leaks --hibp-api-key YOUR_KEY
python osint_toolkit.py -t 8.8.8.8 --ioc --vt-key YOUR_KEY --otx-key YOUR_KEY
python osint_toolkit.py -t vitalik.eth --crypto --etherscan-key YOUR_KEY
```

## Output

Saved under `reports/` as JSON, TXT, HTML, or Markdown (`-f`). Cases live under `cases/`. Open or delete reports from the TUI **Reports** tab.

## Help

```bash
python osint_toolkit.py --help
```
