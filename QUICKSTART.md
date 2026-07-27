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

**Modules:** Auto Scan · Full Scan · Domain · IP · ASN · Social · GitHub · Crawl · Emails · URLs · Wayback · Pastes · Dorks · Buckets · Takeover · Favicon · EXIF/Meta · Phone · Ports · Shodan/Censys · Employees · Dark Web · Onion Search · Reports · Settings

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
```

### People & company
```bash
python osint_toolkit.py -t johndoe --type username --social --github
python osint_toolkit.py -t "Acme Corp" --type company --employees --leaks
python osint_toolkit.py -t "+15551234567" --phone
```

### Meta / dark web
```bash
python osint_toolkit.py -t https://example.com/img.jpg --meta
python osint_toolkit.py -t "example.onion" --type onion --dark-web --tor --onion-search
```

### Optional API keys
```bash
python osint_toolkit.py -t 1.2.3.4 --shodan --shodan-key YOUR_KEY
python osint_toolkit.py -t example.com --pastes --github-token YOUR_TOKEN
python osint_toolkit.py -t "Acme" --type company --leaks --hibp-api-key YOUR_KEY
```

## Output

Saved under `reports/` as JSON, TXT, or HTML (`-f`). Open or delete them from the TUI **Reports** tab.

## Help

```bash
python osint_toolkit.py --help
```
