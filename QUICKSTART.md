# Quick Start Guide

## Installation (Windows)

1. Open PowerShell in the `epic-osint-toolkit` directory
2. Run the setup script:
```powershell
.\setup.ps1
```
3. Activate the virtual environment:
```powershell
.\venv\Scripts\Activate.ps1
```

## Installation (Linux/Mac)

1. Open terminal in the `epic-osint-toolkit` directory
2. Run the setup script:
```bash
chmod +x setup.sh
./setup.sh
```
3. Activate the virtual environment:
```bash
source venv/bin/activate
```

## Basic Examples

### 1. Full Domain Scan
```bash
python osint_toolkit.py -t example.com --full
```

### 2. Social Media Username Search
```bash
python osint_toolkit.py -t username --type username --social
```

### 3. GitHub Intelligence
```bash
python osint_toolkit.py -t githubuser --github
```

### 4. Port Scanning
```bash
python osint_toolkit.py -t 192.168.1.1 --ports
```

### 5. Email Discovery
```bash
python osint_toolkit.py -t example.com --emails
```

### 6. Custom Scan
```bash
python osint_toolkit.py -t example.com --dns --subdomains --ports --emails
```

## Output

All reports are saved in the `reports/` directory in your chosen format (JSON, TXT, or HTML).

## Need Help?

Run with `--help` to see all available options:
```bash
python osint_toolkit.py --help
```

