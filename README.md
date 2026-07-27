# Epic OSINT Toolkit 🔍

A comprehensive, CLI-based Open Source Intelligence (OSINT) gathering tool that combines the best features from multiple OSINT tools into one powerful, unified toolkit. Perfect for security researchers, bug bounty hunters, penetration testers, and cybersecurity professionals.

## 🚀 What Makes This Epic?

This toolkit integrates features inspired by popular OSINT tools including:
- **Scilla** - DNS/Subdomain enumeration
- **OSGINT** - GitHub intelligence
- **creepyCrawler** - Comprehensive web crawling with advanced extraction
- **urlhunter** - URLTeam archive search for exposed shortened URLs
- **TorBot** - Dark web intelligence for .onion domains
- **EmploLeaks** - Employee discovery and leaked credential checking
- **Emora/Profil3r** - Social media intelligence

All in one unified CLI interface with comprehensive reporting capabilities.

## Features

### 🌐 Domain Intelligence
- **DNS Enumeration**: Discover A, AAAA, MX, NS, TXT, CNAME, SOA, and PTR records
- **Subdomain Discovery**: Brute-force and Certificate Transparency log checking
- **WHOIS Lookup**: Extract domain registration information
- **SSL Certificate Analysis**: Analyze SSL/TLS certificates for intelligence

### 👤 Social Media Intelligence
- **Multi-Platform Search**: Search for usernames across 25+ social media platforms
- **Profile Discovery**: Find profiles on GitHub, Twitter, Instagram, Facebook, LinkedIn, Reddit, and more
- **Email Discovery**: Generate potential email addresses from usernames
- **Associated Accounts**: Find accounts associated with a username

### 💻 GitHub Intelligence
- **Profile Analysis**: Get detailed GitHub user profile information
- **Repository Analysis**: Analyze user repositories, languages, and contributions
- **Email Discovery**: Find email addresses from GitHub profiles and commits
- **Account Metadata**: Get account creation date and organization memberships

### 🕷️ Web Crawling (creepyCrawler-inspired)
- **Comprehensive Crawling**: Automatic URL discovery via hrefs, robots.txt, and sitemap.xml
- **Advanced Information Extraction**:
  - Emails and phone numbers
  - Social media links
  - Subdomains
  - Cloud storage links (AWS S3, Azure Blob, GCP, Dropbox, Google Drive, etc.)
  - File links (PDF, DOC, ZIP, etc.)
  - Login pages
  - HTML comments
  - IP addresses
  - Marketing tags (Google Analytics, GTM, Facebook Pixel, etc.)
  - Interesting findings (JSON responses, frame ancestors, etc.)
- **Robots.txt Parsing**: Extract URLs from robots.txt
- **Sitemap Parsing**: Extract URLs from sitemap.xml
- **Directory Enumeration**: Discover hidden directories and files
- **Technology Detection**: Identify technologies used (WordPress, Drupal, React, etc.)

### 📧 Email Intelligence
- **Email Discovery**: Discover email addresses using multiple methods
- **Email Verification**: Verify email addresses (format, MX records)
- **Source Tracking**: Track where emails were found (WHOIS, website, GitHub)
- **Disposable Detection**: Identify disposable email addresses

### 🔗 URL Hunting (urlhunter-inspired)
- **URLTeam Archive Search**: Search URLTeam's brute-forced URL shortener collections
- **Keyword-based Search**: Search with single keywords, multiple keywords (AND logic), or regex
- **Date Range Support**: Search archives by date (latest, single date, year, or date range)
- **Shortened URL Discovery**: Find shortened URLs related to a domain
- **Exposed URL Detection**: Find exposed URLs in pastebins, code repos, and file sharing
- **URL Expansion**: Expand shortened URLs to reveal full destinations

### 🔌 Port Scanning
- **Port Discovery**: Scan for open ports on targets
- **Service Detection**: Identify services running on open ports
- **Banner Grabbing**: Extract service banners for intelligence
- **Nmap Integration**: Use nmap for advanced scanning (if available)

### 👥 Employee & Company Intelligence (EmploLeaks-inspired)
- **Employee Discovery**: Find employees from GitHub, GitLab, and company websites
- **Personal Email Discovery**: Generate and find personal email addresses for employees
- **Leaked Credential Checking**: Check for leaked credentials using Have I Been Pwned API
- **Repository Discovery**: Find personal code repositories of employees
- **Company Analysis**: Comprehensive company intelligence gathering
- **Password Leak Detection**: Check if passwords have been leaked

### 🌑 Dark Web Intelligence (TorBot-inspired)
- **Onion Domain Crawling**: Crawl .onion domains and extract intelligence
- **Link Mapping**: Map link relationships between .onion sites
- **Tor Integration**: Optional Tor proxy support for accessing dark web
- **Onion Link Discovery**: Find other .onion domains linked from target
- **Dark Web Analysis**: Analyze .onion domains for accessibility, technologies, and content

### 📊 Reporting
- **Multiple Formats**: Generate reports in JSON, TXT, and HTML formats
- **Comprehensive Reports**: Detailed intelligence reports with all findings
- **Summary Statistics**: Quick summary of discovered information

## 🎯 Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run a full domain scan
python osint_toolkit.py -t example.com --full

# Comprehensive web crawl
python osint_toolkit.py -t example.com --comprehensive-crawl

# Search URLTeam archives
python osint_toolkit.py -t example.com --urlteam --keywords-file keywords.txt

# Analyze dark web
python osint_toolkit.py -t "example.onion" --type onion --dark-web --tor
```

## 📦 Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Setup

1. **Clone or navigate to the toolkit directory:**
```bash
cd epic-osint-toolkit
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Make the script executable (Linux/Mac):**
```bash
chmod +x osint_toolkit.py
```

## 💻 Usage

### Interactive TUI (keyboard GUI)

Launch with no arguments for a full-screen ASCII/ANSI menu you drive with the keyboard:

```bash
python osint_toolkit.py
# or
python osint_toolkit.py --tui
```

**Controls:** Up/Down navigate · Enter select · Space toggle options · Esc/q back

All modules, settings, and saved-report browsing are available from the menu.

### Basic Usage (classic CLI)

**Full domain scan:**
```bash
python osint_toolkit.py -t example.com --full
```

**Social media username search:**
```bash
python osint_toolkit.py -t username --type username --social
```

**GitHub intelligence:**
```bash
python osint_toolkit.py -t githubuser --github
```

**Company employee discovery and leak checking:**
```bash
python osint_toolkit.py -t "Company Name" --type company --employees --leaks
```

**Company analysis with HIBP API key:**
```bash
python osint_toolkit.py -t "Company Name" --type company --full --hibp-api-key YOUR_API_KEY
```

**Comprehensive crawl (creepyCrawler-style):**
```bash
python osint_toolkit.py -t example.com --comprehensive-crawl --robots --sitemap
```

**URLTeam archive search:**
```bash
python osint_toolkit.py -t example.com --urlteam --keywords-file keywords.txt --urlteam-date latest
```

**Dark web .onion analysis:**
```bash
python osint_toolkit.py -t "example.onion" --type onion --dark-web --tor
```

### Advanced Usage

**Custom scan with specific modules:**
```bash
python osint_toolkit.py -t example.com --dns --subdomains --ports --emails
```

**Port scanning with custom range:**
```bash
python osint_toolkit.py -t 192.168.1.1 --ports --ports-range "1-1000"
```

**Website crawling with custom depth:**
```bash
python osint_toolkit.py -t example.com --crawl --depth 3
```

**Generate HTML report:**
```bash
python osint_toolkit.py -t example.com --full --format html
```

**Quiet mode (minimal output):**
```bash
python osint_toolkit.py -t example.com --full --quiet
```

### Command-Line Options

```
Required:
  -t, --target TARGET    Target (domain, username, IP, etc.)

Optional:
  --type {domain,username,ip,url}
                        Type of target (default: domain)
  --full                Run full comprehensive scan
  
Module Flags:
  --dns                 DNS enumeration
  --subdomains          Subdomain discovery
  --whois               WHOIS lookup
  --ssl                 SSL certificate analysis
  --social              Social media search
  --github              GitHub intelligence
  --crawl               Website crawling
  --directories         Directory enumeration
  --emails              Email discovery
  --urls                URL hunting
  --ports               Port scanning
  --employees           Discover company employees
  --leaks               Check for leaked credentials
  --comprehensive-crawl Comprehensive crawl (creepyCrawler-style)
  --robots              Parse robots.txt
  --sitemap             Parse sitemap.xml
  --urlteam             Search URLTeam archives
  --dark-web            Analyze dark web .onion domain
  --tor                 Use Tor proxy (requires Tor running)

Options:
  --keywords-file FILE  Keywords file for URLTeam search
  --urlteam-date DATE   URLTeam archive date (latest, YYYY-MM-DD, YYYY, or range)
  --max-pages N         Maximum pages to crawl (default: 500)
  --hibp-api-key KEY    Have I Been Pwned API key (for leak checking)
  -o, --output DIR      Output directory (default: reports)
  -f, --format {json,txt,html}
                        Output format (default: json)
  --ports-range RANGE   Port range to scan (default: common)
  --depth DEPTH         Crawl depth (default: 2)
  --quiet               Quiet mode (minimal output)
```

## Examples

### Example 1: Full Domain Intelligence
```bash
python osint_toolkit.py -t example.com --full
```
This will:
- Enumerate DNS records
- Discover subdomains
- Get WHOIS information
- Analyze SSL certificate
- Crawl the website
- Discover email addresses
- Hunt for shortened URLs
- Scan common ports

### Example 2: Username Investigation
```bash
python osint_toolkit.py -t johndoe --type username --social --github
```
This will:
- Search for the username across 25+ social platforms
- Get GitHub profile and repository information
- Discover associated email addresses

### Example 3: Port Scanning
```bash
python osint_toolkit.py -t 192.168.1.100 --ports --ports-range "1-1000"
```
This will:
- Scan ports 1-1000
- Detect services
- Grab banners

### Example 4: Email Discovery
```bash
python osint_toolkit.py -t example.com --emails
```
This will:
- Discover email addresses using multiple methods
- Track sources where emails were found

### Example 5: Company Employee Intelligence
```bash
python osint_toolkit.py -t "Example Corp" --type company --employees --leaks
```
This will:
- Discover employees from GitHub, GitLab, and company websites
- Find personal email addresses for employees
- Check for leaked credentials using Have I Been Pwned
- Discover employee repositories

### Example 6: Comprehensive Website Crawl
```bash
python osint_toolkit.py -t example.com --comprehensive-crawl --robots --sitemap
```
This will:
- Crawl website with automatic URL discovery
- Parse robots.txt and sitemap.xml
- Extract cloud storage links, files, login pages, HTML comments, IPs, marketing tags
- Find all interesting findings

### Example 7: URLTeam Archive Search
```bash
python osint_toolkit.py -t example.com --urlteam --keywords-file keywords.txt --urlteam-date 2024-11-30
```
This will:
- Search URLTeam archives for exposed shortened URLs
- Use keywords from file (supports single keywords, multiple keywords, or regex)
- Search specific date or date range

### Example 8: Dark Web Analysis
```bash
python osint_toolkit.py -t "example.onion" --type onion --dark-web --tor
```
This will:
- Analyze .onion domain accessibility
- Crawl .onion domain and extract links
- Map relationships between .onion sites
- Extract emails, IPs, and interesting content

## Output

Reports are saved in the `reports/` directory (or custom directory specified with `-o`).

**File naming format:**
```
osint_YYYYMMDD_HHMMSS_target.format
```

**Example:**
```
osint_20241130_123456_example.com.json
osint_20241130_123456_example.com.html
osint_20241130_123456_example.com.txt
```

## Module Details

### Domain Intelligence Module
- Uses `dnspython` for DNS queries
- Implements subdomain brute-forcing
- Checks Certificate Transparency logs via crt.sh
- Performs WHOIS lookups
- Analyzes SSL certificates

### Social Media Intelligence Module
- Searches 25+ platforms including:
  - GitHub, Twitter, Instagram, Facebook, LinkedIn
  - Reddit, YouTube, TikTok, Pinterest, Snapchat
  - And many more...
- Generates potential email addresses
- Finds associated accounts

### GitHub Intelligence Module
- Uses GitHub API (no token required for public data)
- Analyzes user profiles and repositories
- Discovers email addresses from commits
- Gets account creation dates

### Web Crawler Module (creepyCrawler-inspired)
- Comprehensive crawling with automatic URL discovery
- Parses robots.txt and sitemap.xml
- Extracts comprehensive intelligence:
  - Emails, phone numbers, social links
  - Subdomains
  - Cloud storage links (AWS, Azure, GCP, Dropbox, Google Drive)
  - File links
  - Login pages
  - HTML comments
  - IP addresses
  - Marketing tags (GA, GTM, Facebook Pixel, etc.)
  - Interesting findings (JSON responses, frame ancestors)
- Enumerates directories using wordlist
- Detects technologies (WordPress, React, etc.)

### Email Intelligence Module
- Discovers emails from multiple sources
- Verifies email format and MX records
- Tracks email sources
- Identifies disposable emails

### URL Hunter Module (urlhunter-inspired)
- Searches URLTeam archives for exposed shortened URLs
- Supports keyword-based search (single, multiple with AND logic, regex)
- Date range support (latest, single date, year, date range)
- Finds shortened URLs related to domains
- Searches pastebins and code repositories
- Expands shortened URLs

### Port Scanner Module
- Multi-threaded port scanning
- Service detection
- Banner grabbing
- Optional nmap integration

### Employee Intelligence Module (EmploLeaks-inspired)
- Employee discovery from multiple sources (GitHub, GitLab, websites)
- Personal email address generation and discovery
- Have I Been Pwned integration for leak checking
- Repository discovery for employees
- Company-wide analysis
- Password leak detection

### Dark Web Intelligence Module (TorBot-inspired)
- .onion domain crawling and analysis
- Link relationship mapping between .onion sites
- Tor proxy integration (optional)
- Onion link discovery
- Dark web content extraction

## Legal and Ethical Considerations

⚠️ **IMPORTANT**: This tool is for **authorized security testing and legitimate OSINT research only**.

- Only use this tool on systems you own or have explicit permission to test
- Respect rate limits and terms of service of platforms
- Do not use for harassment, stalking, or illegal activities
- Be aware of local laws regarding information gathering
- Use responsibly and ethically

## Limitations

- Some features require external APIs or services
- Rate limiting may affect results (HIBP API key recommended for leak checking)
- Some platforms may block automated requests
- Results depend on publicly available information
- Port scanning may be slow for large ranges
- LinkedIn employee discovery requires authentication cookies (manual setup)
- Employee discovery works best with companies that have public GitHub/GitLab presence
- URLTeam archive search requires downloaded archives (can be large, 400GB+)
- Dark web features require Tor to be running (127.0.0.1:9050) for .onion access
- Some .onion domains may be slow or inaccessible

## 🤝 Contributing

Contributions are welcome! Feel free to:
- Report bugs
- Suggest new features
- Submit pull requests
- Improve documentation

## 📄 License

This project is provided as-is for educational and authorized security testing purposes.

## Acknowledgments

Inspired by various OSINT tools including:
- Scilla
- OSGINT
- creepyCrawler (comprehensive web crawling)
- urlhunter (URLTeam archive search)
- TorBot (dark web intelligence)
- Emora
- Profil3r
- EmploLeaks (employee and leak detection)
- And many others from the OSINT community

## 💬 Support

For issues, questions, or suggestions, please open an issue on the repository.

## ⭐ Star History

If you find this tool useful, please consider giving it a ⭐ on GitHub!

If you find this tool useful, please consider giving it a ⭐ on GitHub!

---

## ⚠️ Legal and Ethical Disclaimer

**IMPORTANT**: This tool is for **authorized security testing and legitimate OSINT research only**.

- Only use this tool on systems you own or have explicit written permission to test
- Respect rate limits and terms of service of all platforms
- Do not use for harassment, stalking, or any illegal activities
- Be aware of and comply with local laws regarding information gathering
- Use responsibly and ethically
- The authors are not responsible for misuse of this tool

**Remember**: Always use OSINT tools responsibly and ethically. Only gather intelligence on targets you have authorization to investigate.

