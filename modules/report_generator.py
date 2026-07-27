"""Report Generator Module - Generate reports in various formats"""

from typing import Dict, Any
from datetime import datetime
import html as html_lib


def _esc(value: Any) -> str:
    return html_lib.escape(str(value if value is not None else ""), quote=True)


class ReportGenerator:
    """Generate OSINT reports"""
    
    def generate_text_report(self, results: Dict) -> str:
        """Generate text report"""
        report = []
        report.append("=" * 80)
        report.append("EPIC OSINT TOOLKIT - INTELLIGENCE REPORT")
        report.append("=" * 80)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Target: {results.get('target', 'Unknown')}")
        report.append(f"Scan Type: {results.get('scan_type', 'Unknown')}")
        report.append("=" * 80)
        report.append("")
        
        # Domain Intelligence
        if 'domain' in results.get('results', {}):
            domain_data = results['results']['domain']
            report.append("DOMAIN INTELLIGENCE")
            report.append("-" * 80)
            if 'dns_records' in domain_data:
                report.append("DNS Records:")
                for record_type, values in domain_data['dns_records'].items():
                    if values:
                        if isinstance(values, (list, tuple)):
                            formatted = ', '.join(str(v) for v in values)
                        else:
                            formatted = str(values)
                        report.append(f"  {record_type}: {formatted}")
            if 'subdomains' in domain_data and domain_data['subdomains']:
                report.append(f"\nSubdomains Found: {len(domain_data['subdomains'])}")
                for subdomain in domain_data['subdomains'][:20]:  # Limit to 20
                    report.append(f"  - {subdomain}")
            report.append("")
        
        # Social Media
        if 'social' in results.get('results', {}):
            social_data = results['results']['social']
            report.append("SOCIAL MEDIA INTELLIGENCE")
            report.append("-" * 80)
            if 'profiles' in social_data:
                found_profiles = [p for p, info in social_data['profiles'].items() if info.get('exists')]
                if found_profiles:
                    report.append(f"Found Profiles: {len(found_profiles)}")
                    for platform in found_profiles:
                        info = social_data['profiles'][platform]
                        report.append(f"  - {platform}: {info.get('url', 'N/A')}")
            report.append("")
        
        # GitHub
        if 'github' in results.get('results', {}):
            github_data = results['results']['github']
            report.append("GITHUB INTELLIGENCE")
            report.append("-" * 80)
            if 'profile' in github_data:
                profile = github_data['profile']
                report.append(f"Username: {profile.get('login', 'N/A')}")
                report.append(f"Name: {profile.get('name', 'N/A')}")
                report.append(f"Company: {profile.get('company', 'N/A')}")
                report.append(f"Location: {profile.get('location', 'N/A')}")
                report.append(f"Email: {profile.get('email', 'N/A')}")
                report.append(f"Public Repos: {profile.get('public_repos', 0)}")
                report.append(f"Followers: {profile.get('followers', 0)}")
            report.append("")
        
        # Ports
        if 'ports' in results.get('results', {}):
            ports_data = results['results']['ports']
            report.append("PORT SCAN RESULTS")
            report.append("-" * 80)
            if 'open_ports' in ports_data:
                report.append(f"Open Ports: {len(ports_data['open_ports'])}")
                for port in ports_data['open_ports']:
                    service = ports_data.get('services', {}).get(port, 'Unknown')
                    report.append(f"  - Port {port}: {service}")
            report.append("")
        
        # Emails
        if 'emails' in results.get('results', {}):
            emails_data = results['results']['emails']
            report.append("EMAIL DISCOVERY")
            report.append("-" * 80)
            if 'emails' in emails_data:
                report.append(f"Emails Found: {len(emails_data['emails'])}")
                for email in emails_data['emails'][:20]:  # Limit to 20
                    report.append(f"  - {email}")
            report.append("")
        
        # Company/Employee Intelligence
        if 'company' in results.get('results', {}):
            company_data = results['results']['company']
            report.append("COMPANY INTELLIGENCE")
            report.append("-" * 80)
            if 'employees' in company_data:
                report.append(f"Employees Discovered: {len(company_data['employees'])}")
                for emp in company_data['employees'][:30]:  # Limit to 30
                    report.append(f"\n  Name: {emp.get('name', 'N/A')}")
                    report.append(f"  Title: {emp.get('title', 'N/A')}")
                    if emp.get('email'):
                        report.append(f"  Email: {emp.get('email')}")
                    if emp.get('location'):
                        report.append(f"  Location: {emp.get('location')}")
                    if emp.get('social_profiles'):
                        report.append(f"  Profiles: {', '.join(emp['social_profiles'].keys())}")
            
            if 'leaked_credentials' in company_data and company_data['leaked_credentials']:
                report.append(f"\nLEAKED CREDENTIALS FOUND: {len(company_data['leaked_credentials'])}")
                report.append("-" * 80)
                for leak in company_data['leaked_credentials']:
                    report.append(f"\n  Employee: {leak.get('employee', 'N/A')}")
                    report.append(f"  Email: {leak.get('email', 'N/A')}")
                    report.append(f"  Type: {leak.get('type', 'N/A')}")
                    if leak.get('breaches'):
                        report.append(f"  Breaches: {len(leak['breaches'])}")
                        for breach in leak['breaches'][:5]:  # Limit to 5
                            if isinstance(breach, dict):
                                report.append(f"    - {breach.get('Name', 'Unknown')} ({breach.get('BreachDate', 'N/A')})")
                            else:
                                report.append(f"    - {breach}")
            
            if 'repositories' in company_data and company_data['repositories']:
                report.append(f"\nEMPLOYEE REPOSITORIES: {len(company_data['repositories'])}")
                for repo in company_data['repositories'][:20]:  # Limit to 20
                    report.append(f"  - {repo.get('name', 'N/A')} ({repo.get('platform', 'N/A')}): {repo.get('url', 'N/A')}")
            report.append("")

        # Extra modules
        for key, title in (
            ("website", "WEB CRAWL"),
            ("urls", "URL HUNT"),
            ("wayback", "WAYBACK HISTORY"),
            ("ip", "IP INTELLIGENCE"),
            ("phone", "PHONE OSINT"),
            ("pastes", "PASTE / LEAK HUNT"),
            ("dark_web", "DARK WEB"),
            ("onion_dirs", "ONION DIRECTORY SEARCH"),
            ("host_intel", "SHODAN / CENSYS"),
        ):
            if key in results.get("results", {}):
                data = results["results"][key]
                report.append(title)
                report.append("-" * 80)
                if isinstance(data, dict):
                    for k, v in list(data.items())[:40]:
                        if isinstance(v, (list, dict)):
                            report.append(f"  {k}: {len(v) if isinstance(v, (list, dict)) else v}")
                        else:
                            report.append(f"  {k}: {v}")
                report.append("")

        if results.get("correlation"):
            corr = results["correlation"]
            report.append("CORRELATION")
            report.append("-" * 80)
            report.append(f"  Detected type: {corr.get('detected_type')}")
            for k, n in (corr.get("counts") or {}).items():
                report.append(f"  {k}: {n}")
            report.append("")
        
        report.append("=" * 80)
        report.append("END OF REPORT")
        report.append("=" * 80)
        
        return "\n".join(report)
    
    def generate_html_report(self, results: Dict) -> str:
        """Generate HTML report"""
        html = []
        html.append("<!DOCTYPE html>")
        html.append("<html>")
        html.append("<head>")
        html.append("<title>OSINT Intelligence Report</title>")
        html.append("<style>")
        html.append("""
            body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
            .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
            .section { background: white; margin: 20px 0; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .section h2 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
            .item { margin: 10px 0; padding: 10px; background: #f8f9fa; border-left: 3px solid #3498db; }
            .port { display: inline-block; margin: 5px; padding: 5px 10px; background: #3498db; color: white; border-radius: 3px; }
            .email { color: #27ae60; }
            .url { color: #3498db; text-decoration: none; }
            .url:hover { text-decoration: underline; }
            table { width: 100%; border-collapse: collapse; margin: 10px 0; }
            th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
            th { background: #34495e; color: white; }
        """)
        html.append("</style>")
        html.append("</head>")
        html.append("<body>")
        
        html.append("<div class='header'>")
        html.append("<h1>EPIC OSINT TOOLKIT - INTELLIGENCE REPORT</h1>")
        html.append(f"<p>Generated: {_esc(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}</p>")
        html.append(f"<p>Target: {_esc(results.get('target', 'Unknown'))}</p>")
        html.append(f"<p>Scan Type: {_esc(results.get('scan_type', 'Unknown'))}</p>")
        html.append("</div>")
        
        # Domain Intelligence
        if 'domain' in results.get('results', {}):
            domain_data = results['results']['domain']
            html.append("<div class='section'>")
            html.append("<h2>Domain Intelligence</h2>")
            
            if 'dns_records' in domain_data:
                html.append("<h3>DNS Records</h3>")
                html.append("<table>")
                html.append("<tr><th>Type</th><th>Value</th></tr>")
                for record_type, values in domain_data['dns_records'].items():
                    if values:
                        if isinstance(values, (list, tuple)):
                            formatted = ', '.join(str(v) for v in values)
                        else:
                            formatted = str(values)
                        html.append(f"<tr><td>{record_type}</td><td>{formatted}</td></tr>")
                html.append("</table>")
            
            if 'subdomains' in domain_data and domain_data['subdomains']:
                html.append(f"<h3>Subdomains ({len(domain_data['subdomains'])})</h3>")
                html.append("<div>")
                for subdomain in domain_data['subdomains'][:50]:
                    html.append(f"<div class='item'>{subdomain}</div>")
                html.append("</div>")
            
            html.append("</div>")
        
        # Social Media
        if 'social' in results.get('results', {}):
            social_data = results['results']['social']
            html.append("<div class='section'>")
            html.append("<h2>Social Media Intelligence</h2>")
            if 'profiles' in social_data:
                found_profiles = [p for p, info in social_data['profiles'].items() if info.get('exists')]
                if found_profiles:
                    html.append(f"<p>Found {len(found_profiles)} profiles:</p>")
                    html.append("<table>")
                    html.append("<tr><th>Platform</th><th>URL</th></tr>")
                    for platform in found_profiles:
                        info = social_data['profiles'][platform]
                        url = info.get('url', '#')
                        html.append(f"<tr><td>{platform}</td><td><a href='{url}' class='url' target='_blank'>{url}</a></td></tr>")
                    html.append("</table>")
            html.append("</div>")
        
        # Ports
        if 'ports' in results.get('results', {}):
            ports_data = results['results']['ports']
            html.append("<div class='section'>")
            html.append("<h2>Port Scan Results</h2>")
            if 'open_ports' in ports_data:
                html.append(f"<p>Open Ports: {len(ports_data['open_ports'])}</p>")
                for port in ports_data['open_ports']:
                    service = ports_data.get('services', {}).get(port, 'Unknown')
                    html.append(f"<span class='port'>Port {port}: {service}</span>")
            html.append("</div>")
        
        # Emails
        if 'emails' in results.get('results', {}):
            emails_data = results['results']['emails']
            html.append("<div class='section'>")
            html.append("<h2>Email Discovery</h2>")
            if 'emails' in emails_data:
                html.append(f"<p>Emails Found: {len(emails_data['emails'])}</p>")
                for email in emails_data['emails'][:30]:
                    html.append(f"<div class='item email'>{email}</div>")
            html.append("</div>")
        
        # Company/Employee Intelligence
        if 'company' in results.get('results', {}):
            company_data = results['results']['company']
            html.append("<div class='section'>")
            html.append("<h2>Company Intelligence</h2>")
            
            if 'employees' in company_data:
                html.append(f"<h3>Employees Discovered: {len(company_data['employees'])}</h3>")
                html.append("<table>")
                html.append("<tr><th>Name</th><th>Title</th><th>Email</th><th>Location</th><th>Profiles</th></tr>")
                for emp in company_data['employees'][:50]:
                    html.append("<tr>")
                    html.append(f"<td>{emp.get('name', 'N/A')}</td>")
                    html.append(f"<td>{emp.get('title', 'N/A')}</td>")
                    html.append(f"<td>{emp.get('email', 'N/A')}</td>")
                    html.append(f"<td>{emp.get('location', 'N/A')}</td>")
                    profiles = ', '.join(emp.get('social_profiles', {}).keys()) if emp.get('social_profiles') else 'N/A'
                    html.append(f"<td>{profiles}</td>")
                    html.append("</tr>")
                html.append("</table>")
            
            if 'leaked_credentials' in company_data and company_data['leaked_credentials']:
                html.append(f"<h3 style='color: #e74c3c;'>⚠️ Leaked Credentials Found: {len(company_data['leaked_credentials'])}</h3>")
                html.append("<table>")
                html.append("<tr><th>Employee</th><th>Email</th><th>Type</th><th>Breaches</th></tr>")
                for leak in company_data['leaked_credentials']:
                    html.append("<tr style='background: #fee;'>")
                    html.append(f"<td>{leak.get('employee', 'N/A')}</td>")
                    html.append(f"<td>{leak.get('email', 'N/A')}</td>")
                    html.append(f"<td>{leak.get('type', 'N/A')}</td>")
                    breaches = leak.get('breaches', [])
                    breach_count = len(breaches) if breaches else 0
                    breach_names = ', '.join([b.get('Name', 'Unknown') if isinstance(b, dict) else str(b) for b in breaches[:3]])
                    html.append(f"<td>{breach_count} - {breach_names}</td>")
                    html.append("</tr>")
                html.append("</table>")
            
            if 'repositories' in company_data and company_data['repositories']:
                html.append(f"<h3>Employee Repositories: {len(company_data['repositories'])}</h3>")
                html.append("<table>")
                html.append("<tr><th>Name</th><th>Platform</th><th>URL</th></tr>")
                for repo in company_data['repositories'][:50]:
                    html.append("<tr>")
                    html.append(f"<td>{repo.get('name', 'N/A')}</td>")
                    html.append(f"<td>{repo.get('platform', 'N/A')}</td>")
                    url = repo.get('url', '#')
                    html.append(f"<td><a href='{url}' class='url' target='_blank'>{url}</a></td>")
                    html.append("</tr>")
                html.append("</table>")
            
            html.append("</div>")

        for key, title in (
            ("website", "Web Crawl"),
            ("urls", "URL Hunt"),
            ("wayback", "Wayback History"),
            ("ip", "IP Intelligence"),
            ("phone", "Phone OSINT"),
            ("pastes", "Paste / Leak Hunt"),
            ("dark_web", "Dark Web"),
            ("host_intel", "Shodan / Censys"),
        ):
            if key in results.get("results", {}):
                data = results["results"][key]
                html.append("<div class='section'>")
                html.append(f"<h2>{title}</h2>")
                if isinstance(data, dict):
                    html.append("<table>")
                    for k, v in list(data.items())[:30]:
                        if isinstance(v, (list, dict)):
                            val = f"{len(v)} items"
                        else:
                            val = str(v)[:300]
                        html.append(f"<tr><td>{_esc(k)}</td><td>{_esc(val)}</td></tr>")
                    html.append("</table>")
                html.append("</div>")

        if results.get("correlation"):
            corr = results["correlation"]
            html.append("<div class='section'>")
            html.append("<h2>Correlation</h2>")
            html.append(f"<p>Detected type: {_esc(corr.get('detected_type'))}</p>")
            html.append("<ul>")
            for k, n in (corr.get("counts") or {}).items():
                html.append(f"<li>{_esc(k)}: {_esc(n)}</li>")
            html.append("</ul></div>")
        
        html.append("</body>")
        html.append("</html>")
        
        return "\n".join(html)

    def generate_markdown_report(self, results: Dict) -> str:
        """Generate Markdown report from structured results."""
        lines = [
            "# Epic OSINT Toolkit — Intelligence Report",
            "",
            f"- **Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"- **Target:** `{results.get('target', 'Unknown')}`",
            f"- **Scan type:** `{results.get('scan_type', 'Unknown')}`",
            f"- **Timestamp:** `{results.get('timestamp', '')}`",
            "",
        ]
        res = results.get("results") or {}
        for key, data in res.items():
            title = key.replace("_", " ").title()
            lines.append(f"## {title}")
            lines.append("")
            if isinstance(data, dict):
                for k, v in list(data.items())[:40]:
                    if isinstance(v, (list, tuple)):
                        lines.append(f"### {k}")
                        for item in list(v)[:25]:
                            lines.append(f"- `{item}`" if not isinstance(item, dict) else f"- {item}")
                        lines.append("")
                    elif isinstance(v, dict):
                        lines.append(f"### {k}")
                        for sk, sv in list(v.items())[:20]:
                            lines.append(f"- **{sk}:** `{sv}`")
                        lines.append("")
                    else:
                        lines.append(f"- **{k}:** `{v}`")
            else:
                lines.append(f"```\n{data}\n```")
            lines.append("")
        if results.get("correlation"):
            corr = results["correlation"]
            lines.append("## Correlation")
            lines.append("")
            for k, v in (corr.get("counts") or {}).items():
                lines.append(f"- **{k}:** {v}")
            lines.append("")
        return "\n".join(lines)
    
    def print_summary(self, results: Dict):
        """Print summary to console"""
        print("\n" + "=" * 60)
        print("SCAN SUMMARY")
        print("=" * 60)
        print(f"Target: {results.get('target', 'Unknown')}")
        print(f"Type: {results.get('scan_type', 'Unknown')}")
        
        res = results.get('results', {})
        
        if 'domain' in res:
            domain = res['domain']
            if 'subdomains' in domain:
                print(f"Subdomains Found: {len(domain.get('subdomains', []))}")
            if 'dns_records' in domain:
                print(f"DNS Records: {len(domain.get('dns_records', {}))}")
        
        if 'ports' in res:
            ports = res['ports']
            print(f"Open Ports: {len(ports.get('open_ports', []))}")
        
        if 'emails' in res:
            emails = res['emails']
            print(f"Emails Found: {len(emails.get('emails', []))}")
        
        if 'social' in res:
            social = res['social']
            if 'profiles' in social:
                found = sum(1 for p, info in social['profiles'].items() if info.get('exists'))
                print(f"Social Profiles Found: {found}")

        if 'github' in res:
            github = res['github']
            profile = github.get('profile') or {}
            if profile.get('login'):
                print(f"GitHub User: {profile.get('login')}")
                print(f"GitHub Repos: {profile.get('public_repos', 0)}")
            repos = github.get('repositories') or []
            if repos and not profile.get('public_repos'):
                print(f"GitHub Repos Analyzed: {len(repos)}")
        
        if 'company' in res:
            company = res['company']
            print(f"Employees Discovered: {len(company.get('employees', []))}")
            print(f"Leaked Credentials: {len(company.get('leaked_credentials', []))}")
            print(f"Repositories Found: {len(company.get('repositories', []))}")

        if 'wayback' in res:
            print(f"Wayback URLs: {res['wayback'].get('total', len(res['wayback'].get('urls') or []))}")
        if 'ip' in res:
            ip = res['ip']
            print(f"IP: {ip.get('ip')}  ASN: {(ip.get('asn') or {}).get('asn')}  Risk: {(ip.get('risk') or {}).get('score')}")
        if 'phone' in res:
            print(f"Phone: {res['phone'].get('e164')}  Country: {res['phone'].get('country_hint')}")
        if 'pastes' in res:
            gh = (res['pastes'].get('github_code') or {})
            print(f"Paste/code hits: {gh.get('total', 0)}")
        if results.get('correlation'):
            c = results['correlation'].get('counts') or {}
            print(f"Correlated entities: {sum(c.values())}")
        
        print("=" * 60)

