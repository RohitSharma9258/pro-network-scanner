import json
import csv
import xml.etree.ElementTree as ET
from datetime import datetime
from jinja2 import Template

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Vanguard Titan v12.5 - Enterprise Scan Report</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #e2e8f0; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        h1 { color: #38bdf8; border-bottom: 2px solid #38bdf8; padding-bottom: 10px; margin-bottom: 5px; }
        .subtitle { color: #94a3b8; margin-bottom: 20px; }
        .summary { display: flex; gap: 20px; margin-bottom: 30px; flex-wrap: wrap; }
        .card { background: #1e293b; padding: 20px; border-radius: 8px; flex: 1; text-align: center; min-width: 150px; border: 1px solid #334155; }
        .card h2 { margin: 0; font-size: 2em; color: #38bdf8; }
        .card p { color: #94a3b8; }
        .host-block { background: #1e293b; border-radius: 8px; margin-bottom: 20px; border: 1px solid #334155; overflow: hidden; }
        .host-header { background: #334155; padding: 15px 20px; display: flex; justify-content: space-between; align-items: center; }
        .host-header h3 { color: #38bdf8; }
        .host-header .os-badge { background: #0ea5e9; color: #fff; padding: 4px 12px; border-radius: 12px; font-size: 0.85em; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px 15px; text-align: left; border-bottom: 1px solid #1e293b; font-size: 0.9em; }
        th { background: #1e293b; color: #38bdf8; font-weight: 600; }
        .severity-low { color: #4ade80; font-weight: 600; }
        .severity-medium { color: #fbbf24; font-weight: 600; }
        .severity-high { color: #f87171; font-weight: 600; }
        .ssl-badge { background: #059669; color: #fff; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; }
        .cve-tag { background: #dc2626; color: #fff; padding: 2px 6px; border-radius: 3px; font-size: 0.75em; margin: 2px; display: inline-block; }
        .banner-text { color: #64748b; font-size: 0.8em; max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .no-ports { padding: 20px; color: #64748b; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <h1>⚡ Vanguard Titan Scan Report</h1>
        <p class="subtitle">Generated: {{ timestamp }} | v12.5 Enterprise Edition</p>
        
        <div class="summary">
            <div class="card"><h2>{{ total_hosts }}</h2><p>Hosts Scanned</p></div>
            <div class="card"><h2>{{ total_ports }}</h2><p>Open Ports</p></div>
            <div class="card"><h2>{{ total_cves }}</h2><p>CVEs Found</p></div>
            <div class="card"><h2>{{ total_ssl }}</h2><p>SSL Certs</p></div>
            <div class="card"><h2>{{ high_severity }}</h2><p>High Severity</p></div>
        </div>

        {% for ip, data in results.items() %}
        <div class="host-block">
            <div class="host-header">
                <h3>{{ ip }} ({{ data.target }})</h3>
                <div>
                    <span class="os-badge">{{ data.get('os', 'Unknown') }}</span>
                    <span style="color: #94a3b8; margin-left: 10px;">{{ data.get('family', 'IPv4') }}</span>
                </div>
            </div>
            {% if data.ports %}
            <table>
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Service</th>
                        <th>Version</th>
                        <th>OS Hint</th>
                        <th>Banner</th>
                        <th>SSL/TLS</th>
                        <th>CVEs</th>
                        <th>Severity</th>
                    </tr>
                </thead>
                <tbody>
                    {% for p in data.ports %}
                    <tr>
                        <td>{{ p.port }}/tcp</td>
                        <td>{{ p.service }}</td>
                        <td>{{ p.version }}</td>
                        <td>{{ p.os_hint }}</td>
                        <td><span class="banner-text" title="{{ p.banner }}">{{ p.banner[:50] }}</span></td>
                        <td>
                            {% if p.ssl %}
                                <span class="ssl-badge">🔒 {{ p.ssl.get('protocol', 'TLS') }}</span><br>
                                <small>{{ p.ssl.get('subject_cn', '') }}</small>
                            {% else %}
                                -
                            {% endif %}
                        </td>
                        <td>
                            {% if p.cves %}
                                {% for cve in p.cves %}
                                    <span class="cve-tag" title="{{ cve.get('summary', '') }}">{{ cve.get('id', 'N/A') }}</span>
                                {% endfor %}
                            {% else %}
                                -
                            {% endif %}
                        </td>
                        <td class="severity-{{ p.severity.lower() }}">{{ p.severity }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
            <div class="no-ports">No open ports found</div>
            {% endif %}
        </div>
        {% endfor %}
    </div>
</body>
</html>
"""

class VanguardReporter:
    @staticmethod
    def to_json(results, filename="report.json"):
        with open(filename, "w") as f:
            json.dump(results, f, indent=4)

    @staticmethod
    def to_csv(results, filename="report.csv"):
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "IP", "Target", "Family", "OS", "Port", "Service", "Version",
                "OS Hint", "Banner", "Severity", "SSL Subject", "SSL Issuer",
                "SSL Expiry", "CVEs"
            ])
            for ip, data in results.items():
                if not data["ports"]:
                    writer.writerow([
                        ip, data["target"], data.get("family", "IPv4"),
                        data.get("os", "N/A"), "None", "None", "None",
                        "None", "None", "Info", "", "", "", ""
                    ])
                for p in data["ports"]:
                    ssl_info = p.get("ssl", {})
                    cves = p.get("cves", [])
                    cve_ids = "; ".join(c.get("id", "") for c in cves) if cves else ""
                    writer.writerow([
                        ip, data["target"], data.get("family", "IPv4"),
                        data.get("os", "N/A"),
                        p["port"], p["service"], p.get("version", "N/A"),
                        p.get("os_hint", "N/A"), p["banner"], p["severity"],
                        ssl_info.get("subject_cn", ""),
                        ssl_info.get("issuer_cn", ""),
                        ssl_info.get("not_after", ""),
                        cve_ids
                    ])

    @staticmethod
    def to_html(results, filename="report.html"):
        total_hosts = len(results)
        total_ports = sum(len(h["ports"]) for h in results.values())
        high_severity = sum(1 for h in results.values() for p in h["ports"] if p["severity"] == "High")
        total_cves = sum(len(p.get("cves", [])) for h in results.values() for p in h["ports"])
        total_ssl = sum(1 for h in results.values() for p in h["ports"] if p.get("ssl"))
        
        template = Template(HTML_TEMPLATE)
        html_content = template.render(
            results=results,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_hosts=total_hosts,
            total_ports=total_ports,
            high_severity=high_severity,
            total_cves=total_cves,
            total_ssl=total_ssl
        )
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html_content)

    @staticmethod
    def generate_summary(results):
        total_hosts = len(results)
        open_hosts = len([h for h in results.values() if h["ports"]])
        total_ports = sum(len(h["ports"]) for h in results.values())
        total_cves = sum(len(p.get("cves", [])) for h in results.values() for p in h["ports"])
        total_ssl = sum(1 for h in results.values() for p in h["ports"] if p.get("ssl"))
        
        # Severity breakdown
        counts = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for h in results.values():
            for p in h["ports"]:
                sev = p.get("severity", "Low")
                counts[sev] = counts.get(sev, 0) + 1
        
        summary = f"\n\033[1;36m{'=' * 50}\033[0m\n"
        summary += f"\033[1;36m[!] VANGUARD MISSION SUMMARY [!]\033[0m\n"
        summary += f"\033[1;36m{'=' * 50}\033[0m\n"
        summary += f"[*] Status: Mission Accomplished\n"
        summary += f"[*] Targets Analyzed: {total_hosts} (Open: {open_hosts})\n"
        summary += f"[*] Total Surface Area: {total_ports} open ports\n"
        summary += f"[*] SSL Certificates: {total_ssl}\n"
        summary += f"[*] CVEs Discovered: {total_cves}\n"
        summary += f"[*] Threats: \033[1;31mH:{counts['High']}\033[0m | \033[1;33mM:{counts['Medium']}\033[0m | \033[1;32mL:{counts['Low']}\033[0m\n"
        return summary
