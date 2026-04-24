import json
import csv
import xml.etree.ElementTree as ET
from datetime import datetime
from jinja2 import Template

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Vanguard Titan Pro Max - Scan Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #e2e8f0; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        h1 { color: #38bdf8; border-bottom: 2px solid #38bdf8; padding-bottom: 10px; }
        .summary { display: flex; gap: 20px; margin-bottom: 30px; }
        .card { background: #1e293b; padding: 20px; border-radius: 8px; flex: 1; text-align: center; }
        .card h2 { margin: 0; font-size: 2em; color: #38bdf8; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; background: #1e293b; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #334155; }
        th { background: #334155; color: #38bdf8; }
        .severity-low { color: #4ade80; }
        .severity-medium { color: #fbbf24; }
        .severity-high { color: #f87171; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Vanguard Titan Scan Report</h1>
        <p>Generated at: {{ timestamp }} | Targets: {{ total_hosts }}</p>
        
        <div class="summary">
            <div class="card"><h2>{{ total_hosts }}</h2><p>Hosts Scanned</p></div>
            <div class="card"><h2>{{ total_ports }}</h2><p>Open Ports</p></div>
            <div class="card"><h2>{{ high_severity }}</h2><p>High Severity Issues</p></div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>IP / Target</th>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Version</th>
                    <th>OS Hint</th>
                    <th>Severity</th>
                </tr>
            </thead>
            <tbody>
                {% for ip, data in results.items() %}
                    {% if data.ports %}
                        {% for p in data.ports %}
                        <tr>
                            <td>{{ ip }} ({{ data.target }})</td>
                            <td>{{ p.port }}</td>
                            <td>{{ p.service }}</td>
                            <td>{{ p.version }}</td>
                            <td>{{ p.os_hint }}</td>
                            <td class="severity-{{ p.severity.lower() }}">{{ p.severity }}</td>
                        </tr>
                        {% endfor %}
                    {% else %}
                        <tr>
                            <td>{{ ip }} ({{ data.target }})</td>
                            <td colspan="5">No open ports found</td>
                        </tr>
                    {% endif %}
                {% endfor %}
            </tbody>
        </table>
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
            writer.writerow(["IP", "Target", "Family", "Port", "Service", "Version", "OS Hint", "Banner", "Severity"])
            for ip, data in results.items():
                if not data["ports"]:
                    writer.writerow([ip, data["target"], data.get("family", "IPv4"), "None", "None", "None", "None", "None", "Info"])
                for p in data["ports"]:
                    writer.writerow([
                        ip, data["target"], data.get("family", "IPv4"), 
                        p["port"], p["service"], p.get("version", "N/A"), 
                        p.get("os_hint", "N/A"), p["banner"], p["severity"]
                    ])

    @staticmethod
    def to_html(results, filename="report.html"):
        total_hosts = len(results)
        total_ports = sum(len(h["ports"]) for h in results.values())
        high_severity = sum(1 for h in results.values() for p in h["ports"] if p["severity"] == "High")
        
        template = Template(HTML_TEMPLATE)
        html_content = template.render(
            results=results,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_hosts=total_hosts,
            total_ports=total_ports,
            high_severity=high_severity
        )
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html_content)

    @staticmethod
    def generate_summary(results):
        total_hosts = len(results)
        open_hosts = len([h for h in results.values() if h["ports"]])
        total_ports = sum(len(h["ports"]) for h in results.values())
        
        # Severity breakdown
        counts = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for h in results.values():
            for p in h["ports"]:
                counts[p["severity"]] = counts.get(p["severity"], 0) + 1
        
        summary = f"\n\033[1;36m[!] VANGUARD MISSION SUMMARY [!]\033[0m\n"
        summary += f"[*] Status: Mission Accomplished\n"
        summary += f"[*] Targets Analyzed: {total_hosts} (Open: {open_hosts})\n"
        summary += f"[*] Total Surface Area: {total_ports} open ports\n"
        summary += f"[*] Threats Found: \033[1;31mH:{counts['High']}\033[0m | \033[1;33mM:{counts['Medium']}\033[0m | \033[1;32mL:{counts['Low']}\033[0m\n"
        return summary
