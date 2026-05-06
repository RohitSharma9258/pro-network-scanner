# ⚡ Vanguard Titan — Pro Network Scanner

> Advanced asynchronous network reconnaissance engine built for authorized security auditing.

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688?logo=fastapi&logoColor=white)
![Asyncio](https://img.shields.io/badge/Concurrency-Asyncio-blueviolet)
![License](https://img.shields.io/badge/License-Educational%20Use-orange)
![Auth](https://img.shields.io/badge/Auth-JWT%20%2B%20bcrypt-success)

---

## What it does

Vanguard Titan scans networks at high speed, identifying open ports, running services, OS families, and SSL certificates — then logs everything to a database and generates detailed reports. Built with a **producer-consumer async engine** that can handle large CIDR ranges efficiently without overwhelming the target or the host machine.

---

## Features

| Category | Details |
|---|---|
| **Scanning** | IPs, CIDR ranges (`192.168.1.0/24`), domains, IP ranges (`x.x.x.1-10`), and bulk file input (`@targets.txt`) |
| **Service Detection** | Banner grabbing for SSH, FTP, HTTP, SMTP, RDP, MySQL, PostgreSQL, MongoDB, Redis, Nginx, Apache, IIS |
| **OS Fingerprinting** | TTL-based heuristic (Linux/Unix · Windows · Network Device) |
| **SSL/TLS** | Certificate extraction on ports 443, 993, 995, 8443 and more |
| **Performance** | Up to 1,000 concurrent connections; priority scanning of well-known ports first |
| **API** | Secured FastAPI dashboard with JWT auth, bcrypt password hashing, rate limiting, and token revocation |
| **Persistence** | Batch-processed SQLite storage for scan history and host records |
| **Reports** | Export to HTML, JSON, CSV, and XML |
| **Plugins** | Extensible plugin system with process-level isolation to prevent crashes/RCE |

---

## Architecture

```
main.py
  │
  ├── VanguardValidator     ← Input parsing (IP / CIDR / domain / range / @file)
  │
  ├── VanguardEngine        ← Async producer-consumer scan engine
  │     ├── Port scanner    ← Parallel TCP connection attempts
  │     ├── Banner grabber  ← Service identification via protocol signatures
  │     ├── SSL extractor   ← TLS certificate metadata
  │     └── PluginManager   ← Sandboxed plugin execution
  │
  ├── VanguardDatabase      ← SQLite persistence (batch-write queue)
  │
  ├── FastAPI server        ← REST API + JWT auth + web dashboard
  │
  └── Reporting             ← HTML / JSON / CSV / XML export
```

---

## Quick start

### 1. Clone & install

```bash
git clone https://github.com/RohitSharma9258/pro-network-scanner.git
cd pro-network-scanner
pip install -r requirements.txt
```

### 2. Configure credentials

Copy the example env file and set your own values — **never use the defaults in production**:

```bash
cp .env.example .env
```

Edit `.env`:

```env
API_USER=your_username
API_PASSWORD_RAW=your_strong_password
JWT_SECRET_KEY=replace-with-a-long-random-string
ENV=production
```

### 3. Run a scan

```bash
# Single IP
python main.py 192.168.1.1

# CIDR range
python main.py 192.168.1.0/24

# Multiple targets (comma-separated)
python main.py 192.168.1.1,192.168.1.5,scanme.nmap.org

# IP range
python main.py 192.168.1.1-192.168.1.50

# Bulk targets from file
python main.py @targets.txt

# With custom port range and worker count
python main.py 192.168.1.0/24 -p 1-65535 -w 200

# Launch with web dashboard
python main.py 192.168.1.0/24 --web
# Then open http://localhost:8000
```

---

## CLI options

| Flag | Description | Default |
|---|---|---|
| `target` | Target(s): IP, CIDR, range, or `@file` | — |
| `-t / --targets` | Multiple space-separated targets | — |
| `-tL / --target-list` | File path with one target per line | — |
| `-p / --ports` | Port range | `1-10000` |
| `-w / --workers` | Concurrent worker threads | `100` |
| `--web` | Enable the FastAPI web dashboard | off |

---

## Docker

```bash
docker build -t vanguard-titan .
docker run --rm vanguard-titan 192.168.1.0/24
```

---

## Project structure

```
pro-network-scanner/
├── main.py                  # Entry point
├── port.scanner.py          # Standalone port scanner module
├── requirements.txt
├── Dockerfile
│
├── core/
│   ├── scanner.py           # VanguardEngine — async scan logic
│   ├── database.py          # SQLite persistence layer
│   ├── config.py            # Pydantic settings (reads from .env)
│   ├── exceptions.py        # Custom exception types
│   └── plugins/
│       ├── base.py          # VanguardPlugin abstract base class
│       └── manager.py       # Plugin loader with process isolation
│
├── api/
│   └── server.py            # FastAPI app — JWT auth, rate limiting, endpoints
│
├── utils/
│   ├── validators.py        # Target validation & parsing
│   └── reporting.py        # HTML / JSON / CSV / XML report generation
│
└── tests/
    └── test_scanner.py
```

---

## Writing a plugin

Drop a `.py` file into `plugins/` that inherits `VanguardPlugin`:

```python
from core.plugins.base import VanguardPlugin

class MyPlugin(VanguardPlugin):
    name = "my_plugin"

    async def run(self, target: str, results: dict) -> dict:
        # Add custom logic — e.g. reverse DNS, geo-IP, CVE lookup
        results["custom"] = f"Processed {target}"
        return results
```

Plugins run in isolated processes to prevent a crash or malicious plugin from taking down the main scanner.

---

## Ethical & legal notice

This tool is intended **strictly for authorized security testing, educational use, and research on networks you own or have explicit written permission to scan.** Unauthorized use against systems you do not own is illegal under the IT Act 2000 (India), the Computer Fraud and Abuse Act (USA), and equivalent laws worldwide.

Always obtain written authorization before scanning any network.

---

## Author

**Rohit Sharma** — B.Tech CSE, GLA University, Mathura  
[GitHub](https://github.com/RohitSharma9258) · [Email](mailto:rohitsharma40421@gmail.com)
