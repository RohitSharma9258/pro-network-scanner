# 🛡️ Vanguard Titan v11.0 (Cyber Intelligence Suite)

Vanguard Titan is a high-performance, asynchronous reconnaissance engine designed for enterprise-grade security auditing and network intelligence.

---

## 🏛️ Architecture

Built on a **Producer-Consumer Worker Queue** model, Vanguard Titan ensures high throughput while maintaining system stability even during large-scale network scans.

- **Engine**: Asyncio-based worker system with strict rate limiting  
- **API**: Secured FastAPI with JWT authentication and validation  
- **Storage**: Indexed SQLite for fast historical lookups  
- **Security**: Input sanitization and legal disclaimer enforced  

---

## 🚀 Key Features

- ⚡ Parallel Processing: Concurrent scanning of multiple hosts  
- 🔐 Secure Dashboard: Password-protected web interface  
- 🧠 Input Validation: Sanitizes IPs, CIDRs, and domains  
- 📊 Persistence: Batch-processed scan history tracking  
- 📡 Banner Grabbing & Service Detection  

---

## 🛠️ Setup

pip install -r requirements.txt
python port.scanner.py 192.168.1.0/24 --web

🔐 Credentials (Dev Only)
Username: admin

Password: vanguard123
📄 License

This tool is strictly for educational and authorized security testing purposes only. Unauthorized usage is prohibited.


---

# ⚙️ NOW FIX GIT (IMPORTANT)

Run:

```bash
git add README.md
git commit -m "Resolved README merge conflict and standardized documentation"
git push origin main

