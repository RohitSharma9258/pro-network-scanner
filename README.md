<<<<<<< HEAD
# Vanguard Titan v11.0 (Cyber Intelligence Suite)

Vanguard Titan is a high-performance, asynchronous reconnaissance engine designed for enterprise-grade security auditing and network intelligence.

## 🏛️ Architecture
Built on a **Producer-Consumer Worker Queue** model, Vanguard Titan ensures high throughput while maintaining system stability even during large-scale network scans.

- **Engine**: Asyncio-based worker system with strict rate limiting.
- **API**: Secured FastAPI with Basic Auth and Pydantic validation.
- **Storage**: Indexed SQLite for lightning-fast historical lookups.
- **Security**: Mandatory legal disclaimer and input sanitization.

## 🚀 Key Features
- **Parallel Processing**: Concurrent scanning of multiple hosts.
- **Secure Dashboard**: Password-protected web interface.
- **Input Validation**: Sanitizes IPs, CIDRs, and Domains.
- **Persistence**: Batch-processed results with historical tracking.

## 🛠️ Setup
```bash
# Install dependencies
pip install -r requirements.txt

# Run the suite
python port.scanner.py 192.168.1.0/24 --web
```

## 🔐 Credentials
- **Username**: `admin`
- **Password**: `vanguard123`

## 📄 License
This tool is for educational purposes only. Unauthorized use is prohibited.
=======
# pro-network-scanner
“Advanced asynchronous port scanner with API, JWT authentication, banner grabbing, and service detection.”
>>>>>>> e41bfb3217abf8b924aa45569dcccb2e58c48967
