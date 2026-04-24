import asyncio
import argparse
import sys
import ipaddress
import uvicorn
from core.scanner import VanguardEngine
from core.database import VanguardDatabase
from api.server import app, shared_state
from utils.validators import VanguardValidator

# Simple entry point for Vanguard Titan
async def main():
    parser = argparse.ArgumentParser(description="Vanguard Titan v11.0")
    parser.add_argument("target", nargs="?", help="Target IP/CIDR/Domain")
    parser.add_argument("-p", "--ports", default="1-1024")
    parser.add_argument("-w", "--workers", type=int, default=100)
    parser.add_argument("--web", action="store_true")
    args = parser.parse_args()

    if not args.target:
        args.target = input("\033[1;33m[?] Target: \033[0m").strip()

    targets = [args.target] if "/" not in args.target else [str(ip) for ip in ipaddress.IPv4Network(args.target, False)]
    ports = VanguardValidator.sanitize_port(args.ports)
    
    db = VanguardDatabase()
    engine = VanguardEngine(ports, workers=args.workers)

    if args.web:
        config = uvicorn.Config(app, port=8000, log_level="error")
        srv = uvicorn.Server(config)
        asyncio.create_task(srv.serve())

    results = await engine.scan(targets)
    shared_state["results"] = results
    
    for ip, info in results.items():
        db.save_batch(info, info["ports"])
        print(f"[+] {ip} Scanned.")

if __name__ == "__main__":
    asyncio.run(main())
