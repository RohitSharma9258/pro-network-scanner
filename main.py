import asyncio
import argparse
import sys
import uvicorn
from core.scanner import VanguardEngine
from core.database import VanguardDatabase
from api.server import app, shared_state
from utils.validators import VanguardValidator

# Simple entry point for Vanguard Titan
async def main():
    parser = argparse.ArgumentParser(description="Vanguard Titan v11.0")
    parser.add_argument("target", nargs="?", help="Target(s): IP, CIDR, range, comma-separated, or @file.txt")
    parser.add_argument("-t", "--targets", nargs="+", help="Multiple targets (space-separated)")
    parser.add_argument("-tL", "--target-list", help="File with targets (one per line)")
    parser.add_argument("-p", "--ports", default="1-10000")
    parser.add_argument("-w", "--workers", type=int, default=100)
    parser.add_argument("--web", action="store_true")
    args = parser.parse_args()

    # Multi-Target Collection
    raw_targets = []
    if args.target:
        raw_targets.append(args.target)
    if args.targets:
        raw_targets.extend(args.targets)
    if args.target_list:
        raw_targets.append(f"@{args.target_list}")
    
    if not raw_targets:
        user_input = input("\033[1;33m[?] Target(s) [comma-separated, CIDR, range, or @file]: \033[0m").strip()
        if not user_input:
            print("[!] No targets provided.")
            return
        raw_targets.append(user_input)

    # Parse & Validate
    targets = []
    for raw in raw_targets:
        targets.extend(VanguardValidator.validate_targets(raw))
    
    # Deduplicate
    seen = set()
    targets = [t for t in targets if not (t in seen or seen.add(t))]

    if not targets:
        print("[!] No valid targets found.")
        return

    print(f"[*] Loaded {len(targets)} target(s) for scanning")

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
