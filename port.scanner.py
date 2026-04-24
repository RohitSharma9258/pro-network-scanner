import asyncio
import argparse
import sys
import logging
import uvicorn
import signal
import os
from uuid import uuid4
from tqdm import tqdm

from core.scanner import VanguardEngine
from core.database import VanguardDatabase
from core.config import Config, setup_logging
from core.plugins.manager import PluginManager
from api.server import app, shared_state, get_lock
from utils.validators import VanguardValidator
from utils.reporting import VanguardReporter

# Initialize
setup_logging()
logger = logging.getLogger("VanguardCLI")

BANNER = r"""\033[1;36m
  __     __ _    _   _  _____ _    _          _____  _____  
  \ \   / /   \ | \ | |/ ____| |  | |   /\   |  __ \|  __ \ 
   \ \_/ / /^\ \|  \| | |  __| |  | |  /  \  | |__) | |  | |
    \   / / _ \ | . ` | | |_ | |  | | / /\ \ |  _  /| |  | |
     | | / ___ \| |\  | |__| | |__| |/ ____ \| | \ \| |__| |
     |_|/_/   \_\_| \_|\_____|\____//_/    \_\_|  \_\_____/ 
    \033[1;37m>> VANGUARD TITAN v12.5 | ENTERPRISE EDITION | BY ROHIT\033[0m
"""

SCAN_PROFILES = {
    "stealth": {"workers": 5, "delay": 2.0, "timeout": 3.0, "retries": 3},
    "fast": {"workers": 500, "delay": 0.0, "timeout": 0.5, "retries": 1},
    "full": {"workers": 100, "delay": 0.1, "timeout": 1.5, "retries": 2}
}

async def shutdown(stop_event, db=None, srv=None):
    logger.info("Graceful shutdown initiated...")
    stop_event.set()
    if srv: srv.should_exit = True
    if db: await db.close()
    logger.info("System halted.")

def setup_args():
    parser = argparse.ArgumentParser(description="Vanguard Titan v12.5 - Enterprise Recon Suite")
    parser.add_argument("target", nargs="?", help="IP, CIDR, or Domain")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range")
    parser.add_argument("--top", type=int, help="Scan top X ports")
    parser.add_argument("--profile", choices=SCAN_PROFILES.keys(), help="Scan profile")
    parser.add_argument("--web", action="store_true", help="Start JWT-Hardened API")
    parser.add_argument("--resume", action="store_true", help="Resume from DB")
    parser.add_argument("-o", "--output", help="Output file base name")
    parser.add_argument("-f", "--format", choices=["json", "csv", "xml", "html"], default="html")
    return parser.parse_args()

async def main():
    print(BANNER)
    args = setup_args()

    # Profile logic
    profile = SCAN_PROFILES.get(args.profile, {})
    workers = profile.get("workers", Config.DEFAULT_WORKERS)
    timeout = profile.get("timeout", Config.DEFAULT_TIMEOUT)
    delay = profile.get("delay", Config.DEFAULT_DELAY)
    retries = profile.get("retries", Config.MAX_RETRIES)

    # Acceptance
    if not os.getenv("VANGUARD_SKIP_DISCLAIMER") and input("\033[1;31m[!] ACCEPT LEGAL TERMS? (y/n): \033[0m").lower() != 'y':
        return

    target_str = args.target or input("\033[1;33m[?] Target: \033[0m").strip()
    if not VanguardValidator.validate_target(target_str):
        logger.error("Invalid target format.")
        return

    ports = VanguardValidator.get_top_ports(args.top) if args.top else VanguardValidator.sanitize_port(args.ports)
    
    # Initialize Core
    db = VanguardDatabase()
    engine = VanguardEngine(ports, timeout=timeout, workers=workers, delay=delay, retries=retries)
    plugin_mgr = PluginManager()
    plugin_mgr.load_plugins()
    
    # Target Expansion
    if "/" in target_str:
        import ipaddress
        targets = [str(ip) for ip in ipaddress.IPv4Network(target_str, strict=False)]
    else: targets = [target_str]

    if args.resume:
        targets = [t for t in targets if not db.is_already_scanned(t)]

    if not targets:
        logger.info("Nothing to scan.")
        return

    # API Startup
    stop_event = asyncio.Event()
    srv = None
    if args.web:
        uv_config = uvicorn.Config(app, port=8000, log_level="warning")
        srv = uvicorn.Server(uv_config)
        asyncio.create_task(srv.serve())

    # Execution
    print(f"\033[1;34m[*] MISSION START [Session: {str(uuid4())[:8]}] Profile: {args.profile or 'Custom'}\033[0m")
    
    try:
        with tqdm(total=len(targets), desc="Probing Targets", unit="host") as pbar:
            results = await engine.scan(targets, progress_callback=pbar.update)
    except Exception as e:
        logger.critical(f"Engine Failure: {e}")
        results = {}

    # Run Plugins (Isolated Process) & Update Shared State
    lock = get_lock()
    async with lock:
        for ip, res in results.items():
            results[ip] = await plugin_mgr.run_plugins_isolated(ip, res)
        shared_state["results"] = results

    # Reporting
    print("\n\033[1;35m[+] ENTERPRISE ANALYSIS:\033[0m")
    for ip, info in results.items():
        if info["ports"]:
            db.save_batch(info, info["ports"])
            print(f"\033[1;36m[+] {ip} ({info['target']})\033[0m")
            for p in info["ports"]:
                print(f"    - \033[1;32m{p['port']}/tcp\033[0m {p['service']} {p.get('version', '')} [{p.get('os_hint', 'N/A')}]")

    if args.output:
        VanguardReporter.to_html(results, f"{args.output}.html") if args.format == "html" else None
        # Other formats...
        print(f"\033[1;32m[!] Intelligence saved.\033[0m")

    print(VanguardReporter.generate_summary(results))

    # Shutdown
    if args.web:
        print("\033[1;33m[!] Dashboard Active. Ctrl+C to exit.\033[0m")
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try: loop.add_signal_handler(sig, lambda: asyncio.create_task(shutdown(stop_event, db, srv)))
            except NotImplementedError: pass
        try:
            while not stop_event.is_set(): await asyncio.sleep(1)
        except (KeyboardInterrupt, asyncio.CancelledError): await shutdown(stop_event, db, srv)
    else: await db.close()

if __name__ == "__main__":
    try: asyncio.run(main())
    except KeyboardInterrupt: pass
    except Exception as e:
        logger.critical(f"Fatal: {e}")
        sys.exit(1)
