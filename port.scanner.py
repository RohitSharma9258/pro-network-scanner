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
    "stealth": {"workers": 10,  "delay": 1.5, "timeout": 2.0, "retries": 3},
    "fast":    {"workers": 1000, "delay": 0.0, "timeout": 0.4, "retries": 1},
    "full":    {"workers": 500,  "delay": 0.0, "timeout": 0.7, "retries": 2}
}

async def shutdown(stop_event, db=None, srv=None):
    logger.info("Graceful shutdown initiated...")
    stop_event.set()
    if srv: srv.should_exit = True
    if db: await db.close()
    logger.info("System halted.")

def setup_args():
    parser = argparse.ArgumentParser(
        description="Vanguard Titan v12.5 - Enterprise Recon Suite",
        epilog="""Multi-Target Examples:
  %(prog)s 192.168.1.1,192.168.1.2,10.0.0.1
  %(prog)s 192.168.1.1-192.168.1.50
  %(prog)s 192.168.1.1-50
  %(prog)s 192.168.1.0/24
  %(prog)s @targets.txt
  %(prog)s 192.168.1.1,10.0.0.0/24,example.com""",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("target", nargs="?", help="Target(s): IP, CIDR, range, comma-separated, or @file.txt")
    parser.add_argument("-t", "--targets", nargs="+", help="Multiple targets (space-separated)")
    parser.add_argument("-tL", "--target-list", help="File with targets (one per line)")
    parser.add_argument("-p", "--ports", default="1-10000", help="Port range (default: 1-10000)")
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
            logger.error("No targets provided.")
            return
        raw_targets.append(user_input)

    # Parse & Validate all targets
    targets = []
    for raw in raw_targets:
        parsed = VanguardValidator.validate_targets(raw)
        if not parsed:
            logger.warning(f"Invalid or empty target: {raw}")
        targets.extend(parsed)
    
    # Deduplicate
    seen = set()
    targets = [t for t in targets if not (t in seen or seen.add(t))]

    if not targets:
        logger.error("No valid targets found.")
        return

    print(f"\033[1;34m[*] Loaded {len(targets)} target(s) for scanning\033[0m")

    ports = VanguardValidator.get_top_ports(args.top) if args.top else VanguardValidator.sanitize_port(args.ports)
    
    # Initialize Core
    db = VanguardDatabase()
    engine = VanguardEngine(ports, timeout=timeout, workers=workers, delay=delay, retries=retries)
    plugin_mgr = PluginManager()
    plugin_mgr.load_plugins()

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
    print("\n\033[1;35m" + "=" * 70 + "\033[0m")
    print("\033[1;35m[+] ENTERPRISE ANALYSIS REPORT\033[0m")
    print("\033[1;35m" + "=" * 70 + "\033[0m")
    
    for ip, info in results.items():
        os_fp = info.get("os", "Unknown")
        print(f"\n\033[1;36m╔══ TARGET: {ip} ({info['target']}) | OS: {os_fp} | {info.get('family', 'IPv4')}\033[0m")
        
        if info["ports"]:
            db.save_batch(info, info["ports"])
            for p in info["ports"]:
                sev = p.get("severity", "Low")
                sev_color = {"High": "1;31", "Medium": "1;33", "Low": "1;32"}.get(sev, "0")
                
                print(f"  \033[1;32m╠══ {p['port']}/tcp\033[0m  "
                      f"Service: \033[1;37m{p['service']}\033[0m  "
                      f"Version: \033[1;37m{p.get('version', 'N/A')}\033[0m  "
                      f"OS: \033[1;37m{p.get('os_hint', 'N/A')}\033[0m  "
                      f"Severity: \033[{sev_color}m{sev}\033[0m")
                
                # Banner
                banner = p.get("banner", "")
                if banner and banner != "Open":
                    print(f"  ║   \033[0;90m Banner: {banner[:80]}\033[0m")
                
                # SSL Info
                ssl_info = p.get("ssl", {})
                if ssl_info:
                    print(f"  ║   \033[1;34m🔒 SSL/TLS:\033[0m")
                    print(f"  ║      Subject: {ssl_info.get('subject_cn', 'N/A')}")
                    print(f"  ║      Issuer:  {ssl_info.get('issuer_cn', 'N/A')} ({ssl_info.get('issuer_org', 'N/A')})")
                    print(f"  ║      Valid:   {ssl_info.get('not_before', '?')} → {ssl_info.get('not_after', '?')}")
                    if ssl_info.get("protocol"):
                        print(f"  ║      Proto:   {ssl_info.get('protocol', 'N/A')} | Cipher: {ssl_info.get('cipher', 'N/A')}")
                
                # CVE Info
                cves = p.get("cves", [])
                if cves:
                    print(f"  ║   \033[1;31m⚠ CVEs Found ({len(cves)}):\033[0m")
                    for cve in cves:
                        cvss = cve.get("cvss", "N/A")
                        print(f"  ║      \033[1;31m{cve.get('id', 'N/A')}\033[0m [CVSS: {cvss}] {cve.get('summary', '')[:60]}")
        else:
            print(f"  \033[0;90m╠══ No open ports found\033[0m")
        
        print(f"  \033[1;36m╚══ Scan completed at {info.get('timestamp', 'N/A')}\033[0m")

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
