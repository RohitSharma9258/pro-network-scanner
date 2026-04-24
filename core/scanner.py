import asyncio
import socket
import logging
import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from core.config import Config
from core.exceptions import ScannerError, NetworkError

logger = logging.getLogger(__name__)

class VanguardEngine:
    """Enterprise Scan Engine: Adaptive, Prioritized, and Failure-Resistant."""
    
    _global_semaphore = asyncio.Semaphore(Config.GLOBAL_MAX_CONCURRENCY)

    SIGNATURES = {
        "SSH": [r"SSH-([\d\._-]+)-([a-zA-Z0-9\._-]+)"],
        "FTP": [r"220[ -](?:.*)FTP", r"220[ -]vsFTPd ([\d\.]+)"],
        "HTTP": [r"HTTP/\d\.\d", r"Server: ([\w/ \.\(\)-]+)"],
        "MySQL": [r"([\d\.]+)-MariaDB", r"^.\x00\x00\x00\x0a([\d\.]+)"],
        "Redis": [r"-ERR unknown command", r"\+PONG"],
        "SMTP": [r"220 ([\w\.-]+) ESMTP"],
        "RDP": [r"\x03\x00\x00\x0b\x06\xd0\x00\x00\x124\x00"]
    }

    PRIORITY_PORTS = {22, 80, 443, 445, 3389, 8080}

    def __init__(self, ports: List[int], timeout: float = None, workers: int = None, delay: float = None, retries: int = None):
        # Sort ports by priority
        self.ports = sorted(ports, key=lambda p: p not in self.PRIORITY_PORTS)
        self.timeout = timeout or Config.DEFAULT_TIMEOUT
        self.workers = workers or Config.DEFAULT_WORKERS
        self.delay = delay or Config.DEFAULT_DELAY
        self.retries = retries or Config.MAX_RETRIES
        
        self.results = {}
        self.queue = asyncio.Queue()
        self.is_active = True
        self.adaptive_timeout = self.timeout

    async def _resolve_target(self, target: str) -> Tuple[Optional[str], Optional[int]]:
        """DNS resolution with explicit AF_INET/AF_INET6 handling."""
        try:
            # Check for direct IPs
            for family in (socket.AF_INET, socket.AF_INET6):
                try:
                    socket.inet_pton(family, target)
                    return target, family
                except socket.error: continue
            
            # Domain resolution
            info = await asyncio.get_event_loop().run_in_executor(None, socket.getaddrinfo, target, None)
            if info:
                family, _, _, _, sockaddr = info[0]
                return sockaddr[0], family
        except Exception as e:
            raise NetworkError(f"DNS resolution failed for {target}: {e}")
        return None, None

    async def _grab_banner(self, reader, writer) -> str:
        try:
            banner = await asyncio.wait_for(reader.read(1024), timeout=Config.BANNER_TIMEOUT)
            return banner.decode(errors='ignore').strip()
        except Exception:
            return ""

    def _detect_service(self, port: int, banner: str) -> Tuple[str, str, str, str]:
        service = "Unknown"
        version = "Unknown"
        os_hint = "Unknown"
        severity = "Low"

        PORT_MAP = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP"}
        service = PORT_MAP.get(port, "Unknown")

        if banner:
            for s_name, patterns in self.SIGNATURES.items():
                for pattern in patterns:
                    match = re.search(pattern, banner, re.I)
                    if match:
                        service = s_name
                        if match.groups():
                            version = match.group(1)
                            if len(match.groups()) > 1: os_hint = match.group(2)
                        break
            
            banner_low = banner.lower()
            if "ubuntu" in banner_low: os_hint = "Ubuntu/Linux"
            elif "microsoft" in banner_low: os_hint = "Windows"

        return service, version, severity, os_hint

    async def _probe_tcp(self, ip: str, port: int, family: int = socket.AF_INET) -> Optional[Dict]:
        """Classifies ports as Open, Closed (Refused), or Filtered (Timeout)."""
        last_status = "Closed"
        
        for attempt in range(self.retries + 1):
            async with self._global_semaphore:
                try:
                    if self.delay > 0: await asyncio.sleep(self.delay)
                    current_timeout = self.adaptive_timeout * (1 + attempt * 0.5)
                    
                    conn = asyncio.open_connection(ip, port, family=family)
                    reader, writer = await asyncio.wait_for(conn, timeout=current_timeout)
                    
                    banner = await self._grab_banner(reader, writer)
                    service, version, severity, os_hint = self._detect_service(port, banner)
                    
                    writer.close()
                    await writer.wait_closed()
                    
                    return {
                        "port": port, "proto": "TCP", "status": "Open", 
                        "service": service, "version": version, "os_hint": os_hint,
                        "banner": banner[:100] if banner else "Open", "severity": severity
                    }
                except ConnectionRefusedError:
                    last_status = "Closed"
                    break # Port is closed, no need to retry
                except (asyncio.TimeoutError, OSError):
                    last_status = "Filtered"
                    continue # Retry on timeout
                except Exception as e:
                    logger.debug(f"Probe error {ip}:{port} - {e}")
                    return None
        
        # Optionally return Filtered/Closed results if requested
        return None

    async def _worker(self, progress_callback=None):
        while self.is_active:
            try:
                item = await self.queue.get()
                host, original_host = item
                
                try:
                    ip, family = await self._resolve_target(host)
                except NetworkError as e:
                    logger.warning(str(e))
                    self.queue.task_done()
                    continue

                if not ip:
                    self.queue.task_done()
                    continue

                # Parallel probes (Throttled by global semaphore)
                tasks = [self._probe_tcp(ip, p, family) for p in self.ports]
                found_ports = [r for r in await asyncio.gather(*tasks) if r]
                
                self.results[ip] = {
                    "target": original_host, "ip": ip, "family": "IPv6" if family == socket.AF_INET6 else "IPv4",
                    "ports": found_ports, "timestamp": datetime.now().isoformat()
                }
                
                if progress_callback: progress_callback(1)
                self.queue.task_done()
            except asyncio.CancelledError: break
            except Exception as e:
                logger.error(f"Worker Failure: {e}")
                self.queue.task_done()

    async def scan(self, target_list: List[str], progress_callback=None) -> Dict:
        # Backpressure: CIDR Limiting
        MAX_TARGETS = 10000
        if len(target_list) > MAX_TARGETS:
            logger.warning(f"Scan list too large. Truncating to {MAX_TARGETS} targets.")
            target_list = target_list[:MAX_TARGETS]

        self.results = {}
        for t in target_list: self.queue.put_nowait((t, t)) 

        num_workers = min(self.workers, len(target_list)) if target_list else 1
        worker_tasks = [asyncio.create_task(self._worker(progress_callback)) for _ in range(num_workers)]
        
        try:
            await self.queue.join()
        finally:
            self.is_active = False
            for w in worker_tasks: w.cancel()
            await asyncio.gather(*worker_tasks, return_exceptions=True)
            
        return self.results
