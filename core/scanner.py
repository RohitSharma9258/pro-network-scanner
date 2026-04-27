import asyncio
import socket
import logging
import re
import ssl
import requests
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
        "HTTP": [r"HTTP/\d\.\d", r"Server: ([\w/ \._\(\)-]+)"],
        "MySQL": [r"([\d\.]+)-MariaDB", r"^.\x00\x00\x00\x0a([\d\.]+)"],
        "Redis": [r"-ERR unknown command", r"\+PONG"],
        "SMTP": [r"220 ([\w\.-]+) ESMTP"],
        "RDP": [r"\x03\x00\x00\x0b\x06\xd0\x00\x00\x124\x00"],
        "PostgreSQL": [r"PostgreSQL"],
        "MongoDB": [r"MongoDB", r"It looks like you are trying to access MongoDB"],
        "Nginx": [r"nginx/([\d\.]+)"],
        "Apache": [r"Apache/([\d\.]+)"],
        "IIS": [r"Microsoft-IIS/([\d\.]+)"],
    }

    # Common SSL/TLS ports for certificate extraction
    SSL_PORTS = {443, 8443, 9443, 993, 995, 990, 465, 636, 5223, 2083, 2087, 2096}

    PRIORITY_PORTS = {
        21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995,
        1433, 1723, 3306, 3389, 5432, 5900,
        8080, 8081, 8082, 8083, 8084, 8085, 8087, 8088, 8090, 8443, 8888, 9081
    }

    # TTL-based OS fingerprinting heuristics
    OS_TTL_MAP = {
        (0, 64): "Linux/Unix",
        (65, 128): "Windows",
        (129, 255): "Network Device/Solaris"
    }

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
                except socket.error:
                    continue
            
            # Domain resolution
            info = await asyncio.get_event_loop().run_in_executor(None, socket.getaddrinfo, target, None)
            if info:
                family, _, _, _, sockaddr = info[0]
                return sockaddr[0], family
        except Exception as e:
            raise NetworkError(f"DNS resolution failed for {target}: {e}")
        return None, None

    async def _grab_banner(self, reader, writer) -> str:
        """Grab service banner from open port."""
        try:
            banner = await asyncio.wait_for(reader.read(1024), timeout=Config.BANNER_TIMEOUT)
            return banner.decode(errors='ignore').strip()
        except Exception:
            return ""

    def _detect_service(self, port: int, banner: str) -> Tuple[str, str, str, str]:
        """Detect service, version, severity, and OS hint from port and banner."""
        service = "Unknown"
        version = "Unknown"
        os_hint = "Unknown"
        severity = "Low"

        PORT_MAP = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 89: "SU-MIT-TG", 110: "POP3", 113: "IDENT", 135: "MSRPC",
            139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
            995: "POP3S", 1433: "MSSQL", 1723: "PPTP", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Proxy", 8081: "HTTP-Alt",
            8082: "HTTP-Alt", 8083: "HTTP-Alt", 8084: "HTTP-Alt", 8085: "HTTP-Alt",
            8087: "HTTP-Alt", 8088: "HTTP-Alt", 8090: "HTTP-Alt", 8093: "HTTP-Alt",
            8099: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt", 9081: "HTTP-Alt",
            9090: "WebConsole", 27017: "MongoDB", 6379: "Redis"
        }
        service = PORT_MAP.get(port, "Unknown")

        # Severity by port risk
        HIGH_RISK = {21, 23, 445, 3389, 5900, 1433, 135, 139}
        MEDIUM_RISK = {22, 25, 110, 143, 3306, 5432, 27017, 6379, 8080}
        if port in HIGH_RISK:
            severity = "High"
        elif port in MEDIUM_RISK:
            severity = "Medium"

        if banner:
            for s_name, patterns in self.SIGNATURES.items():
                for pattern in patterns:
                    match = re.search(pattern, banner, re.I)
                    if match:
                        service = s_name
                        if match.groups():
                            version = match.group(1)
                            if len(match.groups()) > 1:
                                os_hint = match.group(2)
                        break
            
            banner_low = banner.lower()
            if "ubuntu" in banner_low:
                os_hint = "Ubuntu/Linux"
            elif "debian" in banner_low:
                os_hint = "Debian/Linux"
            elif "centos" in banner_low:
                os_hint = "CentOS/Linux"
            elif "red hat" in banner_low:
                os_hint = "RHEL/Linux"
            elif "microsoft" in banner_low or "windows" in banner_low:
                os_hint = "Windows"
            elif "freebsd" in banner_low:
                os_hint = "FreeBSD"

        return service, version, severity, os_hint

    def _fingerprint_os(self, ip: str) -> str:
        """OS fingerprinting via TTL analysis (ICMP-like heuristic using TCP)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, 80))  # Try port 80
            ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
            sock.close()
            for (low, high), os_name in self.OS_TTL_MAP.items():
                if low <= ttl <= high:
                    return os_name
        except Exception:
            pass
        return "Unknown"

    def _extract_ssl_info(self, ip: str, port: int) -> Dict:
        """Extract SSL certificate details from an SSL/TLS port."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(
                socket.create_connection((ip, port), timeout=self.timeout),
                server_hostname=ip
            ) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if not cert:
                    # Try binary form for basic info
                    return {"raw": "Certificate present but details unavailable"}
                
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                san_list = []
                for san_type, san_value in cert.get("subjectAltName", []):
                    san_list.append(f"{san_type}:{san_value}")
                
                return {
                    "subject_cn": subject.get("commonName", "N/A"),
                    "issuer_cn": issuer.get("commonName", "N/A"),
                    "issuer_org": issuer.get("organizationName", "N/A"),
                    "not_before": cert.get("notBefore", "N/A"),
                    "not_after": cert.get("notAfter", "N/A"),
                    "serial": cert.get("serialNumber", "N/A"),
                    "san": san_list[:5],  # Limit SAN entries
                    "version": cert.get("version", "N/A"),
                    "protocol": ssock.version() if hasattr(ssock, 'version') else "N/A",
                    "cipher": ssock.cipher()[0] if ssock.cipher() else "N/A",
                }
        except Exception as e:
            logger.debug(f"SSL extraction error for {ip}:{port} - {e}")
            return {}

    def _lookup_cves(self, service: str, version: str) -> List[Dict]:
        """Lookup CVEs for a given service/version via CIRCL CVE API."""
        try:
            if service == "Unknown" or version == "Unknown":
                return []
            
            # Use CIRCL CVE search API (free, no API key needed)
            vendor = service.lower().replace("-", "").replace("_", "")
            url = f"https://cve.circl.lu/api/search/{vendor}/{version}"
            resp = requests.get(url, timeout=5, headers={"User-Agent": "VanguardTitan/12.5"})
            
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list):
                    cves = []
                    for item in data[:5]:  # Top 5 CVEs
                        if isinstance(item, dict):
                            cve_id = item.get("id", "N/A")
                            summary = item.get("summary", "No description")
                            cvss = item.get("cvss", "N/A")
                            cves.append({
                                "id": cve_id,
                                "summary": summary[:120] if summary else "N/A",
                                "cvss": cvss
                            })
                    return cves
        except Exception as e:
            logger.debug(f"CVE lookup error for {service} {version}: {e}")
        return []

    async def _probe_tcp(self, ip: str, port: int, family: int = socket.AF_INET) -> Optional[Dict]:
        """Classifies ports as Open, Closed, or Filtered. Gathers banner, SSL info, and CVE data."""
        last_status = "Closed"
        
        for attempt in range(self.retries + 1):
            async with self._global_semaphore:
                try:
                    if self.delay > 0:
                        await asyncio.sleep(self.delay)
                    current_timeout = self.adaptive_timeout * (1 + attempt * 0.5)
                    
                    # Determine if SSL is needed for connection
                    use_ssl = port in self.SSL_PORTS
                    ssl_ctx = None
                    if use_ssl:
                        ssl_ctx = ssl.create_default_context()
                        ssl_ctx.check_hostname = False
                        ssl_ctx.verify_mode = ssl.CERT_NONE
                    
                    conn = asyncio.open_connection(ip, port, family=family, ssl=ssl_ctx)
                    reader, writer = await asyncio.wait_for(conn, timeout=current_timeout)
                    
                    banner = await self._grab_banner(reader, writer)
                    service, version, severity, os_hint = self._detect_service(port, banner)
                    
                    writer.close()
                    await writer.wait_closed()
                    
                    # SSL certificate extraction (separate sync connection)
                    ssl_info = {}
                    if use_ssl:
                        ssl_info = await asyncio.get_event_loop().run_in_executor(
                            None, self._extract_ssl_info, ip, port
                        )
                    
                    # CVE lookup (non-blocking)
                    cves = await asyncio.get_event_loop().run_in_executor(
                        None, self._lookup_cves, service, version
                    )
                    
                    return {
                        "port": port,
                        "proto": "TCP",
                        "status": "Open",
                        "service": service,
                        "version": version,
                        "os_hint": os_hint,
                        "banner": banner[:200] if banner else "Open",
                        "severity": severity,
                        "ssl": ssl_info,
                        "cves": cves
                    }
                except ConnectionRefusedError:
                    last_status = "Closed"
                    break  # Port is closed, no need to retry
                except (asyncio.TimeoutError, OSError):
                    last_status = "Filtered"
                    continue  # Retry on timeout
                except Exception as e:
                    logger.debug(f"Probe error {ip}:{port} - {e}")
                    return None
        
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

                # OS fingerprinting (run once per host)
                os_fingerprint = await asyncio.get_event_loop().run_in_executor(
                    None, self._fingerprint_os, ip
                )

                # Parallel probes (Throttled by global semaphore)
                tasks = [self._probe_tcp(ip, p, family) for p in self.ports]
                found_ports = [r for r in await asyncio.gather(*tasks) if r]

                # Enrich OS hint from fingerprint if individual ports didn't detect
                for p in found_ports:
                    if p.get("os_hint") == "Unknown" and os_fingerprint != "Unknown":
                        p["os_hint"] = os_fingerprint
                
                self.results[ip] = {
                    "target": original_host, "ip": ip,
                    "family": "IPv6" if family == socket.AF_INET6 else "IPv4",
                    "os": os_fingerprint,
                    "ports": found_ports,
                    "timestamp": datetime.now().isoformat()
                }
                
                if progress_callback:
                    progress_callback(1)
                self.queue.task_done()
            except asyncio.CancelledError:
                break
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
        for t in target_list:
            self.queue.put_nowait((t, t))

        num_workers = min(self.workers, len(target_list)) if target_list else 1
        worker_tasks = [asyncio.create_task(self._worker(progress_callback)) for _ in range(num_workers)]
        
        try:
            await self.queue.join()
        finally:
            self.is_active = False
            for w in worker_tasks:
                w.cancel()
            await asyncio.gather(*worker_tasks, return_exceptions=True)
            
        return self.results
