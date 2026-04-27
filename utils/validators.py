import ipaddress
import re
import os

class VanguardValidator:
    @staticmethod
    def validate_target(target):
        """Validate if target is a valid IP, CIDR, or Domain."""
        if not target:
            return False
        
        # Check for IP or CIDR
        try:
            if "/" in target:
                ipaddress.IPv4Network(target, strict=False)
                return True
            ipaddress.IPv4Address(target)
            return True
        except ValueError:
            pass
            
        # Check for Domain (must have at least one dot to be considered a domain, or be 'localhost')
        if target.lower() == "localhost":
            return True
        domain_regex = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
        if re.match(domain_regex, target.lower()):
            return len(target) <= 253
        
        return False

    @staticmethod
    def validate_targets(target_str):
        """Parse multi-target input: comma-separated, IP range, or file path.
        
        Supported formats:
          - Single: 192.168.1.1
          - Comma-separated: 192.168.1.1,192.168.1.2,example.com
          - CIDR: 192.168.1.0/24
          - IP Range: 192.168.1.1-192.168.1.10
          - File: @targets.txt (one target per line)
        Returns list of validated individual targets.
        """
        targets = []

        # File input: @filepath
        if target_str.startswith("@"):
            filepath = target_str[1:]
            if not os.path.isfile(filepath):
                return []
            with open(filepath, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            for line in lines:
                targets.extend(VanguardValidator.validate_targets(line))
            return targets

        # Split by comma for multiple targets
        parts = [t.strip() for t in target_str.split(",") if t.strip()]

        for part in parts:
            # CIDR notation
            if "/" in part:
                try:
                    network = ipaddress.IPv4Network(part, strict=False)
                    targets.extend([str(ip) for ip in network])
                except ValueError:
                    pass
                continue

            # IP Range: 192.168.1.1-192.168.1.10 or 192.168.1.1-10
            if "-" in part:
                try:
                    start_str, end_str = part.split("-", 1)
                    start_ip = ipaddress.IPv4Address(start_str.strip())
                    end_str = end_str.strip()
                    # Short form: 192.168.1.1-10
                    if "." not in end_str:
                        base = str(start_ip).rsplit(".", 1)[0]
                        end_ip = ipaddress.IPv4Address(f"{base}.{end_str}")
                    else:
                        end_ip = ipaddress.IPv4Address(end_str)
                    if int(start_ip) <= int(end_ip):
                        current = int(start_ip)
                        while current <= int(end_ip):
                            targets.append(str(ipaddress.IPv4Address(current)))
                            current += 1
                    continue
                except (ValueError, TypeError):
                    pass

            # Single IP or domain
            if VanguardValidator.validate_target(part):
                targets.append(part)

        # Remove duplicates, preserve order
        seen = set()
        unique = []
        for t in targets:
            if t not in seen:
                seen.add(t)
                unique.append(t)
        return unique

    @staticmethod
    def sanitize_port(port_str):
        """Parse port strings like '80', '1-1024', '22,80,443'."""
        ports = set()
        try:
            parts = port_str.replace(" ", "").split(",")
            for part in parts:
                if "-" in part:
                    start, end = map(int, part.split("-"))
                    if 1 <= start <= 65535 and 1 <= end <= 65535:
                        ports.update(range(min(start, end), max(start, end) + 1))
                else:
                    p = int(part)
                    if 1 <= p <= 65535:
                        ports.add(p)
        except (ValueError, AttributeError):
            return []
        
        return sorted(list(ports))

    @staticmethod
    def get_top_ports(count=100):
        """Commonly used ports for presets."""
        COMMON_PORTS = [
            21, 22, 23, 25, 53, 80, 89, 110, 113, 135, 139, 143, 443, 445,
            993, 995, 1433, 1723, 3306, 3389, 5432, 5900, 6379,
            8080, 8081, 8082, 8083, 8084, 8085, 8087, 8088, 8090, 8093,
            8099, 8443, 8888, 9081, 9090, 27017
        ]
        # In a real tool, this would be a larger list
        return COMMON_PORTS[:count]
