import ipaddress
import re

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
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 
            1723, 3306, 3389, 5900, 8080, 8443
        ]
        # In a real tool, this would be a larger list
        return COMMON_PORTS[:count]
