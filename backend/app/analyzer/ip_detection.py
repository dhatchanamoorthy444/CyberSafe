"""
CyberSafe - IP Address Detection Module
Analyzes whether a hostname is an IPv4, IPv6, obfuscated IP, or domain name strictly offline.
"""

from typing import List, Optional, Tuple
import ipaddress
import re
from .models import Finding
from .parser import ParsedURL


class IPDetector:
    """Detects standard and obfuscated IP address hosts in URLs."""

    @classmethod
    def analyze(cls, parsed: ParsedURL) -> Tuple[List[Finding], Optional[str]]:
        """
        Analyze hostname for IP address usage.
        Returns (findings, ip_type) where ip_type is 'ipv4', 'ipv6', 'obfuscated_ip', or None.
        """
        findings: List[Finding] = []
        host = parsed.hostname

        if not host:
            return findings, None

        # 1. Check standard IPv4 / IPv6 via ipaddress module
        try:
            ip_obj = ipaddress.ip_address(host)
            ip_type = f"IPv{ip_obj.version}"

            is_private = ip_obj.is_private
            is_loopback = ip_obj.is_loopback
            is_global = ip_obj.is_global

            scope_desc = "Private / Local Network" if (is_private or is_loopback) else "Public Internet"

            findings.append(
                Finding(
                    rule_id="IP_ADDRESS_HOST",
                    severity="medium",
                    score=25,
                    title=f"Direct {ip_type} address used as hostname",
                    message=(
                        f"The URL targets a raw {ip_type} address ({host}, {scope_desc}) "
                        f"instead of a domain name. While legitimate for local routers, development, or internal apps, "
                        f"direct IP URLs are frequently used in phishing to bypass domain reputation blocklists."
                    ),
                    evidence=f"Host: {host} ({ip_type}, {scope_desc})"
                )
            )
            return findings, ip_type.lower()
        except ValueError:
            pass

        # 2. Check for obfuscated IP formats (e.g. Hex, Octal, Dword/Integer IPs)
        # Examples: 0x7f000001 (Hex), 2130706433 (Dword), 0177.0.0.1 (Octal)
        obfuscated_found = False

        # Pure numeric hostname (DWORD IP) e.g. http://2130706433/
        if re.match(r"^\d{8,10}$", host):
            try:
                num = int(host)
                if 0 <= num <= 4294967295:
                    resolved_ip = str(ipaddress.IPv4Address(num))
                    findings.append(
                        Finding(
                            rule_id="OBFUSCATED_IP_HOST",
                            severity="high",
                            score=55,
                            title="Obfuscated DWORD integer IP address",
                            message=(
                                f"The hostname '{host}' is an integer (DWORD) encoding representing IPv4 address {resolved_ip}. "
                                f"This technique is heavily used in malicious links to conceal destinations from security filters."
                            ),
                            evidence=f"{host} -> {resolved_ip}"
                        )
                    )
                    return findings, "obfuscated_ip"
            except Exception:
                pass

        # Hexadecimal IP representation (e.g. 0x7f.0x0.0x0.0x1 or 0x7f000001)
        if re.match(r"^0x[0-9a-fA-F]+(\.0x[0-9a-fA-F]+)*$", host) or (host.startswith("0x") and len(host) <= 10):
            findings.append(
                Finding(
                    rule_id="OBFUSCATED_IP_HOST",
                    severity="high",
                    score=55,
                    title="Obfuscated Hexadecimal IP address",
                    message=(
                        f"The hostname '{host}' uses hexadecimal formatting to disguise an IP address destination. "
                        f"This is a common filter-evasion technique."
                    ),
                    evidence=f"Hex host: {host}"
                )
            )
            return findings, "obfuscated_ip"

        return findings, None
