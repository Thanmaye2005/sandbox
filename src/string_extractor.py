"""String Extractor Module
Extracts ASCII and Unicode (UTF-16 LE) strings from binary files and scans
for suspicious artifacts such as registry paths, anti-analysis tools, and driver names.
"""

import re
from typing import Dict, List, Set, Any


class StringExtractor:
    """Extracts strings and identifies suspicious patterns."""

    def __init__(self, data: bytes, min_len: int = 4):
        self.data = data
        self.min_len = min_len

        # Regex patterns for string extraction
        self.ascii_pattern = re.compile(rf"[\x20-\x7e]{{{self.min_len},}}".encode("ascii"))
        self.unicode_pattern = re.compile(rf"(?:[\x20-\x7e]\x00){{{self.min_len},}}".encode("ascii"))

        # Precompiled patterns for heuristic scanning
        self.ip_pattern = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
        self.url_pattern = re.compile(r"https?://[a-zA-Z0-9_\-\./:]+")
        self.reg_pattern = re.compile(r"(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|SOFTWARE\\|SYSTEM\\CurrentControlSet|HARDWARE\\DEVICEMAP)[a-zA-Z0-9_\\]+", re.IGNORECASE)
        self.driver_pattern = re.compile(r"[a-zA-Z0-9_\-\.]+\.(?:sys|vxd|drv)", re.IGNORECASE)

    def extract_raw_strings(self) -> List[str]:
        """Extract both ASCII and UTF-16LE strings."""
        extracted: List[str] = []

        # ASCII
        for match in self.ascii_pattern.finditer(self.data):
            try:
                extracted.append(match.group().decode("ascii", errors="ignore"))
            except Exception:
                pass

        # Unicode (UTF-16LE)
        for match in self.unicode_pattern.finditer(self.data):
            try:
                extracted.append(match.group().decode("utf-16le", errors="ignore"))
            except Exception:
                pass

        return extracted

    def analyze_strings(self) -> Dict[str, Any]:
        """Extract strings and categorize heuristic indicators."""
        raw_strings = self.extract_raw_strings()
        unique_strings: Set[str] = set(raw_strings)

        ips: Set[str] = set()
        urls: Set[str] = set()
        registry_keys: Set[str] = set()
        drivers: Set[str] = set()

        for s in unique_strings:
            # IPs
            for match in self.ip_pattern.findall(s):
                ips.add(match)
            # URLs
            for match in self.url_pattern.findall(s):
                urls.add(match)
            # Registry
            for match in self.reg_pattern.findall(s):
                registry_keys.add(match)
            # Drivers
            for match in self.driver_pattern.findall(s):
                drivers.add(match)

        return {
            "total_strings_count": len(raw_strings),
            "unique_strings_count": len(unique_strings),
            "all_unique_strings": list(unique_strings),
            "extracted_ips": sorted(list(ips)),
            "extracted_urls": sorted(list(urls)),
            "extracted_registry_keys": sorted(list(registry_keys)),
            "extracted_drivers": sorted(list(drivers)),
        }
