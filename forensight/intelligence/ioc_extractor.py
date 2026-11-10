"""
Advanced Indicators of Compromise (IOC) extraction and normalization engine.

Extracts, validates, deduplicates, and defangs network and host-based indicators
from raw text or strings without making network connections.
"""

import ipaddress
import re
from typing import Dict, List, Optional, Set, Tuple

from forensight.core.security import defang_ioc
from forensight.core.types import ConfidenceLevel, IOCRecord, IOCType


class IOCExtractor:
    """
    Regex-based forensic IOC extractor with strict validation, deduplication, and defanging.
    """

    COMMON_TLDS = {
        "com", "net", "org", "io", "co", "gov", "mil", "edu", "info", "biz",
        "xyz", "top", "online", "site", "ru", "cn", "ir", "cc", "me", "pw", "tk", "uk", "de", "nl"
    }

    FILE_EXTENSIONS_TO_IGNORE = {
        "exe", "dll", "sys", "pdf", "docx", "docm", "xlsx", "pptx", "zip",
        "txt", "log", "xml", "json", "png", "jpg", "jpeg", "gif", "bin", "c", "h", "py", "sh"
    }

    # Regex definitions
    URL_PATTERN = re.compile(r"https?://[a-zA-Z0-9\-\._~:/\?#\[\]@!\$&'\(\)\*\+,;=%]+", re.IGNORECASE)
    EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
    IPV4_PATTERN = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
    DOMAIN_PATTERN = re.compile(r"\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+([a-zA-Z]{2,})\b")
    REGISTRY_PATTERN = re.compile(r"\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU|HKCR|HKU|HKCC)\\[A-Za-z0-9_.\-\\]+\b", re.IGNORECASE)
    WIN_PATH_PATTERN = re.compile(r"\b(?:[A-Za-z]:\\|%[A-Za-z]+%\\)[A-Za-z0-9_.\-\\]+\b")
    UNIX_PATH_PATTERN = re.compile(r"/(?:etc|tmp|var|usr|bin|sbin|dev|home|opt)/[A-Za-z0-9_.\-/]+")
    HASH_SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")
    HASH_SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
    HASH_MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")

    def _is_valid_ipv4(self, candidate: str) -> bool:
        """Validate candidate IPv4 string, excluding loopback, 0.0.0.0, and broadcasts."""
        try:
            ip = ipaddress.IPv4Address(candidate)
            # Filter out non-routable / loopback noise
            if ip.is_loopback or ip.is_unspecified or candidate in ("255.255.255.255", "0.0.0.0"):
                return False
            return True
        except ValueError:
            return False

    def extract_iocs(self, text: str, context_label: str = "Extracted String") -> List[IOCRecord]:
        """
        Extract all valid, normalized, defanged, and deduplicated IOCs from input text.
        """
        if not text:
            return []

        # Deduplication map: (ioc_type, raw_value) -> IOCRecord
        iocs: Dict[Tuple[IOCType, str], IOCRecord] = {}

        # 1. URLs
        for match in self.URL_PATTERN.finditer(text):
            raw_url = match.group(0).rstrip(".,;)>'\"")
            key = (IOCType.URL, raw_url)
            if key not in iocs:
                iocs[key] = IOCRecord(
                    ioc_type=IOCType.URL,
                    value=raw_url,
                    defanged_value=defang_ioc(raw_url),
                    context=context_label,
                    offset=match.start(),
                    confidence=ConfidenceLevel.CONFIRMED,
                    occurrences=1,
                )
            else:
                iocs[key].occurrences += 1

        # 2. Email Addresses
        for match in self.EMAIL_PATTERN.finditer(text):
            raw_email = match.group(0)
            key = (IOCType.EMAIL, raw_email)
            if key not in iocs:
                iocs[key] = IOCRecord(
                    ioc_type=IOCType.EMAIL,
                    value=raw_email,
                    defanged_value=raw_email.replace("@", "[at]").replace(".", "[.]"),
                    context=context_label,
                    offset=match.start(),
                    confidence=ConfidenceLevel.CONFIRMED,
                    occurrences=1,
                )
            else:
                iocs[key].occurrences += 1

        # 3. IPv4 Addresses
        for match in self.IPV4_PATTERN.finditer(text):
            raw_ip = match.group(0)
            if self._is_valid_ipv4(raw_ip):
                key = (IOCType.IPV4, raw_ip)
                if key not in iocs:
                    iocs[key] = IOCRecord(
                        ioc_type=IOCType.IPV4,
                        value=raw_ip,
                        defanged_value=defang_ioc(raw_ip),
                        context=context_label,
                        offset=match.start(),
                        confidence=ConfidenceLevel.CONFIRMED,
                        occurrences=1,
                    )
                else:
                    iocs[key].occurrences += 1

        # 4. Domain Names (excluding file extensions and already captured URLs)
        for match in self.DOMAIN_PATTERN.finditer(text):
            raw_domain = match.group(0).lower().rstrip(".,;)>'\"")
            tld = raw_domain.split(".")[-1]
            if tld in self.COMMON_TLDS and tld not in self.FILE_EXTENSIONS_TO_IGNORE:
                # Avoid re-adding if domain is part of an already extracted URL or email
                if not any(raw_domain in key[1] for key in iocs if key[0] in (IOCType.URL, IOCType.EMAIL)):
                    key = (IOCType.DOMAIN, raw_domain)
                    if key not in iocs:
                        iocs[key] = IOCRecord(
                            ioc_type=IOCType.DOMAIN,
                            value=raw_domain,
                            defanged_value=defang_ioc(raw_domain),
                            context=context_label,
                            offset=match.start(),
                            confidence=ConfidenceLevel.HIGH,
                            occurrences=1,
                        )
                    else:
                        iocs[key].occurrences += 1

        # 5. Registry Keys
        for match in self.REGISTRY_PATTERN.finditer(text):
            raw_reg = match.group(0).rstrip("\\")
            key = (IOCType.REGISTRY_KEY, raw_reg)
            if key not in iocs:
                iocs[key] = IOCRecord(
                    ioc_type=IOCType.REGISTRY_KEY,
                    value=raw_reg,
                    defanged_value=raw_reg,  # Registry keys don't require defanging
                    context=context_label,
                    offset=match.start(),
                    confidence=ConfidenceLevel.CONFIRMED,
                    occurrences=1,
                )
            else:
                iocs[key].occurrences += 1

        # 6. Windows & Unix File Paths
        for pattern in (self.WIN_PATH_PATTERN, self.UNIX_PATH_PATTERN):
            for match in pattern.finditer(text):
                raw_path = match.group(0).rstrip(",;)>'\"")
                if len(raw_path) > 4:
                    key = (IOCType.FILE_PATH, raw_path)
                    if key not in iocs:
                        iocs[key] = IOCRecord(
                            ioc_type=IOCType.FILE_PATH,
                            value=raw_path,
                            defanged_value=raw_path,
                            context=context_label,
                            offset=match.start(),
                            confidence=ConfidenceLevel.HIGH,
                            occurrences=1,
                        )
                    else:
                        iocs[key].occurrences += 1

        # 7. Hashes (SHA-256, SHA-1, MD5)
        for match in self.HASH_SHA256_PATTERN.finditer(text):
            val = match.group(0).lower()
            key = (IOCType.HASH_SHA256, val)
            if key not in iocs:
                iocs[key] = IOCRecord(
                    ioc_type=IOCType.HASH_SHA256,
                    value=val,
                    defanged_value=val,
                    context=context_label,
                    offset=match.start(),
                    confidence=ConfidenceLevel.CONFIRMED,
                    occurrences=1,
                )
            else:
                iocs[key].occurrences += 1

        for match in self.HASH_MD5_PATTERN.finditer(text):
            val = match.group(0).lower()
            # Avoid matching substring of SHA-256
            if not any(val in k[1] for k in iocs if k[0] == IOCType.HASH_SHA256):
                key = (IOCType.HASH_MD5, val)
                if key not in iocs:
                    iocs[key] = IOCRecord(
                        ioc_type=IOCType.HASH_MD5,
                        value=val,
                        defanged_value=val,
                        context=context_label,
                        offset=match.start(),
                        confidence=ConfidenceLevel.MEDIUM,
                        occurrences=1,
                    )
                else:
                    iocs[key].occurrences += 1

        return list(iocs.values())


# Global IOC extractor instance
ioc_extractor = IOCExtractor()

