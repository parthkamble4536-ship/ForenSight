"""
Unit tests for IOC extraction, normalization, deduplication, and defanging.
"""

import pytest

from forensight.core.types import IOCType
from forensight.intelligence.ioc_extractor import IOCExtractor


class TestIOCExtractor:
    """Tests for regex-based indicator extraction and defanging."""

    def test_extract_and_defang_urls(self) -> None:
        """Verify URLs are extracted, normalized, and defanged."""
        text = "Contact C2 server at http://bad-actor.xyz/beacon.php and https://stage2.net/payload"
        extractor = IOCExtractor()
        iocs = extractor.extract_iocs(text)

        urls = [ioc for ioc in iocs if ioc.ioc_type == IOCType.URL]
        assert len(urls) == 2

        raw_urls = {u.value for u in urls}
        assert "http://bad-actor.xyz/beacon.php" in raw_urls
        assert "https://stage2.net/payload" in raw_urls

        defanged = {u.defanged_value for u in urls}
        assert any("hxxp://bad-actor[.]xyz/beacon[.]php" in d for d in defanged)
        assert any("hxxps://stage2[.]net/payload" in d for d in defanged)

    def test_extract_ipv4_and_filter_noise(self) -> None:
        """Verify valid routable IPv4 addresses are captured while loopback is filtered."""
        text = "Attacker IP: 198.51.100.45, Loopback: 127.0.0.1, Gateway: 10.0.0.1"
        extractor = IOCExtractor()
        iocs = extractor.extract_iocs(text)

        ips = [ioc.value for ioc in iocs if ioc.ioc_type == IOCType.IPV4]
        assert "198.51.100.45" in ips
        assert "10.0.0.1" in ips
        # 127.0.0.1 must be filtered out
        assert "127.0.0.1" not in ips

    def test_extract_domain_and_ignore_file_extensions(self) -> None:
        """Verify domains with real TLDs are extracted, but filenames like sample.exe are ignored."""
        text = "Downloaded malware sample.exe and data.pdf from beacon.threat-actor.org"
        extractor = IOCExtractor()
        iocs = extractor.extract_iocs(text)

        domains = [ioc.value for ioc in iocs if ioc.ioc_type == IOCType.DOMAIN]
        assert "beacon.threat-actor.org" in domains
        assert "sample.exe" not in domains
        assert "data.pdf" not in domains

    def test_extract_registry_keys(self) -> None:
        """Verify Windows Registry paths are identified."""
        text = "Persistence key created at HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"
        extractor = IOCExtractor()
        iocs = extractor.extract_iocs(text)

        reg_keys = [ioc.value for ioc in iocs if ioc.ioc_type == IOCType.REGISTRY_KEY]
        assert len(reg_keys) == 1
        assert "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater" in reg_keys[0]

    def test_extract_hashes(self) -> None:
        """Verify SHA-256 and MD5 hashes are extracted."""
        sha256_val = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
        md5_val = "9e107d9d372bb6826bd81d3542a419d6"
        text = f"Sample hashes: SHA256={sha256_val} MD5={md5_val}"

        extractor = IOCExtractor()
        iocs = extractor.extract_iocs(text)

        sha_iocs = [ioc.value for ioc in iocs if ioc.ioc_type == IOCType.HASH_SHA256]
        md5_iocs = [ioc.value for ioc in iocs if ioc.ioc_type == IOCType.HASH_MD5]

        assert sha256_val in sha_iocs
        assert md5_val in md5_iocs

