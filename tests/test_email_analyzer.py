"""
Unit tests for the Email forensic static analyzer (EML and MSG).
"""

from pathlib import Path
import pytest

from forensight.analyzers.email_analyzer import EmailAnalyzer
from forensight.core.types import EvidenceMetadata, FindingSeverity, IOCType


class TestEmailAnalyzer:
    """Tests for header parsing, spoof detection, attachment hashing, and link extraction."""

    def test_phishing_email_with_spoof_and_dangerous_attachment(self, tmp_path: Path) -> None:
        """Verify email spoofing, SPF failure, and dangerous attachments trigger correct findings."""
        eml_path = tmp_path / "phish.eml"
        eml_content = (
            b"From: CEO <legit-ceo@trusted-corp.com>\n"
            b"To: Employee <victim@trusted-corp.com>\n"
            b"Reply-To: attacker@burner-mail.net\n"
            b"Subject: Urgent Wire Transfer\n"
            b"Date: Mon, 10 Nov 2026 10:00:00 +0000\n"
            b"Authentication-Results: mx.trusted-corp.com; spf=fail smtp.mailfrom=attacker.com\n"
            b"MIME-Version: 1.0\n"
            b"Content-Type: multipart/mixed; boundary=\"boundary123\"\n\n"
            b"--boundary123\n"
            b"Content-Type: text/plain; charset=utf-8\n\n"
            b"Please review invoice at http://malicious-portal.org/login.php immediately.\n\n"
            b"--boundary123\n"
            b"Content-Type: application/x-dosexec\n"
            b"Content-Disposition: attachment; filename=\"invoice.exe\"\n\n"
            b"MZ_DUMMY_EXECUTABLE_BYTES\n"
            b"--boundary123--\n"
        )
        eml_path.write_bytes(eml_content)

        meta = EvidenceMetadata(
            file_size_bytes=len(eml_content),
            identified_type="EML",
            mime_type="message/rfc822",
            declared_extension=".eml",
            entropy=4.5,
        )

        analyzer = EmailAnalyzer()
        output = analyzer.analyze(eml_path, meta)

        rule_ids = {f.rule_id for f in output.findings}
        assert "EML-SPOOF-001" in rule_ids
        assert "EML-AUTH-001" in rule_ids
        assert "EML-ATT-001" in rule_ids

        # Verify attachment was hashed
        assert len(output.details["attachments"]) == 1
        att = output.details["attachments"][0]
        assert att["filename"] == "invoice.exe"
        assert len(att["sha256"]) == 64

        # Verify body URL was extracted and defanged
        url_iocs = [ioc for ioc in output.iocs if ioc.ioc_type == IOCType.URL]
        assert any("hxxp://malicious-portal[.]org/login[.]php" in ioc.defanged_value for ioc in url_iocs)

        # Verify timeline event created
        assert len(output.timeline_events) == 1
        assert "Urgent Wire Transfer" in output.timeline_events[0].description

