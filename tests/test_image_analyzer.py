"""
Unit tests for the Image forensic static analyzer (EXIF & structural triage).
"""

from pathlib import Path
from PIL import Image
import pytest

from forensight.analyzers.image_analyzer import ImageAnalyzer
from forensight.core.types import EvidenceMetadata


class TestImageAnalyzer:
    """Tests for image format verification, dimension extraction, and EXIF processing."""

    def test_benign_png_analysis(self, tmp_path: Path) -> None:
        """Verify clean synthetic PNG parses dimensions and format correctly."""
        img_path = tmp_path / "test_image.png"
        img = Image.new("RGB", (64, 64), color="blue")
        img.save(img_path, format="PNG")

        meta = EvidenceMetadata(
            file_size_bytes=img_path.stat().st_size,
            identified_type="IMAGE_PNG",
            mime_type="image/png",
            declared_extension=".png",
            entropy=3.5,
        )

        analyzer = ImageAnalyzer()
        output = analyzer.analyze(img_path, meta)

        assert output.details["format"] == "PNG"
        assert output.details["dimensions"] == "64x64"
        assert output.details["mode"] == "RGB"

