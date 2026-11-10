"""
Unit tests for cryptographic streaming multi-hasher.
"""

import io
from pathlib import Path
import pytest

from forensight.storage.hasher import (
    StreamHasher,
    compute_hashes_from_bytes,
    compute_hashes_from_file,
    compute_hashes_from_stream,
)


class TestStreamHasher:
    """Tests for multi-algorithm hashing correctness and streaming behavior."""

    # Standard test vectors
    EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    EMPTY_SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    EMPTY_MD5 = "d41d8cd98f00b204e9800998ecf8427e"

    FOX_STRING = b"The quick brown fox jumps over the lazy dog"
    FOX_SHA256 = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
    FOX_SHA1 = "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
    FOX_MD5 = "9e107d9d372bb6826bd81d3542a419d6"

    def test_empty_input_hashes(self) -> None:
        """Verify hash digests for empty byte sequence match standard RFC values."""
        result = compute_hashes_from_bytes(b"")
        assert result.sha256 == self.EMPTY_SHA256
        assert result.sha1 == self.EMPTY_SHA1
        assert result.md5 == self.EMPTY_MD5
        assert result.size_bytes == 0

    def test_known_vector_hashes(self) -> None:
        """Verify digests for standard 'quick brown fox' test vector."""
        result = compute_hashes_from_bytes(self.FOX_STRING)
        assert result.sha256 == self.FOX_SHA256
        assert result.sha1 == self.FOX_SHA1
        assert result.md5 == self.FOX_MD5
        assert result.size_bytes == len(self.FOX_STRING)

    def test_chunked_streaming_equivalence(self) -> None:
        """Verify feeding small chunks produces identical digests to single buffer."""
        hasher = StreamHasher()
        chunk_size = 5
        for i in range(0, len(self.FOX_STRING), chunk_size):
            hasher.update(self.FOX_STRING[i : i + chunk_size])

        result = hasher.finalize()
        assert result.sha256 == self.FOX_SHA256
        assert result.sha1 == self.FOX_SHA1
        assert result.md5 == self.FOX_MD5
        assert result.size_bytes == len(self.FOX_STRING)

    def test_compute_hashes_from_stream(self) -> None:
        """Verify stream-based hash helper correctly consumes binary stream."""
        stream = io.BytesIO(self.FOX_STRING)
        result = compute_hashes_from_stream(stream, chunk_size=8)
        assert result.sha256 == self.FOX_SHA256
        assert result.sha1 == self.FOX_SHA1
        assert result.md5 == self.FOX_MD5
        assert result.size_bytes == len(self.FOX_STRING)

    def test_compute_hashes_from_file(self, tmp_path: Path) -> None:
        """Verify file-based hash helper matches bytes helper."""
        test_file = tmp_path / "sample.bin"
        test_file.write_bytes(self.FOX_STRING)

        result = compute_hashes_from_file(test_file, chunk_size=8)
        assert result.sha256 == self.FOX_SHA256
        assert result.sha1 == self.FOX_SHA1
        assert result.md5 == self.FOX_MD5
        assert result.size_bytes == len(self.FOX_STRING)

    def test_hasher_immutability_after_finalize(self) -> None:
        """Verify that updating a finalized StreamHasher raises RuntimeError."""
        hasher = StreamHasher()
        hasher.update(b"data")
        hasher.finalize()

        with pytest.raises(RuntimeError, match="Cannot update StreamHasher after finalize"):
            hasher.update(b"more data")

