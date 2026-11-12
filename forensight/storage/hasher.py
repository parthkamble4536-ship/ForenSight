"""
Cryptographic streaming multi-hasher for ForenSight.

Computes SHA-256, SHA-1, and MD5 hashes concurrently in memory-bounded
streams without loading large artifacts into RAM.
"""

import hashlib
from pathlib import Path
from typing import BinaryIO, Generator

from forensight.core.config import settings
from forensight.core.types import HashResult


class StreamHasher:
    """
    Concurrent multi-algorithm streaming hasher.

    Maintains independent hashlib contexts for SHA-256, SHA-1, and MD5,
    updating each context in-flight as data chunks arrive.
    """

    def __init__(self) -> None:
        self._sha256 = hashlib.sha256()
        self._sha1 = hashlib.sha1(usedforsecurity=False)
        self._md5 = hashlib.md5(usedforsecurity=False)
        self._size_bytes: int = 0
        self._finalized: bool = False
        self._result: HashResult | None = None

    def update(self, chunk: bytes) -> None:
        """Feed a byte chunk to all active hash contexts and increment size counter."""
        if self._finalized:
            raise RuntimeError("Cannot update StreamHasher after finalize() has been called.")
        if not chunk:
            return

        self._sha256.update(chunk)
        self._sha1.update(chunk)
        self._md5.update(chunk)
        self._size_bytes += len(chunk)

    @property
    def bytes_processed(self) -> int:
        """Current number of bytes processed so far."""
        return self._size_bytes

    def finalize(self) -> HashResult:
        """
        Produce hexadecimal digests for all algorithms.

        Returns an immutable HashResult model. Subsequent updates are prohibited.
        """
        if not self._finalized:
            self._result = HashResult(
                sha256=self._sha256.hexdigest().lower(),
                sha1=self._sha1.hexdigest().lower(),
                md5=self._md5.hexdigest().lower(),
                size_bytes=self._size_bytes,
            )
            self._finalized = True
        assert self._result is not None
        return self._result


def compute_hashes_from_stream(
    stream: BinaryIO,
    chunk_size: int = settings.chunk_size_bytes,
) -> HashResult:
    """
    Compute cryptographic hashes from an open binary stream using chunked reads.
    """
    hasher = StreamHasher()
    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        hasher.update(chunk)
    return hasher.finalize()


def compute_hashes_from_file(
    file_path: Path,
    chunk_size: int = settings.chunk_size_bytes,
) -> HashResult:
    """
    Compute cryptographic hashes directly from a file on disk using chunked reads.
    """
    hasher = StreamHasher()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.finalize()


def compute_hashes_from_bytes(data: bytes) -> HashResult:
    """
    Compute cryptographic hashes for an in-memory byte string.
    """
    hasher = StreamHasher()
    hasher.update(data)
    return hasher.finalize()

