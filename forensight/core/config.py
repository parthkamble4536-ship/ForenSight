"""
Global application configuration and settings management for ForenSight.
"""

from pathlib import Path
from typing import Optional, Set
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings populated from environment variables with forensic-safe defaults."""

    # Application metadata
    app_name: str = "ForenSight"
    version: str = "0.2.0"
    debug: bool = False

    # Server configuration — strictly local-first by default (127.0.0.1)
    host: str = "127.0.0.1"
    port: int = 8000

    # Base workspace directory (resolved dynamically to repo root)
    base_dir: Path = Path(__file__).resolve().parent.parent.parent

    # Storage paths (isolated from public static web assets)
    data_dir: Path = Path(__file__).resolve().parent.parent.parent / "data"
    evidence_dir: Path = Path(__file__).resolve().parent.parent.parent / "data" / "evidence"
    reports_dir: Path = Path(__file__).resolve().parent.parent.parent / "data" / "reports"
    keys_dir: Path = Path(__file__).resolve().parent.parent.parent / "data" / "keys"

    # SQLite Database configuration with WAL mode
    database_url: str = f"sqlite:///{Path(__file__).resolve().parent.parent.parent / 'data' / 'forensight.db'}"

    # Ingestion & file constraints (DoS & Resource Exhaustion Defense)
    max_upload_size_bytes: int = 25 * 1024 * 1024  # 25 MB max upload default
    chunk_size_bytes: int = 64 * 1024  # 64 KB streaming buffer

    # Archive & nested inspection safety boundaries (Zip-bomb & Recursion defense)
    archive_max_recursion_depth: int = 2
    archive_max_expanded_size_bytes: int = 100 * 1024 * 1024  # 100 MB max total expansion
    archive_max_entries: int = 500
    archive_max_compression_ratio: float = 100.0  # Max uncompressed / compressed ratio

    # String extraction constraints
    max_string_extract: int = 5000
    min_string_len: int = 4
    max_string_len: int = 256
    max_text_lines: int = 50000

    # External Threat Intelligence — STRICTLY DISABLED BY DEFAULT
    enable_external_intel: bool = False

    # Digital Signature & Chain of Custody
    ed25519_private_key_path: Optional[Path] = None
    ed25519_public_key_path: Optional[Path] = None

    # Supported file extensions for triage
    supported_extensions: Set[str] = {
        ".exe",
        ".dll",
        ".sys",
        ".pdf",
        ".docx",
        ".docm",
        ".eml",
        ".msg",
        ".zip",
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".txt",
        ".log",
        ".csv",
        ".json",
        ".xml",
        ".bin",
    }

    model_config = SettingsConfigDict(
        env_prefix="FORENSIGHT_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    def ensure_directories(self) -> None:
        """Create necessary data, evidence, report, and key storage directories if absent."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.keys_dir.mkdir(parents=True, exist_ok=True)


# Singleton application settings
settings = Settings()
settings.ensure_directories()
