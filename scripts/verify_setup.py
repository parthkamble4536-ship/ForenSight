"""
ForenSight Pre-flight Environment Readiness Audit Script.

Validates that all runtime dependencies, filesystem permissions, cryptographic
libraries, and SQLite database settings are functioning properly across both
Windows and Kali Linux.
"""

import sys
from pathlib import Path

REQUIRED_MODULES = [
    ("fastapi", "FastAPI web framework"),
    ("uvicorn", "ASGI web server"),
    ("jinja2", "Jinja2 HTML templating"),
    ("pydantic", "Pydantic data validation"),
    ("pydantic_settings", "Pydantic Settings"),
    ("sqlalchemy", "SQLAlchemy 2.0 ORM"),
    ("pefile", "Windows PE static analyzer"),
    ("pypdf", "PDF structural analyzer"),
    ("docx", "Office OpenXML analyzer (python-docx)"),
    ("puremagic", "Pure-Python magic byte identifier"),
    ("PIL", "Pillow image/EXIF parser"),
    ("reportlab", "ReportLab PDF report generator"),
    ("cryptography", "Ed25519 asymmetric cryptography"),
    ("pytest", "Pytest automated test runner"),
]


def run_audit() -> bool:
    base_dir = Path(__file__).resolve().parent.parent
    if str(base_dir) not in sys.path:
        sys.path.insert(0, str(base_dir))

    print("=" * 66)
    print(" ForenSight: System Environment & Runtime Readiness Audit")
    print("=" * 66)

    # 1. Python version check
    py_ver = sys.version_info
    print(f"[*] Python Runtime: {py_ver.major}.{py_ver.minor}.{py_ver.micro} ({sys.platform})")
    if py_ver < (3, 10):
        print("[-] FAIL: Python 3.10 or higher is required.")
        return False
    print("[+] PASS: Python version is compatible.")

    # 2. Required packages audit
    print("\n[*] Auditing required Python modules:")
    all_modules_present = True
    for mod_name, description in REQUIRED_MODULES:
        try:
            __import__(mod_name)
            print(f"  [+] {mod_name:<18} -> Available ({description})")
        except ImportError:
            print(f"  [-] {mod_name:<18} -> MISSING ({description})")
            all_modules_present = False

    if not all_modules_present:
        print("\n[-] FAIL: One or more required packages are missing. Run: pip install -r requirements.txt")
        return False

    # 3. Directory layout and permissions
    print("\n[*] Validating storage directory structure and permissions:")
    base_dir = Path(__file__).resolve().parent.parent
    data_dir = base_dir / "data"
    subdirs = ["evidence", "keys", "reports", "samples"]
    for sub in subdirs:
        p = data_dir / sub
        p.mkdir(parents=True, exist_ok=True)
        test_file = p / ".audit_perm_test.tmp"
        try:
            test_file.write_text("ok")
            test_file.unlink()
            print(f"  [+] data/{sub:<12} -> Verified writable")
        except Exception as err:
            print(f"  [-] data/{sub:<12} -> Write permission error: {err}")
            return False

    # 4. Cryptographic Ed25519 keypair audit
    print("\n[*] Testing Ed25519 asymmetric keypair engine:")
    try:
        from forensight.crypto.keys import key_manager
        from forensight.crypto.signing import sign_payload, verify_payload_signature

        priv, pub = key_manager.load_or_create_keypair()
        test_payload = b"ForenSight Cryptographic Verification Probe"
        sig = sign_payload(test_payload, priv)
        assert verify_payload_signature(test_payload, sig, pub) is True
        print(f"  [+] Key Fingerprint: {key_manager.get_public_key_fingerprint(pub)}")
        print("  [+] PASS: Ed25519 signing and verification validated.")
    except Exception as err:
        print(f"  [-] FAIL: Cryptographic audit error: {err}")
        return False

    # 5. Database & SQLite WAL Mode audit
    print("\n[*] Testing SQLite database and WAL mode:")
    try:
        from sqlalchemy import text
        from forensight.database.session import SessionLocal, init_db

        init_db()
        with SessionLocal() as session:
            result = session.execute(text("PRAGMA journal_mode;")).scalar()
            print(f"  [+] SQLite Journal Mode: {str(result).upper()}")
        print("  [+] PASS: Database initialized successfully.")
    except Exception as err:
        print(f"  [-] FAIL: Database audit error: {err}")
        return False

    # 6. Synthetic evidence battery check
    print("\n[*] Inspecting synthetic demonstration sample battery:")
    samples_dir = data_dir / "samples"
    sample_files = list(samples_dir.glob("sample_*.*"))
    print(f"  [+] Found {len(sample_files)} demonstration specimens in data/samples/")

    print("\n" + "=" * 66)
    print(" [✓] AUDIT SUCCESSFUL: ForenSight is fully operational and ready!")
    print("=" * 66)
    return True


if __name__ == "__main__":
    success = run_audit()
    sys.exit(0 if success else 1)
