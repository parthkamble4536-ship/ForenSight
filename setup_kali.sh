#!/usr/bin/env bash
# ==============================================================================
# ForenSight — Kali Linux Automated Setup & Verification Script
# ==============================================================================
set -euo pipefail

echo "=================================================================="
echo " ForenSight: Advanced Digital Forensics & Static Analysis Platform"
echo " Initializing Native Kali Linux Runtime & Testing Environment"
echo "=================================================================="

# 1. Verify Python 3
if ! command -v python3 &> /dev/null; then
    echo "[-] Error: python3 is not installed or not in PATH."
    exit 1
fi

PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "[+] Detected Python version: ${PY_VERSION}"

# 2. Virtual Environment Setup
VENV_DIR="venv"
if [ ! -d "${VENV_DIR}" ]; then
    echo "[*] Creating isolated Python virtual environment in ./${VENV_DIR}..."
    python3 -m venv "${VENV_DIR}"
fi

echo "[*] Activating virtual environment..."
source "${VENV_DIR}/bin/activate"

# 3. Upgrade Pip and Install Dependencies
echo "[*] Installing ForenSight production and testing dependencies..."
pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet
pip install -r requirements-dev.txt --quiet

# 4. Generate Synthetic Sample Battery (if not present)
if [ ! -f "data/samples/sample_clean.exe" ]; then
    echo "[*] Generating synthetic demonstration evidence specimens..."
    python3 scripts/generate_samples.py
fi

# 5. Run Environment Audit & Automated Test Suite
echo "[*] Running environment readiness audit..."
python3 scripts/verify_setup.py

echo "[*] Executing automated test suite..."
python3 -m pytest tests/ -v

echo "=================================================================="
echo " [✓] Environment verification completed successfully!"
echo " Starting ForenSight web server bound to http://127.0.0.1:8000"
echo " (Press Ctrl+C to terminate)"
echo "=================================================================="

uvicorn forensight.main:app --host 127.0.0.1 --port 8000

