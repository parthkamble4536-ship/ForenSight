<div align="center">

<img src="https://img.shields.io/badge/ForenSight-DFIR%20v2-00f5d4?style=for-the-badge&logo=shield&logoColor=white"/>

# 🔬 ForenSight
### Advanced Digital Forensics & Evidence Intelligence Platform

[![CI](https://github.com/parthkamble4536-ship/ForenSight/actions/workflows/ci.yml/badge.svg)](https://github.com/parthkamble4536-ship/ForenSight/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.13-3776AB?style=flat&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat&logo=docker&logoColor=white)](Dockerfile)
[![Tests](https://img.shields.io/badge/Tests-100%20Passed-success?style=flat&logo=pytest&logoColor=white)](tests/)
[![Security](https://img.shields.io/badge/Bandit-0%20High%20Severity-brightgreen?style=flat&logo=security&logoColor=white)](#security)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat)](LICENSE)
[![Binding](https://img.shields.io/badge/Binding-127.0.0.1%20Local--First-critical?style=flat)](#security)

<br/>

> **A high-assurance, air-gapped, local-first forensic workbench** for incident responders, DFIR analysts, students, and security engineers — no cloud, no execution, no leakage.

<br/>

**[🚀 Quick Start](#-quick-start) · [🖥️ Screenshots](#-screenshots) · [🏗️ Architecture](#-architecture) · [🔬 Analyzers](#-forensic-analyzers) · [🔐 Security](#-security-model) · [🐳 Docker](#-docker) · [🧪 Tests](#-testing)**

</div>

---

## ✨ What is ForenSight?

**ForenSight** is a production-grade, **static-only** digital forensics platform built for SOC analysts, malware researchers, forensic examiners, and cybersecurity students.

It allows you to:
- **Upload** any suspect file — PE executables, PDFs, Office documents, emails, archives, images, logs.
- **Identify** real file type via binary magic bytes, catching masquerading attacks.
- **Analyze** deeply using 7 format-specific forensic analyzers with MITRE ATT&CK mapping.
- **Score** threat level 0–100 with fully explainable, deterministic risk rules.
- **Extract** defanged IOCs (IPs, URLs, hashes, registry keys, paths).
- **Track** every action via a tamper-evident SHA-256 hash-chained Chain of Custody ledger.
- **Verify** integrity with Ed25519 digital signatures at any time.
- **Export** signed forensic reports in HTML, JSON, PDF, CSV (findings), and STIX 2.1 (threat intel).

> **🔒 Zero-Execution Guarantee**: ForenSight never executes, loads, or evaluates uploaded evidence. No `subprocess`, no `eval`, no shell — verified by automated AST scanning in every CI run.

---

## 🖥️ Screenshots

### 1. Evidence Triage Workbench — Explainable Risk Verdict
![Triage Workbench](Screenshots/1.png)

### 2. Cryptographic Vault & Ed25519 Signed Manifest
![Crypto Vault](Screenshots/2.png)

### 3. Detections & MITRE ATT&CK Mapping
![MITRE Detections](Screenshots/3.png)

### 4. Forensic Timeline — UTC Normalized Events
![Forensic Timeline](Screenshots/4.png)

### 5. Chain of Custody — SHA-256 Hash-Chained Ledger
![Chain of Custody](Screenshots/5.png)

### 6. Standalone Forensic Report (HTML Export)
![Forensic Report](Screenshots/6.png)

### 7. EML Evidence Verification — Integrity Pass
![Verification](Screenshots/8.png)

---

## 🏗️ Architecture

### System Overview

```mermaid
flowchart TD
    subgraph INPUT["📁 INPUT LAYER"]
        A["🌐 Browser Upload\nDrag & Drop / API"]
    end

    subgraph INGESTION["⚙️ INGESTION PIPELINE"]
        B["🔢 Streaming Multi-Hasher\nSHA-256 · SHA-1 · MD5\n64 KB chunks"]
        C["🏦 UUID Evidence Vault\ndata/evidence/<uuid>.bin\nRead-Only Isolation"]
        D["🔍 File Identification\nMagic Bytes + Masquerade\nDetection + Entropy"]
        E["✍️ Ed25519 Signing\nAcquisition Manifest"]
    end

    subgraph ANALYZERS["🔬 FORENSIC ANALYZERS v2.1"]
        H1["🪟 PE Analyzer\nHeaders · Entropy · APIs\nMITRE T1055, T1027"]
        H2["📄 PDF Analyzer\n/JS · /Launch · /URI\nForm & Embedded Files"]
        H3["📝 DOCX Analyzer\nVBA · Remote Template\nMITRE T1221"]
        H4["📧 Email Analyzer\nSPF · DKIM · DMARC\nSpoofing · Attachments"]
        H5["🗜️ Archive Analyzer\nZip Bomb · Zip Slip\nNested Inspection"]
        H6["🖼️ Image Analyzer\nEXIF · GPS · Camera\nTimestamp Anomalies"]
        H7["📃 Text Analyzer\nPowerShell · LOLBins\nRansomware Patterns"]
    end

    subgraph INTELLIGENCE["🧠 INTELLIGENCE ENGINE"]
        I["🎯 IOC Extractor\nIPs · URLs · Hashes\nDefanged Automatically"]
        J["📊 Risk Scorer\n0–100 Explainable\nCategory-Capped"]
        K["🔗 Chain of Custody\nSHA-256 Hash Chain\nTamper Detection"]
    end

    subgraph PERSISTENCE["💾 PERSISTENCE"]
        L[("🗄️ SQLite WAL\nCases · Evidence\nFindings · Timeline")]
    end

    subgraph OUTPUT["📤 OUTPUT LAYER"]
        M["🖥️ SOC Dashboard\nFastAPI + Jinja2\n127.0.0.1 Only"]
        N["📋 HTML Report\nSelf-Contained\nXSS-Safe"]
        O["📑 PDF Report\nReportLab\nSigned"]
        P["🔖 STIX 2.1\nThreat Intel Bundle"]
        Q["📊 CSV Export\nFindings Matrix"]
    end

    A --> B --> C --> D --> E --> K
    D --> H1 & H2 & H3 & H4 & H5 & H6 & H7
    H1 & H2 & H3 & H4 & H5 & H6 & H7 --> I --> J --> L
    K --> L
    L --> M
    L --> N & O & P & Q
```

---

### Security Boundaries

```mermaid
flowchart LR
    subgraph INTERNET["🌍 External World"]
        EX1["❌ No CDN Calls"]
        EX2["❌ No Threat Intel Upload"]
        EX3["❌ No Cloud Storage"]
    end

    subgraph HOST["🖥️ Host Machine (127.0.0.1)"]
        subgraph CONTAINER["🐳 ForenSight Container / Process"]
            WEB["🌐 FastAPI\n127.0.0.1:8000"]
            subgraph VAULT["🔐 Evidence Vault (data/)"]
                EV["📦 UUID.bin Files\nRead-Only 0o444"]
                DB[("🗄️ SQLite WAL")]
                KEYS["🔑 Ed25519 Keys\n.gitignored"]
            end
            ANALYZERS2["🔬 Static Analyzers\nNEVER executes payloads"]
        end
        BROWSER["🌐 Analyst Browser"]
    end

    INTERNET -. "BLOCKED by design" .-> HOST
    BROWSER <--> WEB
    WEB --> ANALYZERS2
    ANALYZERS2 --> VAULT
    WEB --> VAULT
```

---

### Database Entity Relationship

```mermaid
erDiagram
    CASES {
        string case_id PK
        string title
        string status
        string investigator
        string investigator_notes
        string tags_json
        datetime closed_at
    }
    EVIDENCE_ITEMS {
        string evidence_id PK
        string case_id FK
        string original_filename
        string sha256
        string sha1
        string md5
        int file_size_bytes
        float entropy
        string manifest_signature
        string last_verification_status
    }
    ANALYSIS_RUNS {
        string run_id PK
        string evidence_id FK
        int risk_score
        string verdict
        datetime analyzed_at
    }
    FINDINGS {
        string finding_id PK
        string run_id FK
        string rule_id
        string severity
        string analyzer_name
        string mitre_technique
        string review_status
        bool is_false_positive
    }
    IOCS {
        string ioc_id PK
        string run_id FK
        string ioc_type
        string defanged_value
        int offset
    }
    CUSTODY_EVENTS {
        string event_id PK
        string evidence_id
        string event_type
        string previous_event_hash
        string event_hash
        int sequence_index
    }
    TIMELINE_EVENTS {
        string event_id PK
        string evidence_id FK
        string timestamp_type
        string confidence
        string source
    }
    CASE_ACTIVITIES {
        string activity_id PK
        string case_id FK
        string action
        string actor
    }

    CASES ||--o{ EVIDENCE_ITEMS : "contains"
    CASES ||--o{ CASE_ACTIVITIES : "logs"
    EVIDENCE_ITEMS ||--o{ ANALYSIS_RUNS : "analyzed by"
    ANALYSIS_RUNS ||--o{ FINDINGS : "produces"
    ANALYSIS_RUNS ||--o{ IOCS : "extracts"
    ANALYSIS_RUNS ||--o{ TIMELINE_EVENTS : "generates"
    EVIDENCE_ITEMS ||--o{ CUSTODY_EVENTS : "tracked by"
```

---

### CI/CD Pipeline

```mermaid
flowchart LR
    DEV["👨‍💻 Developer\nPush / PR"]
    -->|"git push"| GH["GitHub\nmaster / main"]

    GH --> TEST["🧪 Test Matrix\nPy 3.11 · 3.12 · 3.13\n100 Tests"]
    GH --> SAST["🔐 Bandit SAST\n0 High Severity"]
    GH --> DOCKER["🐳 Docker Build\n+ Health Check"]

    TEST -->|"✅ PASS"| MERGE["✅ PR Ready\nto Merge"]
    SAST -->|"✅ PASS"| MERGE
    DOCKER -->|"✅ PASS"| MERGE

    TEST -->|"❌ FAIL"| BLOCK["🚫 Blocked"]
    SAST -->|"❌ FAIL"| BLOCK
    DOCKER -->|"❌ FAIL"| BLOCK
```

---

## 🔬 Forensic Analyzers

| Analyzer | File Types | Key Detections | MITRE ATT&CK |
|:---|:---|:---|:---|
| **PE Analyzer v2.1** | `.exe`, `.dll`, `.sys` | PE32/PE32+ headers, compile timestamp, section entropy, RWX sections, IAT suspicious APIs, exports, PDB paths, overlay | T1027 (Obfuscation), T1055 (Process Injection), T1056 (Keylogging) |
| **PDF Analyzer v2.1** | `.pdf` | `/JavaScript`, `/Launch`, `/OpenAction`, `/EmbeddedFiles`, `/AcroForm`, `/URI` IOCs | T1566 (Phishing), T1204 (User Execution) |
| **Office Analyzer v2.1** | `.docx`, `.docm` | VBA macro storage, OLE objects, External Template Injection (`.dotm`), bounded XML parsing | T1221 (Template Injection), T1137 (Office Application Startup) |
| **Email Analyzer v2.1** | `.eml` | Header spoofing, SPF/DKIM/DMARC, `Return-Path` anomalies, dangerous attachments | T1566.001 (Spearphishing Attachment), T1598 (Phishing for Info) |
| **Archive Analyzer v2.1** | `.zip` | Zip Slip traversal, zip bombs (ratio/size/entries), nested inspection, double extensions | T1027 (Obfuscation), T1074 (Data Staged) |
| **Image Analyzer v2.1** | `.jpg`, `.png`, `.gif` | EXIF metadata, GPS coordinates, camera fingerprinting, editing software (Photoshop/GIMP) | T1646 (Exfiltration over C2) |
| **Text/Log Analyzer v2.1** | `.txt`, `.log`, `.csv`, `.xml` | PowerShell encoding, `IEX`/`iex`, `vssadmin`, `certutil`, `mimikatz`, LOLBins | T1059 (Command Interpreter), T1490 (Shadow Copy Deletion) |

---

## 🧪 Testing

The project maintains **100 automated test cases** across 25 test suites:

```bash
python -m pytest tests/ -v
```

| Test Module | Coverage Area |
|:---|:---|
| `test_phase1_fixes.py` | SQLite persistence, custody chain, HTML escaping, timeline |
| `test_phase2_analyzers.py` | All 7 analyzers, detection provenance, bounded parsing |
| `test_phase3_intelligence.py` | Verification Center, Findings, Timeline, Case Workflow |
| `test_phase4_5_validation.py` | Adversarial inputs, Zip Slip, bombs, AST security guard |
| `test_pe_analyzer.py` | PE header parsing, entropy, IAT analysis |
| `test_pdf_analyzer.py` | PDF action detection, encryption |
| `test_email_analyzer.py` | Spoofing detection, header anomalies |
| `test_crypto.py` | Ed25519 key generation, signing, verification |
| `test_custody_ledger.py` | Chain integrity, tamper detection |
| `test_storage_security.py` | Zip Slip defense, path traversal |
| *(+ 15 more modules)* | Hashing, strings, IOC extraction, scoring, database, API |

---

## 🔐 Security Model

| Guardrail | Implementation |
|:---|:---|
| **Zero Execution** | AST-verified: `0` calls to `subprocess`, `os.system`, `eval`, or `exec` |
| **Localhost Only** | Binds to `127.0.0.1:8000` by default — not accessible from network |
| **XSS Prevention** | All report output HTML-escaped with `html.escape(quote=True)` |
| **Zip Bomb Defense** | 100 MB expansion cap, 100.0x ratio limit, 500 entry ceiling, depth 2 |
| **Path Traversal** | Zip Slip guard on archive members; `sanitize_filename()` on all uploads |
| **XXE Prevention** | XML member reads capped at 2 MB with DTD/ENTITY tag screening |
| **Evidence Isolation** | UUID4-named `.bin` files outside web-served routes, read-only permissions |
| **Chain of Custody** | SHA-256 hash chain with `sequence_index`; refuses tampered DB append |
| **Cryptographic Signing** | Ed25519 manifest signed at acquisition; verifiable at any time |
| **External Intel Disabled** | `FORENSIGHT_ENABLE_EXTERNAL_INTEL=false` by default |

---

## 🚀 Quick Start

### Option A — Windows (Python 3.13)

```powershell
# 1. Clone the repository
git clone https://github.com/parthkamble4536-ship/ForenSight.git
cd ForenSight

# 2. Create and activate virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# 4. Generate synthetic test specimens
python scripts/generate_samples.py

# 5. Run the full test suite (100 tests should pass)
python -m pytest tests/ -v

# 6. Launch ForenSight
python -m uvicorn forensight.main:app --host 127.0.0.1 --port 8000 --reload
```

Open **http://127.0.0.1:8000** in your browser.

---

### Option B — Kali Linux / Ubuntu

```bash
# 1. Clone
git clone https://github.com/parthkamble4536-ship/ForenSight.git
cd ForenSight

# 2. Quick automated setup (installs libmagic, creates venv, runs tests)
bash setup_kali.sh

# Or manual:
sudo apt-get install -y libmagic1
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
python scripts/generate_samples.py
python -m pytest tests/ -v
uvicorn forensight.main:app --host 127.0.0.1 --port 8000
```

---

### Option C — Docker (Recommended for Production)

```bash
# 1. Build and launch (all platforms)
docker-compose up -d --build

# 2. Check status and logs
docker-compose ps
docker-compose logs -f

# 3. Stop
docker-compose down
```

> Evidence vault, database, and Ed25519 keys are persisted in a named Docker volume (`forensight_vault_data`) across container restarts.

---

## 🌐 Web Interface

| Page | URL | Purpose |
|:---|:---|:---|
| **Triage Console** | http://127.0.0.1:8000/ | Upload evidence, view queue, live risk scores |
| **Case Dossiers** | http://127.0.0.1:8000/cases | Manage cases, view correlation graph |
| **Findings Center** | http://127.0.0.1:8000/findings | Triage findings, mark false positives |
| **Verification Center** | http://127.0.0.1:8000/verification | Multi-factor cryptographic audit |
| **Timeline Explorer** | http://127.0.0.1:8000/timeline | UTC chronological forensic timeline |
| **API Docs** | http://127.0.0.1:8000/docs | Interactive OpenAPI/Swagger interface |

---

## 📁 Project Structure

```
ForenSight/
├── forensight/
│   ├── core/           # Config, exceptions, Pydantic schemas, security utils
│   ├── ingestion/      # Streaming hasher, file ID, archive safety, pipeline
│   ├── analyzers/      # 7 deep static forensic analyzers (v2.1.0)
│   ├── extraction/     # ASCII & UTF-16LE string extractor, encoding detector
│   ├── intelligence/   # IOC extractor + defanger, 0–100 risk scoring engine
│   ├── evidence/       # Custody ledger, verification, timeline, correlation
│   ├── crypto/         # Ed25519 key management and signing
│   ├── database/       # SQLAlchemy 2.0 ORM models, session, CRUD layer
│   ├── reports/        # HTML, JSON, PDF, CSV, STIX 2.1 export generators
│   ├── api/            # FastAPI REST endpoints (/api/v1)
│   ├── dashboard/      # Jinja2 templates, CSS, JavaScript, routes
│   └── main.py         # FastAPI lifespan application factory
├── tests/              # 100 automated unit, integration & adversarial tests
├── scripts/            # Sample generator, environment verification audit
├── data/               # Evidence vault, reports, keys, SQLite DB (gitignored)
├── .github/workflows/  # GitHub Actions CI pipeline (Test + SAST + Docker)
├── Dockerfile          # Multi-stage hardened Python 3.13 container
├── docker-compose.yml  # Orchestrated deployment with security hardening
├── requirements.txt    # Production dependencies
└── requirements-dev.txt # Dev/test dependencies
```

---

## 🎓 For Students — Getting Started Guide

**New to digital forensics?** Here is how to learn from ForenSight:

1. **Start the server** and upload files from `data/samples/` — these are safe synthetic test specimens.
2. **Read the Findings tab** — every finding explains *why* it was flagged, the MITRE technique, and the confidence level.
3. **Study the Chain of Custody** — see how every action is permanently recorded with cryptographic linking.
4. **Try the Verification Center** — click "Run Full Verification" to see how integrity audits work.
5. **Export a Report** — download the PDF or HTML report and study the full forensic dossier structure.
6. **Mark False Positives** — go to Findings Center and practice analyst disposition (a core DFIR skill).
7. **Read the Code** — start with `forensight/analyzers/pe_analyzer.py` to understand static PE analysis.

**Key Concepts You'll Learn:**
- SHA-256 / Ed25519 cryptographic verification
- Chain of Custody in digital forensics
- MITRE ATT&CK framework mapping
- IOC defanging and safe handling
- Static vs dynamic malware analysis
- Zip bomb and path traversal defenses

---

## 🧰 Supported File Types

`.exe` · `.dll` · `.sys` · `.pdf` · `.docx` · `.docm` · `.eml` · `.zip` · `.jpg` · `.jpeg` · `.png` · `.gif` · `.txt` · `.log` · `.csv` · `.json` · `.xml` · `.bin`

---

## 📦 Dependencies

| Package | Purpose |
|:---|:---|
| `fastapi` | ASGI web framework & REST API |
| `uvicorn` | ASGI server |
| `sqlalchemy` | ORM & SQLite WAL persistence |
| `pydantic` | Data validation & schemas |
| `cryptography` | Ed25519 asymmetric signing |
| `pefile` | Windows PE binary parsing |
| `pypdf` | PDF structure parsing |
| `python-docx` | OpenXML Office document parsing |
| `Pillow` | Image EXIF metadata extraction |
| `puremagic` | Pure-Python file type identification |
| `reportlab` | PDF forensic report generation |
| `jinja2` | HTML template rendering |

---

## ⚙️ Configuration

Copy `.env.example` to `.env` and customize:

```env
FORENSIGHT_HOST=127.0.0.1          # Never change to 0.0.0.0 in production
FORENSIGHT_PORT=8000
FORENSIGHT_DEBUG=false
FORENSIGHT_MAX_UPLOAD_SIZE_BYTES=26214400   # 25 MB
FORENSIGHT_MAX_STRING_EXTRACT=5000
FORENSIGHT_ENABLE_EXTERNAL_INTEL=false      # Keep false — air-gapped by design
```

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

Pull requests are welcome! Please:
1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/my-enhancement`.
3. Run the full test suite: `python -m pytest tests/ -v` — all 100 tests must pass.
4. Run Bandit SAST: `bandit -r forensight/ -ll -q --severity-level high` — zero high findings.
5. Submit a pull request with a clear description of changes.

---

<div align="center">

**Built with ❤️ for the Digital Forensics & Incident Response Community**

*ForenSight — Static Triage Only · Local First · Air-Gapped · Cryptographically Verified*

</div>
