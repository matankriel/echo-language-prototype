# Echo — CVE Remediation Demo

A focused prototype that shows one core concept: **when a developer requests a vulnerable Python package, Echo detects the CVE, builds a backport-patched wheel on demand, and serves it transparently through a private PEP 503-compatible registry.**

## What the demo shows

Two distinct severity flows using **urllib3** and **requests**:

| Package | CVE | Severity | CVSS | Behaviour |
|---|---|---|---|---|
| `urllib3==1.26.0` | CVE-2021-33503 | **High** | 7.5 | Build **blocked** — error printed, fix suggested |
| `requests==2.28.0` | CVE-2023-32681 | **Medium** | 6.1 | **Warning** printed, patched wheel injected transparently |

Each patched wheel embeds a **CycloneDX 1.4 SBOM** so security scanners can verify the fix.

---

## Architecture

```
client/install.py          # pip wrapper: checks registry → warns/blocks
       │
       ▼
registry/server.py         # FastAPI: PEP 503 simple index + /check endpoint
       │
       ├── GET /check/{package}/{version}   → CVE lookup, upsert request_log
       ├── GET /simple/{package}/           → PEP 503 wheel index w/ CVE metadata
       └── GET /files/{filename}            → serve patched wheel

factory/builder.py         # demand-driven backport builder (30-day filter)
factory/sbom.py            # CycloneDX SBOM generator + wheel injector

db/schema.py               # SQLite schema (cves, version_groups, request_log)
db/seed.py                 # seed 2 CVEs + version groups + demo request_log
```

### Demand-driven build filter

The builder only builds a wheel if a matching package version was requested **within the last 30 days** (tracked in `request_log`). Seeded demo data illustrates both sides:

| Package | Version | Last Requested | Outcome |
|---|---|---|---|
| requests | 2.28.0 | 7 days ago | **BUILD** (within window, in CVE range) |
| requests | 2.26.0 | 50 days ago | **SKIP** (outside 30-day window) |
| urllib3 | 1.26.0 | 15 days ago | **pre-built** (skip) |

---

## Quick start

```bash
# 1. Reset to clean state (creates venvs, plants vulnerable versions)
./reset.sh

# 2. Run the full 6-step demo
./run.sh
```

> **Requirements:** Python 3.9+, internet access (builder downloads sdists from PyPI).
> Both scripts auto-create `.venv` (tool environment) and `.demo_env` (simulated customer environment).

### Manual steps

```bash
# Seed database
python3 db/seed.py

# Start registry on :8000
uvicorn registry.server:app --port 8000

# Run builder (builds requests wheel, skips pre-built urllib3 wheels)
python3 factory/builder.py

# Medium severity: warning + patched wheel installed
python3 client/install.py requests==2.28.0

# High severity: build blocked (exit 1)
python3 client/install.py urllib3==1.26.0

# Full requirements (blocked due to urllib3 High CVE)
python3 client/install.py -r client/requirements.txt
```

---

## Demo walkthrough

### Step 1 — Pre-flight
Checks Python, dependencies, and verifies the three urllib3 pre-built wheels exist in `factory/artifacts/`. Shows the demo environment's "before" state (`urllib3==1.26.0`, `requests==2.28.0`).

### Step 2 — Seed DB + start registry
Populates SQLite with 2 CVEs, 4 version groups, and 5 request_log rows. Starts the FastAPI registry on `:8000`.

### Step 3 — Builder (demand-driven)
Runs `factory/builder.py`. urllib3 groups are already built (skipped). The requests group (`2.28.0` was requested 7 days ago) is eligible and built. A CycloneDX SBOM is injected into the wheel.

### Step 4 — Medium severity (requests)
```
[ECHO] ⚠ WARNING: requests==2.28.0 — CVE-2023-32681 (Medium, CVSS 6.1)
       Affected range:  >=2.1.0,<2.31.0
       Proceeding with patched backport: requests-2.28.2+echo1
       Recommended fix: pip install 'requests>=2.31.0'
```
The patched wheel is installed and the embedded SBOM is verified.

### Step 5 — High severity (urllib3)
```
[ECHO] ✗ BLOCKED: urllib3==1.26.0 — CVE-2021-33503 (High, CVSS 7.5)
       Affected range:  >=1.25.8,<1.26.5
       Quick fix:       pip install 'urllib3>=1.26.5'
       Patched build:   urllib3-1.26.4+echo1 available but severity requires explicit upgrade
```
`client/install.py` exits with code 1. The build is aborted.

### Step 6 — Registry inspection
Shows the PEP 503 index for urllib3 (with embedded CVE metadata in HTML comments) and the updated `request_log` counts.

---

## CVE database

**CVE-2021-33503** — urllib3, High, CVSS 7.5
ReDoS via crafted HTTP response header in `urllib3.util.url`. Fixed in 1.26.5.

| Version range | Pivot | Artifact |
|---|---|---|
| `>=1.25.4,<1.25.8` | 1.25.7 | `urllib3-1.25.7+echo1-py2.py3-none-any.whl` |
| `>=1.25.8,<1.26.5` | 1.26.4 | `urllib3-1.26.4+echo1-py2.py3-none-any.whl` |
| `>=2.0.0,<2.0.6`   | 2.0.5  | `urllib3-2.0.5+echo1-py3-none-any.whl` |

**CVE-2023-32681** — requests, Medium, CVSS 6.1
SSRF via trusted Host header forwarded through redirects to untrusted origins. Fixed in 2.31.0.

| Version range | Pivot | Artifact |
|---|---|---|
| `>=2.1.0,<2.31.0` | 2.28.2 | `requests-2.28.2+echo1-py3-none-any.whl` *(built during demo)* |

---

## SBOM verification

```bash
python3 -c "
import zipfile, json
with zipfile.ZipFile('factory/artifacts/requests-2.28.2+echo1-py3-none-any.whl') as zf:
    sbom_path = next(n for n in zf.namelist() if 'sbom.cdx.json' in n)
    print(json.dumps(json.loads(zf.read(sbom_path)), indent=2))
"
# Expected: CycloneDX SBOM with CVE-2023-32681, analysis.state = "resolved"
```

---

## File structure

```
echo/
├── db/
│   ├── schema.py          # SQLite schema + get_connection() + init_db()
│   └── seed.py            # seed CVEs, version groups, request_log
├── factory/
│   ├── builder.py         # demand-driven backport wheel builder
│   ├── sbom.py            # CycloneDX SBOM generator + wheel injector
│   └── artifacts/         # pre-built urllib3 wheels + CVE patches
├── registry/
│   └── server.py          # FastAPI PEP 503 registry + /check endpoint
├── client/
│   ├── install.py         # pip wrapper with CVE check
│   └── requirements.txt   # urllib3==1.26.0 + requests==2.28.0 (demo "before")
├── run.sh                 # 6-step demo script
└── reset.sh               # reset to clean state
```
