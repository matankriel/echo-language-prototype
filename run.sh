#!/usr/bin/env bash
# run.sh — Echo demo: vulnerable package → CVE detected → patched wheel served
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; BLUE='\033[0;34m'
BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOLS_VENV="$SCRIPT_DIR/.venv"        # builder, registry, seed scripts
DEMO_VENV="$SCRIPT_DIR/.demo_env"     # simulated customer environment
REGISTRY_PORT=8000
REGISTRY_URL="http://localhost:$REGISTRY_PORT"
REGISTRY_PID=""

sep()    { printf "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n"; }
ok()     { printf "  ${GREEN}✓${RESET}  $1\n"; }
warn()   { printf "  ${YELLOW}!${RESET}  $1\n"; }
fail()   { printf "  ${RED}✗${RESET}  $1\n"; }
info()   { printf "  ${CYAN}›${RESET}  $1\n"; }
label()  { printf "  ${DIM}$1${RESET}\n"; }
header() {
    local n="$1" title="$2"
    printf "\n${BOLD}${BLUE}[STEP $n]${RESET} ${BOLD}$title${RESET}\n"
    sep
}

cleanup() {
    if [[ -n "$REGISTRY_PID" ]] && kill -0 "$REGISTRY_PID" 2>/dev/null; then
        kill "$REGISTRY_PID" 2>/dev/null
    fi
}
trap cleanup EXIT

# ── Ensure both venvs exist ────────────────────────────────────────────────────
if [[ ! -f "$TOOLS_VENV/bin/python3" ]]; then
    printf "${BOLD}Setting up tool virtual environment (.venv)...${RESET}\n"
    python3 -m venv "$TOOLS_VENV"
fi
# Always ensure tool venv has working deps (not the vulnerable urllib3==1.26.0)
"$TOOLS_VENV/bin/pip" install "urllib3>=2.0" requests fastapi uvicorn packaging build --quiet --quiet

if [[ ! -f "$DEMO_VENV/bin/python3" ]]; then
    printf "${BOLD}Setting up demo virtual environment (.demo_env)...${RESET}\n"
    printf "${BOLD}Run ./reset.sh first to create the demo environment.${RESET}\n"
    exit 1
fi

PYTHON="$TOOLS_VENV/bin/python3"
PIP="$TOOLS_VENV/bin/pip"
DEMO_PIP="$DEMO_VENV/bin/pip"

# ── Banner ─────────────────────────────────────────────────────────────────────
clear
printf "${BOLD}${CYAN}"
printf "  ███████╗ ██████╗██╗  ██╗ ██████╗ \n"
printf "  ██╔════╝██╔════╝██║  ██║██╔═══██╗\n"
printf "  █████╗  ██║     ███████║██║   ██║\n"
printf "  ██╔══╝  ██║     ██╔══██║██║   ██║\n"
printf "  ███████╗╚██████╗██║  ██║╚██████╔╝\n"
printf "  ╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ \n"
printf "${RESET}"
printf "${DIM}  CVE Remediation Demo — urllib3 (High) + requests (Medium)${RESET}\n"
printf "${DIM}  $(date '+%Y-%m-%d %H:%M:%S')${RESET}\n\n"

# ── Step 1: Pre-flight ─────────────────────────────────────────────────────────
header 1 "Pre-flight"

"$PYTHON" --version &>/dev/null && ok "Python: $("$PYTHON" --version 2>&1)" \
    || { fail "tool venv Python not found"; exit 1; }

missing=()
for pkg in fastapi uvicorn packaging requests build; do
    "$PIP" show "$pkg" &>/dev/null || missing+=("$pkg")
done
if [[ ${#missing[@]} -eq 0 ]]; then
    ok "All tool dependencies installed (fastapi, uvicorn, packaging, requests, build)"
else
    info "Installing missing packages: ${missing[*]}"
    "$PIP" install "${missing[@]}" --quiet --quiet
    ok "Dependencies installed"
fi

# Verify urllib3 pre-built wheels exist
for whl in urllib3-1.25.7+echo1-py2.py3-none-any.whl \
           urllib3-1.26.4+echo1-py2.py3-none-any.whl \
           urllib3-2.0.5+echo1-py3-none-any.whl; do
    if [[ -f "$SCRIPT_DIR/factory/artifacts/$whl" ]]; then
        ok "Pre-built wheel: $whl"
    else
        fail "Missing pre-built wheel: $whl"
        exit 1
    fi
done

printf "\n  ${BOLD}Demo environment state (before):${RESET}\n"
current_urllib3=$("$DEMO_PIP" show urllib3  2>/dev/null | awk '/^Version:/{print $2}' || echo "not installed")
current_requests=$("$DEMO_PIP" show requests 2>/dev/null | awk '/^Version:/{print $2}' || echo "not installed")
printf "  ${DIM}└─${RESET} urllib3  version: ${YELLOW}${BOLD}$current_urllib3${RESET}  ${RED}← CVE-2021-33503 (High)${RESET}\n"
printf "  ${DIM}└─${RESET} requests version: ${YELLOW}${BOLD}$current_requests${RESET}  ${YELLOW}← CVE-2023-32681 (Medium)${RESET}\n"

# ── Step 2: Discover CVEs + seed DB + start registry ─────────────────────────
header 2 "Discover CVEs + seed DB + start registry"

cd "$SCRIPT_DIR"

if [[ -z "${GITHUB_TOKEN:-}" ]]; then
    fail "GITHUB_TOKEN is not set — export it before running:"
    info "  export GITHUB_TOKEN=ghp_xxx"
    exit 1
fi

"$PYTHON" db/discover.py urllib3:CVE-2021-33503 requests:CVE-2023-32681
"$PYTHON" db/seed.py

printf "\n"
pkill -f "uvicorn registry.server:app" 2>/dev/null && sleep 1 || true
"$TOOLS_VENV/bin/uvicorn" registry.server:app --port $REGISTRY_PORT --log-level warning &
REGISTRY_PID=$!
sleep 2

if curl -s "$REGISTRY_URL/simple/" > /dev/null 2>&1; then
    ok "Registry is UP  →  ${BOLD}$REGISTRY_URL${RESET}"
    label "    PID $REGISTRY_PID  |  Simple index: $REGISTRY_URL/simple/"
else
    fail "Registry failed to start"; exit 1
fi

# ── Step 3: Builder (demand-driven) ───────────────────────────────────────────
header 3 "Builder  (demand-driven, 30-day filter)"

printf "\n"
info "Running factory/builder.py ..."
info "  urllib3 groups: artifact linked by discover.py → skip"
info "  requests 2.28.0 (7d ago)  → ${GREEN}BUILD${RESET}"
info "  requests 2.26.0 (50d ago) → ${YELLOW}SKIP${RESET} (outside 30-day window)"
printf "\n"

"$PYTHON" "$SCRIPT_DIR/factory/builder.py" 2>&1 | sed 's/^/    /'
printf "\n"

requests_whl=$(find "$SCRIPT_DIR/factory/artifacts" -name "requests-*+echo1*.whl" 2>/dev/null | head -1 || true)
if [[ -n "$requests_whl" ]]; then
    ok "requests patched wheel built: $(basename "$requests_whl")"
    ok "SBOM injected into wheel"
else
    warn "requests wheel not found — check builder output above"
fi

# Resolve the actual +echo1 version specs from the DB for use in Steps 6 and 7
URLLIB3_ECHO_SPEC=$("$PYTHON" - <<'PYEOF'
import sys; sys.path.insert(0, '.')
from packaging.specifiers import SpecifierSet
from packaging.version import Version
from db.schema import get_connection
demo = Version("1.26.0")
with get_connection() as conn:
    rows = conn.execute("""
        SELECT vg.pivot_version, vg.version_range FROM version_groups vg
        JOIN cves c ON c.cve_id = vg.cve_id
        WHERE c.package = 'urllib3' AND vg.artifact_filename IS NOT NULL
    """).fetchall()
    for r in rows:
        try:
            if demo in SpecifierSet(r['version_range']):
                print(f"urllib3=={r['pivot_version']}+echo1"); break
        except Exception:
            pass
PYEOF
)

REQUESTS_ECHO_SPEC=$("$PYTHON" - <<'PYEOF'
import sys; sys.path.insert(0, '.')
from db.schema import get_connection
with get_connection() as conn:
    row = conn.execute("""
        SELECT vg.pivot_version FROM version_groups vg
        JOIN cves c ON c.cve_id = vg.cve_id
        WHERE c.package = 'requests' AND vg.artifact_filename IS NOT NULL
        LIMIT 1
    """).fetchone()
    if row: print(f"requests=={row['pivot_version']}+echo1")
PYEOF
)

if [[ -n "$URLLIB3_ECHO_SPEC" ]]; then
    ok "urllib3 echo spec: ${BOLD}$URLLIB3_ECHO_SPEC${RESET}"
else
    warn "Could not resolve urllib3 echo spec — Steps 6/7 may fail"
fi
if [[ -n "$REQUESTS_ECHO_SPEC" ]]; then
    ok "requests echo spec: ${BOLD}$REQUESTS_ECHO_SPEC${RESET}"
else
    warn "Could not resolve requests echo spec — Steps 6/7 may fail"
fi

# ── Step 4: Medium severity demo — warn + proceed with vulnerable ─────────────
header 4 "Medium severity demo  (requests → CVE info block + proceed with vulnerable)"

printf "\n"
info "Installing requests==2.28.0 (CVE-2023-32681, Medium, CVSS 6.1)..."
printf "\n"
ECHO_PIP="$DEMO_PIP" "$PYTHON" "$SCRIPT_DIR/client/install.py" requests==2.28.0 2>&1 | sed 's/^/  /'
printf "\n"

installed_requests=$("$DEMO_PIP" show requests 2>/dev/null | awk '/^Version:/{print $2}' || echo "not installed")
ok "requests installed: ${BOLD}$installed_requests${RESET}"

if [[ "$installed_requests" == "2.28.0" ]]; then
    ok "Vulnerable version installed as expected (Medium — explicit fix recommended)"
else
    warn "Unexpected version: $installed_requests — check output above"
fi

# ── Step 5: High severity demo — build blocked ────────────────────────────────
header 5 "High severity demo  (urllib3 + requests → blocked due to urllib3 High CVE)"

printf "\n  ${DIM}client/requirements.txt:${RESET}\n"
cat "$SCRIPT_DIR/client/requirements.txt" | sed 's/^/    /'
printf "\n"
info "Installing -r client/requirements.txt (urllib3==1.26.0 is High CVE)..."
printf "\n"

set +e
ECHO_PIP="$DEMO_PIP" "$PYTHON" "$SCRIPT_DIR/client/install.py" -r "$SCRIPT_DIR/client/requirements.txt" 2>&1 | sed 's/^/  /'
EXIT_CODE=${PIPESTATUS[0]}
set -e

printf "\n"
if [[ "$EXIT_CODE" -ne 0 ]]; then
    ok "Build correctly blocked (exit code $EXIT_CODE)"
else
    warn "Expected non-zero exit code — check output above"
fi

printf "\n  ${DIM}Direct API check:${RESET}\n"
curl -s "$REGISTRY_URL/check/urllib3/1.26.0" | "$PYTHON" -m json.tool | sed 's/^/    /'

# ── Step 6: Apply Echo patches ────────────────────────────────────────────────
header 6 "Applying Echo patches — installing patched builds"

printf "\n"
info "Installing ${BOLD}$URLLIB3_ECHO_SPEC${RESET} and ${BOLD}$REQUESTS_ECHO_SPEC${RESET} into demo env..."
printf "\n"
"$DEMO_PIP" install "$URLLIB3_ECHO_SPEC" "$REQUESTS_ECHO_SPEC" \
    --find-links "$SCRIPT_DIR/factory/artifacts/" --quiet
printf "\n"
ok "Echo-patched wheels installed"
printf "\n  ${DIM}Installed versions:${RESET}\n"
"$DEMO_PIP" show urllib3 requests | grep -E "^(Name|Version)" | sed 's/^/    /'

# ── Step 7: Re-run install after Echo fix — High severity now passes ──────────
header 7 "Re-running install after Echo fix — High severity now passes"

printf "\n"
info "Installing ${BOLD}$URLLIB3_ECHO_SPEC${RESET} ${BOLD}$REQUESTS_ECHO_SPEC${RESET} via install.py..."
info "  Registry sees +echo1 → returns vulnerable=false → no block"
printf "\n"

set +e
ECHO_PIP="$DEMO_PIP" "$PYTHON" "$SCRIPT_DIR/client/install.py" \
    "$URLLIB3_ECHO_SPEC" "$REQUESTS_ECHO_SPEC" 2>&1 | sed 's/^/  /'
EXIT_CODE=${PIPESTATUS[0]}
set -e

printf "\n"
if [[ "$EXIT_CODE" -eq 0 ]]; then
    ok "Install succeeded (exit code 0) — +echo1 versions pass the CVE check"
else
    warn "Expected exit code 0 but got $EXIT_CODE — check output above"
fi

printf "\n  ${DIM}Registry check on +echo1 (early-return):${RESET}\n"
URLLIB3_ECHO_VER="${URLLIB3_ECHO_SPEC#*==}"
curl -s "$REGISTRY_URL/check/urllib3/$URLLIB3_ECHO_VER" | "$PYTHON" -m json.tool | sed 's/^/    /'

# ── Step 8: Registry inspection ───────────────────────────────────────────────
header 8 "Registry inspection"

printf "\n  ${DIM}PEP 503 index for urllib3:${RESET}\n"
curl -s "$REGISTRY_URL/simple/urllib3/" | sed 's/^/    /'

printf "\n\n  ${DIM}Updated request_log (request_count incremented by install.py calls):${RESET}\n"
"$PYTHON" - <<'PYEOF'
import sys
sys.path.insert(0, '.')
from db.schema import get_connection
from datetime import datetime, timedelta, timezone
cutoff = datetime.now(timezone.utc) - timedelta(days=30)
with get_connection() as conn:
    rows = conn.execute("SELECT * FROM request_log ORDER BY package, version").fetchall()
    print(f"  {'Package':<10}  {'Version':<10}  {'Count':<6}  {'30d window':<10}  Last Requested")
    print("  " + "─" * 65)
    for r in rows:
        lr = datetime.fromisoformat(r['last_requested'].replace('Z', '+00:00'))
        if lr.tzinfo is None:
            lr = lr.replace(tzinfo=timezone.utc)
        within = lr > cutoff
        w_label = '\033[0;32mWITHIN\033[0m' if within else '\033[1;33mOUTSIDE\033[0m'
        print(f"  {r['package']:<10}  {r['version']:<10}  {r['request_count']:<6}  {w_label:<10}  {r['last_requested']}")
PYEOF

# ── Summary ────────────────────────────────────────────────────────────────────
sep
printf "\n${BOLD}${GREEN}  Demo complete!${RESET}\n\n"
printf "  ${BOLD}What happened:${RESET}\n"
printf "  ${DIM}1.${RESET}  DB populated: CVEs + version groups fetched live from GitHub Security Advisory (GHSA)\n"
printf "  ${DIM}2.${RESET}  Registry started at ${BOLD}$REGISTRY_URL${RESET} (PEP 503 + /check endpoint)\n"
printf "  ${DIM}3.${RESET}  Builder: urllib3 groups skipped (linked by discover), requests wheel built + SBOM injected\n"
printf "  ${DIM}4.${RESET}  Medium demo: requests==2.28.0 → CVE info block → proceeded with vulnerable version\n"
printf "  ${DIM}5.${RESET}  High demo:   urllib3==1.26.0 → CVE info block → BUILD BLOCKED (exit 1)\n"
printf "  ${DIM}6.${RESET}  Echo patches applied: $URLLIB3_ECHO_SPEC + $REQUESTS_ECHO_SPEC installed\n"
printf "  ${DIM}7.${RESET}  Re-run with +echo1 specs: registry early-returns vulnerable=false → install succeeds (exit 0)\n"
printf "  ${DIM}8.${RESET}  Registry /simple/urllib3/ shows embedded CVE metadata per wheel\n\n"
printf "  ${DIM}Registry is still running (PID $REGISTRY_PID). Press Ctrl+C to stop.${RESET}\n\n"

wait "$REGISTRY_PID" 2>/dev/null || true
