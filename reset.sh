#!/usr/bin/env bash
# reset.sh — clears generated data and plants vulnerable versions for the demo
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

sep()  { printf "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n"; }
ok()   { printf "  ${GREEN}✓${RESET}  $1\n"; }
skip() { printf "  ${YELLOW}–${RESET}  $1\n"; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOLS_VENV="$SCRIPT_DIR/.venv"          # tool environment (builder, registry, seed)
DEMO_VENV="$SCRIPT_DIR/.demo_env"       # customer simulation environment

# ── Ensure tool venv exists with working deps ─────────────────────────────────
if [[ ! -f "$TOOLS_VENV/bin/python3" ]]; then
    printf "${BOLD}Setting up tool virtual environment (.venv)...${RESET}\n"
    python3 -m venv "$TOOLS_VENV"
fi
# Always ensure tool venv has a working urllib3 (not the vulnerable 1.26.0)
"$TOOLS_VENV/bin/pip" install "urllib3>=2.0" requests fastapi uvicorn packaging build --quiet --quiet
ok "Tool environment ready at .venv"

printf "\n${BOLD}${RED}  ╔═══════════════════════════════════╗${RESET}\n"
printf   "${BOLD}${RED}  ║       ECHO — RESET ENVIRONMENT    ║${RESET}\n"
printf   "${BOLD}${RED}  ╚═══════════════════════════════════╝${RESET}\n\n"

# ── 1. Kill registry ───────────────────────────────────────────────────────────
sep
printf "${BOLD}[1/3] Stopping registry${RESET}\n"
if pkill -f "uvicorn registry.server:app" 2>/dev/null; then
    sleep 1
    ok "Registry process killed"
else
    skip "Registry was not running"
fi

# ── 2. Delete DB + requests artifacts ─────────────────────────────────────────
sep
printf "${BOLD}[2/3] Clearing db/echo.db + factory/artifacts/requests-*.whl${RESET}\n"

if [[ -f "$SCRIPT_DIR/db/echo.db" ]]; then
    rm -f "$SCRIPT_DIR/db/echo.db"
    ok "Removed db/echo.db"
else
    skip "db/echo.db did not exist"
fi

requests_whl_count=$(find "$SCRIPT_DIR/factory/artifacts" -name "requests-*.whl" 2>/dev/null | wc -l | tr -d ' ')
if [[ "$requests_whl_count" -gt 0 ]]; then
    rm -f "$SCRIPT_DIR/factory/artifacts/requests-"*.whl
    ok "Removed $requests_whl_count requests wheel(s)"
else
    skip "No requests wheels to remove"
fi

# ── 3. Create demo env with vulnerable versions ────────────────────────────────
sep
printf "${BOLD}[3/3] Creating demo environment with vulnerable versions${RESET}\n"

# Recreate demo venv fresh so we always start from a clean state
rm -rf "$DEMO_VENV"
python3 -m venv "$DEMO_VENV"
"$DEMO_VENV/bin/pip" install "urllib3==1.26.0" "requests==2.28.0" --quiet --quiet 2>&1 || \
    "$DEMO_VENV/bin/pip" install "urllib3==1.26.0" "requests==2.28.0" --quiet 2>&1

urllib3_v=$("$DEMO_VENV/bin/pip" show urllib3  2>/dev/null | awk '/^Version:/{print $2}' || echo "?")
requests_v=$("$DEMO_VENV/bin/pip" show requests 2>/dev/null | awk '/^Version:/{print $2}' || echo "?")
ok "urllib3  $urllib3_v   ${YELLOW}(CVE-2021-33503 — High)${RESET}"
ok "requests $requests_v  ${YELLOW}(CVE-2023-32681 — Medium)${RESET}"

# ── Done ───────────────────────────────────────────────────────────────────────
sep
printf "\n${BOLD}${GREEN}  Reset complete.${RESET}\n"
printf   "${CYAN}  State: db removed, requests artifacts cleared, urllib3 pre-built wheels intact.${RESET}\n"
printf   "${CYAN}  Planted: urllib3 ${YELLOW}1.26.0${CYAN} (High)  requests ${YELLOW}2.28.0${CYAN} (Medium)  in .demo_env${RESET}\n"
printf   "${CYAN}  Run ${BOLD}./run.sh${RESET}${CYAN} to start the demo.${RESET}\n\n"
