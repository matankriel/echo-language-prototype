#!/usr/bin/env bash
# reset.sh — clears generated data and plants vulnerable versions for the demo
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

sep()  { printf "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n"; }
ok()   { printf "  ${GREEN}✓${RESET}  $1\n"; }
skip() { printf "  ${YELLOW}–${RESET}  $1\n"; }
info() { printf "  ${CYAN}›${RESET}  $1\n"; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOLS_VENV="$SCRIPT_DIR/.venv"
DEMO_VENV="$SCRIPT_DIR/.demo_env"
ARTIFACTS_DIR="$SCRIPT_DIR/factory/artifacts"

printf "\n${BOLD}${RED}  ╔═══════════════════════════════════╗${RESET}\n"
printf   "${BOLD}${RED}  ║       ECHO — RESET ENVIRONMENT    ║${RESET}\n"
printf   "${BOLD}${RED}  ╚═══════════════════════════════════╝${RESET}\n\n"

# ── 1. Kill registry ───────────────────────────────────────────────────────────
sep
printf "${BOLD}[1/4] Stopping registry${RESET}\n"
if pkill -f "uvicorn registry.server:app" 2>/dev/null; then
    sleep 1
    ok "Registry process killed"
else
    skip "Registry was not running"
fi

# ── 2. Delete DB ───────────────────────────────────────────────────────────────
sep
printf "${BOLD}[2/4] Clearing db/echo.db${RESET}\n"

if [[ -f "$SCRIPT_DIR/db/echo.db" ]]; then
    rm -f "$SCRIPT_DIR/db/echo.db"
    ok "Removed db/echo.db"
else
    skip "db/echo.db did not exist"
fi

# ── 3. Clean all generated artifacts ──────────────────────────────────────────
sep
printf "${BOLD}[3/4] Cleaning factory/artifacts/ (all wheels + patches)${RESET}\n"

removed_whls=0
removed_patches=0

for whl in "$ARTIFACTS_DIR"/*.whl; do
    [[ -f "$whl" ]] || continue
    rm -f "$whl"
    (( removed_whls++ )) || true
done

for patch in "$ARTIFACTS_DIR"/*.patch; do
    [[ -f "$patch" ]] || continue
    rm -f "$patch"
    (( removed_patches++ )) || true
done

if [[ $removed_whls -gt 0 || $removed_patches -gt 0 ]]; then
    ok "Removed $removed_whls wheel(s) and $removed_patches patch file(s)"
else
    skip "No artifacts to remove"
fi

# ── 4. Create demo env with vulnerable versions ────────────────────────────────
sep
printf "${BOLD}[4/4] Creating demo environment with vulnerable versions${RESET}\n"

# Ensure tool venv exists and has required deps
if [[ ! -f "$TOOLS_VENV/bin/python3" ]]; then
    info "Creating tool virtual environment (.venv)..."
    python3 -m venv "$TOOLS_VENV"
    "$TOOLS_VENV/bin/pip" install "urllib3>=2.0" requests fastapi uvicorn packaging build certifi --quiet --quiet
    ok "Tool environment created at .venv"
else
    ok "Tool environment already exists at .venv"
fi

# Recreate demo venv fresh so we always start from a clean state
info "Recreating demo environment..."
if [[ -d "$DEMO_VENV" ]]; then
    chmod -R u+w "$DEMO_VENV" 2>/dev/null || true
    rm -rf "$DEMO_VENV"
fi
python3 -m venv "$DEMO_VENV"
"$DEMO_VENV/bin/pip" install "urllib3==1.26.0" "requests==2.28.0" --quiet --quiet

urllib3_v=$("$DEMO_VENV/bin/pip" show urllib3  2>/dev/null | awk '/^Version:/{print $2}' || echo "?")
requests_v=$("$DEMO_VENV/bin/pip" show requests 2>/dev/null | awk '/^Version:/{print $2}' || echo "?")
ok "urllib3  $urllib3_v   ${YELLOW}(CVE-2021-33503 — High)${RESET}"
ok "requests $requests_v  ${YELLOW}(CVE-2023-32681 — Medium)${RESET}"

# ── Done ───────────────────────────────────────────────────────────────────────
sep
printf "\n${BOLD}${GREEN}  Reset complete.${RESET}\n"
printf   "${CYAN}  Cleared:  db/echo.db, all wheels + patches (fully regenerated on next run)${RESET}\n"
printf   "${CYAN}  Planted:  urllib3 ${YELLOW}1.26.0${CYAN} (High)  requests ${YELLOW}2.28.0${CYAN} (Medium)  in .demo_env${RESET}\n"
printf   "${CYAN}  Run ${BOLD}./run.sh${RESET}${CYAN} to start the demo.${RESET}\n\n"
