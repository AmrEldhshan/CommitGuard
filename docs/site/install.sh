#!/usr/bin/env bash
# ==============================================================================
# CommitGuard — Universal Offline Installer for Linux & macOS
# Repository: https://github.com/AmrEldhshan/CommitGuard
# ==============================================================================
set -euo pipefail

# ANSI Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${CYAN}${BOLD}"
echo "  ╔════════════════════════════════════════════════════════════╗"
echo "  ║        🛡️  CommitGuard — Universal Offline Installer        ║"
echo "  ║  Next-Gen Pre-Commit Security, SAST & Blast-Radius Engine  ║"
echo "  ╚════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ------------------------------------------------------------------------------
# 1. Verification: Ensure current directory is inside a Git repository
# ------------------------------------------------------------------------------
echo -e "${BLUE}▶ Checking environment...${NC}"

if ! command -v git >/dev/null 2>&1; then
    echo -e "${RED}${BOLD}❌ [ERROR] 'git' command not found on PATH.${NC}" >&2
    echo -e "CommitGuard requires Git. Please install git and try again." >&2
    exit 1
fi

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo -e "${RED}${BOLD}❌ [ERROR] The current directory is NOT a git repository!${NC}" >&2
    echo -e "${YELLOW}CommitGuard must be installed inside a valid git repository (e.g., your project repo).${NC}" >&2
    echo -e "Please navigate into your project directory first:" >&2
    echo -e "  cd /path/to/your/project" >&2
    echo -e "  ./install.sh" >&2
    exit 1
fi

REPO_ROOT="$(git rev-parse --show-toplevel)"
REPO_NAME="$(basename "$REPO_ROOT")"
echo -e "${GREEN}✔ Valid git repository detected:${NC} ${BOLD}${REPO_NAME}${NC} (${REPO_ROOT})"

# ------------------------------------------------------------------------------
# 2. Python 3 Verification
# ------------------------------------------------------------------------------
PYTHON_BIN=""
for candidate in python3 python python3.14 python3.13 python3.12 python3.11; do
    if command -v "$candidate" >/dev/null 2>&1; then
        if "$candidate" -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" 2>/dev/null; then
            PYTHON_BIN="$candidate"
            break
        fi
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    echo -e "${RED}${BOLD}❌ [ERROR] Python 3.10+ was not found on PATH.${NC}" >&2
    echo -e "CommitGuard requires Python 3.10 or higher. Please install Python and try again." >&2
    exit 1
fi

PY_VER="$("$PYTHON_BIN" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')")"
echo -e "${GREEN}✔ Python detected:${NC} ${PYTHON_BIN} (v${PY_VER})"

# Ensure PyYAML is available (or install into user cache if missing)
if ! "$PYTHON_BIN" -c "import yaml" >/dev/null 2>&1; then
    echo -e "${YELLOW}ℹ PyYAML is required to parse YAML security rules. Installing pyyaml...${NC}"
    "$PYTHON_BIN" -m pip install pyyaml --quiet --user 2>/dev/null || "$PYTHON_BIN" -m pip install pyyaml --quiet 2>/dev/null || {
        echo -e "${YELLOW}⚠ Could not automatically install PyYAML. If rule parsing fails, run: pip install pyyaml${NC}"
    }
fi

# ------------------------------------------------------------------------------
# 3. Locate or Download CommitGuard Toolkit Source
# ------------------------------------------------------------------------------
TEMP_DIR=""
cleanup() {
    if [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
    fi
}
trap cleanup EXIT INT TERM

SOURCE_DIR=""

# Check if script is executed from within the CommitGuard source tree
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "${SCRIPT_DIR}/install_hook.py" ]; then
    SOURCE_DIR="${SCRIPT_DIR}"
elif [ -f "${SCRIPT_DIR}/../../install_hook.py" ]; then
    SOURCE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
elif [ -f "${REPO_ROOT}/install_hook.py" ]; then
    SOURCE_DIR="${REPO_ROOT}"
fi

if [ -n "$SOURCE_DIR" ] && [ -f "${SOURCE_DIR}/install_hook.py" ]; then
    echo -e "${BLUE}▶ Using local CommitGuard toolkit from:${NC} ${SOURCE_DIR}"
else
    echo -e "${BLUE}▶ Downloading latest CommitGuard toolkit from GitHub...${NC}"
    TEMP_DIR="$(mktemp -d -t commitguard-install-XXXXXX)"
    ARCHIVE_URL="https://github.com/AmrEldhshan/CommitGuard/archive/refs/heads/main.tar.gz"

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$ARCHIVE_URL" -o "${TEMP_DIR}/commitguard.tar.gz"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "${TEMP_DIR}/commitguard.tar.gz" "$ARCHIVE_URL"
    else
        echo -e "${RED}${BOLD}❌ Neither curl nor wget found. Cannot download CommitGuard.${NC}" >&2
        exit 1
    fi

    tar -xzf "${TEMP_DIR}/commitguard.tar.gz" -C "$TEMP_DIR"
    SOURCE_DIR="${TEMP_DIR}/CommitGuard-main"
fi

# ------------------------------------------------------------------------------
# 4. Execute Installation into the Target Repository
# ------------------------------------------------------------------------------
echo -e "${BLUE}▶ Installing CommitGuard into:${NC} ${REPO_ROOT}..."

"$PYTHON_BIN" "${SOURCE_DIR}/install_hook.py" install "$REPO_ROOT" --force

# Make wrapper script executable
if [ -f "${REPO_ROOT}/commit-guard" ]; then
    chmod +x "${REPO_ROOT}/commit-guard"
fi

# ------------------------------------------------------------------------------
# 5. Verification & Friendly Sign-Off
# ------------------------------------------------------------------------------
echo ""
echo -e "${GREEN}========================================================================${NC}"
echo -e "${GREEN}${BOLD}✔ CommitGuard has been successfully installed into: ${REPO_NAME}!${NC}"
echo -e "${CYAN}🛡️  Offline protection is active:${NC} Every 'git commit' will now automatically"
echo -e "   scan staged diffs for hardcoded secrets, AST taint flows, and CVEs."
echo ""
echo -e "💡 Quick commands to try inside '${REPO_NAME}':"
echo -e "   ${BOLD}./commit-guard scan${NC}        # Run manual scan on staged changes"
echo -e "   ${BOLD}./commit-guard gui${NC}         # Launch visual control center on 127.0.0.1"
echo -e "   ${BOLD}./commit-guard doctor${NC}      # Verify installation health"
echo -e "${GREEN}========================================================================${NC}"
echo ""
echo -e "${GREEN}${BOLD}Have a nice life far from hacking developer bro :) 😊${NC}"
echo ""

