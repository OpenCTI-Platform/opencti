#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────
SKIP_INSTALL=false
SNYK_VERSION="1.1291.0"  # Pin Snyk version for reproducibility

usage() {
  echo "Usage: $0 [--skip-install] [<branch>]"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-install) SKIP_INSTALL=true; shift ;;
    -*) echo "Unknown option: $1"; usage ;;
    *) BRANCH="$1"; shift ;;
  esac
done

# ─────────────────────────────────────────────
# Resolve branch — fail explicitly on detached HEAD
# ─────────────────────────────────────────────
if [ -z "${BRANCH:-}" ]; then
  BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null)" \
    || { echo "[ERROR] Could not determine current branch (detached HEAD?)" >&2; exit 1; }
  [ "$BRANCH" = "HEAD" ] \
    && { echo "[ERROR] Detached HEAD state — please specify a branch explicitly." >&2; exit 1; }
fi

REPO_ROOT="$(git rev-parse --show-toplevel)"
mkdir -p "${REPO_ROOT}/.snyk-reports"

# ─────────────────────────────────────────────
# Trap — always restore stash on exit
# ─────────────────────────────────────────────
STASHED=false

cleanup() {
  if [ "$STASHED" = true ]; then
    log "Restoring stashed changes..."
    git -C "$REPO_ROOT" stash pop || echo "[WARN] Could not pop stash — check 'git stash list'" >&2
  fi
}
trap cleanup EXIT

# ─────────────────────────────────────────────
# Functions
# ─────────────────────────────────────────────
log() { echo -e "\n\033[1;34m>>> $*\033[0m"; }
err() { echo -e "\033[1;31m[ERROR] $*\033[0m" >&2; exit 1; }

sanitize_branch() {
  # Replace any character that is unsafe in a filename
  echo "$1" | tr -s '/~^:? ' '-' | sed 's/[^a-zA-Z0-9._-]/-/g'
}

install_deps() {
  log "Installing dependencies..."

  cd "$REPO_ROOT"
  yarn install

  cd "$REPO_ROOT/opencti-platform/opencti-graphql"
  yarn install
  yarn install:python

  cd "$REPO_ROOT/opencti-platform/opencti-front"
  yarn install

  cd "$REPO_ROOT/opencti-worker/src"
  python3 -m pip install -r requirements.txt

  cd "$REPO_ROOT/docs"
  pip install -r requirements.txt

  cd "$REPO_ROOT/client-python"
  pip install -r requirements.txt
}

check_snyk_auth() {
  log "Checking Snyk authentication..."
  if ! npx "snyk@${SNYK_VERSION}" whoami &>/dev/null; then
    err "Snyk is not authenticated. Run 'npx snyk@${SNYK_VERSION} auth' and try again."
  fi
}

run_snyk() {
  log "Running Snyk scan (branch: $BRANCH, sha: $CURRENT_SHA)..."
  cd "$REPO_ROOT"

  # Separate exit code from output: exit 1 = vulns found, exit 2 = scan error
  set +e
  npx "snyk@${SNYK_VERSION}" test --all-projects 2>&1 | tee "$REPORT_FILE"
  SNYK_EXIT="${PIPESTATUS[0]}"
  set -e

  case "$SNYK_EXIT" in
    0) log "Snyk: no vulnerabilities found." ;;
    1) log "Snyk: vulnerabilities found — see report." ;;
    2) err "Snyk scan failed (tool error, network issue, or bad token). Exit code: 2" ;;
    *) err "Snyk exited with unexpected code: $SNYK_EXIT" ;;
  esac

  return "$SNYK_EXIT"
}

# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────
cd "$REPO_ROOT"

# Stash — include untracked files to get a clean working tree
if ! git diff --quiet || ! git diff --cached --quiet || [ -n "$(git ls-files --others --exclude-standard)" ]; then
  log "Stashing local changes (including untracked files)..."
  git stash push --include-untracked -m "snyk-compare-stash"
  STASHED=true
fi

log "Switching to branch: $BRANCH"
git checkout "$BRANCH" || err "Failed to checkout branch '$BRANCH'"

if ! git pull --ff-only 2>/dev/null; then
  log "Could not fast-forward — scanning local state of $(git rev-parse --short HEAD)"
fi

# Resolve SHA and report path after checkout
CURRENT_SHA="$(git rev-parse --short HEAD)"
SAFE_BRANCH="$(sanitize_branch "$BRANCH")"
REPORT_FILE="${REPO_ROOT}/.snyk-reports/snyk-${SAFE_BRANCH}-${CURRENT_SHA}.txt"

log "Scanning commit: $CURRENT_SHA"

if [ "$SKIP_INSTALL" = true ]; then
  log "Skipping dependency installation (--skip-install)"
else
  install_deps
fi

check_snyk_auth
run_snyk
SCAN_EXIT=$?

echo ""
echo "────────────────────────────────────────────"
echo "  Branch : $BRANCH"
echo "  SHA    : $CURRENT_SHA"
echo "  Report : $REPORT_FILE"
echo "────────────────────────────────────────────"

exit "$SCAN_EXIT"