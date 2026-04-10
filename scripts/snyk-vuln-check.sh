#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────
SKIP_INSTALL=false

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

[ -z "${BRANCH:-}" ] && BRANCH="$(git rev-parse --abbrev-ref HEAD)"

REPO_ROOT="$(git rev-parse --show-toplevel)"

mkdir -p "${REPO_ROOT}/.snyk-reports"

# ─────────────────────────────────────────────
# Functions
# ─────────────────────────────────────────────
log() { echo -e "\n\033[1;34m>>> $*\033[0m"; }
err() { echo -e "\033[1;31m[ERROR] $*\033[0m" >&2; exit 1; }

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
  pip install -r requirements.txt

  cd "$REPO_ROOT/docs"
  pip install -r requirements.txt

  cd "$REPO_ROOT/client-python"
  pip install -r requirements.txt
}

check_snyk_auth() {
  log "Checking Snyk authentication..."
  if ! yarn dlx snyk whoami &>/dev/null; then
    err "Snyk is not authenticated. Please run 'snyk auth' first and try again."
  fi
}

run_snyk() {
  log "Running Snyk scan..."
  cd "$REPO_ROOT"
  yarn dlx snyk test --all-projects 2>&1 | tee "$REPORT_FILE" || true
}

# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────
cd "$REPO_ROOT"

if ! git diff --quiet || ! git diff --cached --quiet; then
  log "Stashing local changes..."
  git stash push -m "snyk-compare-stash"
  STASHED=true
else
  STASHED=false
fi

log "Switching to branch: $BRANCH"
git checkout "$BRANCH" || err "Failed to checkout branch '$BRANCH'"
git pull --ff-only 2>/dev/null || log "Could not fast-forward — continuing with local state"

REPORT_FILE="${REPO_ROOT}/.snyk-reports/snyk-${BRANCH//\//-}-$(git rev-parse --short HEAD).txt"

[ "$SKIP_INSTALL" = true ] && log "Skipping dependency installation (--skip-install)" || install_deps

check_snyk_auth
run_snyk

[ "$STASHED" = true ] && { log "Restoring stashed changes..."; git stash pop; }

echo ""
echo "────────────────────────────────────────────"
echo "  Report saved to: $REPORT_FILE"
echo "────────────────────────────────────────────"