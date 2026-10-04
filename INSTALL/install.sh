#!/bin/bash
# Kane Orchestrator — Civic Infrastructure node installer.
#
# On a freshly installed Ubuntu Server 24.04 LTS, run one command:
#
#   curl -fsSL https://raw.githubusercontent.com/git64bit/kane-orchestrator/v0.3.0/INSTALL/install.sh | sudo bash
#
# Options are passed to INSTALL/node_install.py, for example:
#
#   ... | sudo bash -s -- --dry-run
#   ... | sudo bash -s -- --subnet 10.88.0.0/24 --storage dir
#
# From a clone of this repository:  sudo ./INSTALL/install.sh [options]
set -euo pipefail

# Updated at each release so the one-line command installs the same release
# the script was fetched from.
RELEASE_REF="v0.3.0"

REPO_URL="${KANE_ORCHESTRATOR_REPO:-https://github.com/git64bit/kane-orchestrator}"
REF="${KANE_ORCHESTRATOR_REF:-$RELEASE_REF}"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run the installer as root: sudo bash INSTALL/install.sh" >&2
  exit 1
fi

script="${BASH_SOURCE[0]:-}"
if [ -n "$script" ] && [ -f "$script" ] \
   && [ -f "$(dirname "$script")/node_install.py" ] \
   && [ -d "$(dirname "$script")/../src/civic_orchestrator" ]; then
  SOURCE="$(cd "$(dirname "$script")/.." && pwd)"
  echo "Using this checkout: $SOURCE"
else
  SOURCE="/opt/kane-orchestrator/$REF"
  if [ ! -d "$SOURCE/.git" ]; then
    echo "Fetching kane-orchestrator $REF"
    export DEBIAN_FRONTEND=noninteractive
    command -v git >/dev/null || {
      apt-get -o DPkg::Lock::Timeout=600 update -q
      apt-get -o DPkg::Lock::Timeout=600 install -y -q git
    }
    rm -rf "$SOURCE.partial"
    mkdir -p "$(dirname "$SOURCE")"
    git clone -q "$REPO_URL" "$SOURCE.partial"
    git -C "$SOURCE.partial" -c advice.detachedHead=false checkout -q "$REF"
    mv "$SOURCE.partial" "$SOURCE"
  fi
  echo "Using $SOURCE ($(git -C "$SOURCE" rev-parse --short=12 HEAD))"
fi

exec python3 "$SOURCE/INSTALL/node_install.py" --source "$SOURCE" "$@"
