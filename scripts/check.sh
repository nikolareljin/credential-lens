#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
helper="$repo_root/scripts/script-helpers/scripts/ci_node.sh"
if [[ ! -x "$helper" ]]; then
  echo "script-helpers is not initialized. Run: git submodule update --init --recursive" >&2
  exit 1
fi
exec bash "$helper" --workdir "$repo_root" --no-docker --no-install \
  --lint-cmd 'node --check bin/credential-lens.js && node --check src/index.js && node --check src/inspect-file.js && node --check src/inspection-session.js' \
  --test-cmd 'npm test' \
  --build-cmd 'npm pack --dry-run'
