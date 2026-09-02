#!/usr/bin/env bash
# run-gates.sh — run Revenant's QA gates in one shot and return a single
# aggregate exit code (non-zero if any gate fails).
#
# The individual scripts/check-*.py checkers each re-root themselves and can be
# run one at a time; this is the convenience aggregate the CI workflow calls.
# Which gates run is Revenant's scope, documented in scripts/gates.yml.
#
# Usage:  bash scripts/run-gates.sh
# Env:    PYTHON=python3.12 bash scripts/run-gates.sh   # override interpreter
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PY="${PYTHON:-python3}"

fail=0
run() {
  local label="$1"; shift
  echo "════════ ${label} ════════"
  if "$@"; then
    echo "  → PASS (${label})"
  else
    echo "  → FAIL (${label})"
    fail=1
  fi
  echo
}

# ACTIVE gates (see scripts/gates.yml for the full inventory + what's deferred).
run "provenance — check-upstream"                "$PY" scripts/check-upstream.py
run "stock-pin drift — sync-ludus-stock-pins"    "$PY" scripts/sync-ludus-stock-pins.py check
run "module availability"                        "$PY" scripts/check-module-availability.py

if [ "$fail" -ne 0 ]; then
  echo "GATES: FAIL"
  exit 1
fi
echo "GATES: PASS"
exit 0
