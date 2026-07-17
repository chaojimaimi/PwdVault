#!/usr/bin/env bash
# Thin entry point for the Phase 5 Python orchestrator.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$PROJECT_ROOT"
exec python3 scripts/phase5/run_gate.py "$@"
