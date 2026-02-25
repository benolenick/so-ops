#!/usr/bin/env bash
# One-time migration: move data from old layout to so-ops-data
# Run on jagg: bash /home/om/so-ops/scripts/migrate_state.sh
set -euo pipefail

OLD_TRIAGE="$HOME/so-triage"
OLD_VULNS="$HOME/vuln-scans"
NEW_BASE="$HOME/so-ops-data"

echo "Migrating to ${NEW_BASE}..."

mkdir -p "${NEW_BASE}/state"
mkdir -p "${NEW_BASE}/logs"
mkdir -p "${NEW_BASE}/output/triage/summaries"
mkdir -p "${NEW_BASE}/output/health"
mkdir -p "${NEW_BASE}/output/vulnscan"

# Triage state
if [ -f "${OLD_TRIAGE}/state.json" ]; then
    echo "  state.json -> state/triage.json"
    cp "${OLD_TRIAGE}/state.json" "${NEW_BASE}/state/triage.json"
fi

# Triage JSONL log
if [ -f "${OLD_TRIAGE}/triage_log.jsonl" ]; then
    echo "  triage_log.jsonl -> logs/triage.jsonl"
    cp "${OLD_TRIAGE}/triage_log.jsonl" "${NEW_BASE}/logs/triage.jsonl"
fi

# Triage summaries
if [ -d "${OLD_TRIAGE}/summaries" ]; then
    echo "  summaries/ -> output/triage/summaries/"
    cp -r "${OLD_TRIAGE}/summaries/"* "${NEW_BASE}/output/triage/summaries/" 2>/dev/null || true
fi

# Health reports
if [ -d "${OLD_TRIAGE}/health-reports" ]; then
    echo "  health-reports/ -> output/health/"
    cp -r "${OLD_TRIAGE}/health-reports/"* "${NEW_BASE}/output/health/" 2>/dev/null || true
fi

# Vuln scans
if [ -d "${OLD_VULNS}" ]; then
    echo "  vuln-scans/ -> output/vulnscan/"
    cp -r "${OLD_VULNS}/"* "${NEW_BASE}/output/vulnscan/" 2>/dev/null || true
fi

echo "Migration complete. Old directories left in place for safety."
echo "After verifying, you can remove:"
echo "  rm -rf ${OLD_TRIAGE} ${OLD_VULNS}"
