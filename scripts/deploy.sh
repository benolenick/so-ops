#!/usr/bin/env bash
# Deploy so-ops to jagg via SSH (ProxyJump through torr)
# Run from repo root on zasz: ./scripts/deploy.sh
#
# On Windows (Git Bash without rsync): uses tar+ssh
# On Linux: uses rsync if available, falls back to tar+ssh
set -euo pipefail

REMOTE="jagg"
REMOTE_DIR="/home/om/so-ops"
SYSTEMD_DIR="/etc/systemd/system"

echo "=== Syncing code to ${REMOTE}:${REMOTE_DIR} ==="
if command -v rsync &>/dev/null; then
    rsync -avz --delete \
        --exclude config.toml \
        --exclude __pycache__ \
        --exclude '*.pyc' \
        --exclude .git \
        --exclude .venv \
        --exclude '*.egg-info' \
        ./ "${REMOTE}:${REMOTE_DIR}/"
else
    # Fallback: tar over ssh (preserves structure, skips excluded files)
    ssh "${REMOTE}" "mkdir -p ${REMOTE_DIR}"
    tar czf - \
        --exclude='config.toml' \
        --exclude='__pycache__' \
        --exclude='*.pyc' \
        --exclude='.git' \
        --exclude='.venv' \
        --exclude='*.egg-info' \
        . | ssh "${REMOTE}" "cd ${REMOTE_DIR} && tar xzf -"
fi

echo "=== Fixing line endings ==="
ssh "${REMOTE}" "find ${REMOTE_DIR} -name '*.sh' -o -name '*.py' -o -name '*.toml' -o -name '*.service' -o -name '*.timer' | xargs sed -i 's/\r$//'"

echo "=== Installing package ==="
ssh "${REMOTE}" "cd ${REMOTE_DIR} && .venv/bin/pip install -e . --quiet"

echo "=== Deploying systemd units ==="
ssh "${REMOTE}" "sudo cp ${REMOTE_DIR}/systemd/*.service ${REMOTE_DIR}/systemd/*.timer ${SYSTEMD_DIR}/ && sudo systemctl daemon-reload"

echo "=== Enabling timers ==="
ssh "${REMOTE}" "sudo systemctl enable --now so-triage.timer so-health.timer so-vulnscan-nmap.timer so-vulnscan-nuclei.timer"

echo "=== Done ==="
ssh "${REMOTE}" "systemctl list-timers | grep so-"
