#!/bin/bash
# Xarex Probe — one-command launcher
# Usage: sudo ./run-probe.sh

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -f "./xarex-probe" ]; then
  echo "[xarex] Binary not found. Building..."
  go build -o xarex-probe .
  echo "[xarex] Build complete."
fi

echo "[xarex] Starting probe... (Ctrl+C to stop)"
sudo ./xarex-probe
