#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"

if command -v python3 >/dev/null 2>&1; then
    exec python3 "$DIR/scripts/fix_antigravity_context.py" "$@"
elif command -v python >/dev/null 2>&1; then
    exec python "$DIR/scripts/fix_antigravity_context.py" "$@"
else
    echo "[ERROR] Python 3 not found." >&2
    exit 1
fi
