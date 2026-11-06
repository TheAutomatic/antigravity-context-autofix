#!/usr/bin/env bash
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

if ! command -v python3 >/dev/null 2>&1; then
    echo "[ERROR] python3 not found."
    read -r -p "Press Enter to close / 按回车关闭窗口..." _
    exit 1
fi

python3 "$DIR/scripts/fix_antigravity_context.py" --status "$@"
echo ""
read -r -p "Press Enter to close / 按回车关闭窗口..." _
