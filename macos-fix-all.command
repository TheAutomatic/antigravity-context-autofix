#!/usr/bin/env bash
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

if ! command -v python3 >/dev/null 2>&1; then
    echo "[ERROR] python3 not found."
    read -r -p "Press Enter to close / 按回车关闭窗口..." _
    exit 1
fi

echo "=== Antigravity 1M Context & Rules Auto-Patcher (macOS) ==="
echo "请先关闭 Antigravity IDE / CLI 窗口，核对目标后输入 Y 继续。"
echo "Please close Antigravity IDE / CLI first, then review targets and type Y."
echo ""
python3 "$DIR/scripts/fix_antigravity_context.py" "$@"
echo ""
read -r -p "Press Enter to close / 按回车关闭窗口..." _
