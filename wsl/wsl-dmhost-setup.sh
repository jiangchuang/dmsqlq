#!/usr/bin/env bash
# ============================================================
# wsl-dmhost-setup.sh —— 在 WSL 里安装「自动解析 Windows 主机地址」的辅助函数
# ============================================================
# 目的：WSL2 默认 NAT 模式下，Windows 本机（跑着达梦）的地址是 WSL 的默认网关
#       （形如 172.20.240.1），且**每次重启/更新 WSL 都可能变**。
#       本脚本装一个 `dmhost` 函数 + 登录自动打印，免去每次查 IP。
#
# 用法（在 WSL 的 Debian 终端里执行一次）：
#     bash wsl-dmhost-setup.sh
#
# 幂等：重复执行安全 —— 受管代码块用标记包裹，已存在则原位替换，不会重复追加。
#
# 卸载：bash wsl-dmhost-setup.sh --uninstall
# ============================================================

set -u

RC="${HOME}/.bashrc"
BEGIN="# >>> dmsqlq dmhost >>>"
END="# <<< dmsqlq dmhost <<<"

# ---------- 卸载 ----------
if [ "${1:-}" = "--uninstall" ]; then
    if [ -f "$RC" ] && grep -qF "$BEGIN" "$RC"; then
        # 用 awk 删除受管块（含标记行本身）
        awk -v b="$BEGIN" -v e="$END" '
            $0 == b { skip = 1; next }
            $0 == e { skip = 0; next }
            !skip { print }
        ' "$RC" > "${RC}.tmp" && mv "${RC}.tmp" "$RC"
        echo "已移除 dmhost 受管块：$RC"
    else
        echo "未发现受管块，无需卸载。"
    fi
    exit 0
fi

# ---------- 安装 ----------
if [ ! -f "$RC" ]; then
    touch "$RC"
    echo "（$RC 不存在，已创建）"
fi

# 受管块：用「带引号的 heredoc」写入 —— 必须引号，
# 否则 $(dmhost)、$__dmh、\033 会在写入阶段就被当前 shell 展开（实测踩过）。
BLOCK=$(cat <<'DMEOF'
# >>> dmsqlq dmhost >>>
# dmsqlq 辅助：解析「Windows 主机在 WSL 眼里的地址」。
# 原理：WSL2 默认 NAT 模式下，默认路由的网关就是 Windows 主机那一侧。
# 地址会随 WSL 重启/更新变化，所以每次登录现算，不要硬编码。
dmhost() {
    ip route show default 2>/dev/null | awk '{print $3; exit}'
}

# 登录时打印一次，省得每次敲 ipconfig / ip route 去查。
# 只在交互式 shell 打印（非交互式如 scp/rsync/脚本不会被打扰）。
case $- in
    *i*)
        if command -v ip >/dev/null 2>&1; then
            __dmh="$(dmhost)"
            if [ -n "$__dmh" ]; then
                printf '\033[2m[dmhost] Windows 主机地址: \033[0m\033[36m%s\033[0m\n' "$__dmh"
                printf '\033[2m[dmhost] 连本机达梦: dmsqlq watch -H %s -P 5236 -p <口令>\033[0m\n' "$__dmh"
                printf '\033[2m[dmhost] 虚拟机环境用其自身 IP: 192.168.16.135:15236(主) / 192.168.16.133:5236(单机)\033[0m\n'
            fi
            unset __dmh
        fi
        ;;
esac
# <<< dmsqlq dmhost <<<
DMEOF
)

# 已存在受管块 → 先删再写（保证幂等且能更新内容）
if grep -qF "$BEGIN" "$RC"; then
    awk -v b="$BEGIN" -v e="$END" '
        $0 == b { skip = 1; next }
        $0 == e { skip = 0; next }
        !skip { print }
    ' "$RC" > "${RC}.tmp" && mv "${RC}.tmp" "$RC"
    echo "发现已存在的受管块，已先移除（准备写入最新版）。"
fi

# 追加：printf '%s\n' 只做一次字面量输出，不解释内容里的转义
{
    printf '\n'
    printf '%s\n' "$BLOCK"
} >> "$RC"

echo "已写入受管块：$RC"
echo
echo "---- 校验 ----"
if grep -qF "$BEGIN" "$RC" && grep -qF "$END" "$RC"; then
    echo "✓ 标记完整"
else
    echo "✗ 标记缺失，请检查 $RC"
    exit 1
fi
echo "✓ 函数定义：$(grep -c '^dmhost() {' "$RC") 处"
echo "✓ 语法自检：$(bash -n "$RC" 2>&1 && echo '通过' || echo '★ 有语法错')"
echo
echo "---- 立即在本终端生效（不用重开） ----"
echo "    source \"$RC\""
echo
echo "---- 验证 ----"
echo "    dmhost          # 应打印 Windows 主机地址（如 172.20.240.1）"
echo
echo "提示：下次登录它会自动打印该地址。想卸载：bash \"$0\" --uninstall"
