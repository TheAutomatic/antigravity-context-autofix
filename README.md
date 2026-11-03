# antigravity-context-autofix

**[简体中文](README.md) | [English](README.en.md)**

Antigravity（IDE / 桌面端 / `agy` CLI）1M 上下文窗口与 `AGENTS.md` 规则预算的**跨版本自动定位与一键修复脚本**。零第三方依赖（仅需 Python 3 标准库），不分发任何专有二进制文件。

---

## 致谢与原理说明

- 特别感谢 **[@lmxxf](https://github.com/lmxxf)** 的排查与分享。
- 同时感谢 **Antigravity IDE**（本仓库的 Windows 架构梳理、Go `pclntab` 跨版本自动定位脚本编写与端到端验库，均由运行在 Antigravity IDE 中的 Agent 协作完成）。

关于为什么 Antigravity 面板显示 1M 窗口但实际在 256K 就会丢历史、以及为什么大体积 `AGENTS.md` 会被截断或整份排除的完整排查过程与底层原理，请直接阅读 [@lmxxf](https://github.com/lmxxf) 的原仓库与文章：
- 原仓库：[https://github.com/lmxxf/antigravity-context-fix](https://github.com/lmxxf/antigravity-context-fix)
- 排查原文：[公众号 340-A 记录](https://github.com/lmxxf/ai-theorys-study/blob/main/wechat/340-A.md)

**本项目在此基础上做了什么：**
原仓库针对 Linux 版 `agy` 提供了特定版本的固定偏移补丁与归档。本项目将其做成了一个**跨平台、跨版本的纯脚本自动定位器（Autofix）**：
- 直接解析可执行文件的 Go `pclntab` 符号表与 getter 指令，自动算出新版函数偏移与结构体字段偏移，**客户端自动升级后无需等待人工重定位，重跑一次脚本即可**；
- 除 Linux (`x86_64` / `ARM64`) 的 `agy` CLI 外，新增支持 **Windows (`x86_64` PE)** 下的 **Antigravity IDE**、**`agy` CLI** 以及 **Antigravity 独立桌面端**（自动发现并同步更新 `agy.version.json` 缓存元数据）。

**修改内容摘要（与上游方案一致）：**
1. 将 Gemini 4 Argon（High / Medium / Low 三档）最终配置合并出口的 `max_token_limit` 设为 `1,000,000`（数据库实际请求上限为 **`983,040` tokens**）；
2. 关闭自动 Checkpoint 提前裁剪（返回 `false, nil`），借用其不可达函数体放置跳板，保持文件大小不变；
3. 单文件规则/技能读取上限：`24,000` → `1,048,576` 字节（1 MiB）；
4. Rules / Customizations 两项总预算：`20,000` → `131,072` tokens。

---

## 支持的目标程序

- **Windows (`x86_64` PE)**（脚本默认自动扫描以下两处）：
  - `C:\Users\<User>\.gemini\bin\agy.exe`（**Antigravity IDE** 与 **`agy` CLI** 共用的后端）
  - `C:\Users\<User>\AppData\Local\Programs\antigravity\resources\bin\language_server.exe`（**Antigravity 独立桌面端** 后端）
- **Linux (`x86_64` / `ARM64` ELF)**：
  - `~/.local/bin/agy` 或 `~/.gemini/bin/agy`

---

## 快速使用

### Windows（双击或命令行）

1. **只读检查当前状态（无需关闭 IDE）**：
   双击 `check-status.cmd`，或运行：
   ```powershell
   python fix_antigravity_context.py --check
   ```

2. **一键定位并打补丁（每次客户端升级后重跑一次即可）**：
   先关闭 Antigravity IDE / 桌面端窗口，然后双击 `fix-all.cmd`，或运行：
   ```powershell
   python fix_antigravity_context.py --kill
   ```
   > 原版会自动备份到 `C:\Users\<User>\.gemini\agy-patches\`，重启客户端即可生效。

3. **验证当前会话数据库是否已变为 `983040`**：
   双击 `verify-latest.cmd`，或运行：
   ```powershell
   python verify_session.py
   ```

4. **一键还原原版**：
   双击 `restore-all.cmd`，或运行：
   ```powershell
   python fix_antigravity_context.py --kill --restore
   ```

### Linux (`x86_64` / `ARM64`)

```bash
# 只读检查
python3 fix_antigravity_context.py --check --target ~/.local/bin/agy

# 自动定位并打补丁
python3 fix_antigravity_context.py --target ~/.local/bin/agy

# 验证会话数据库
python3 verify_session.py <conversation_id> --agents /path/to/AGENTS.md

# 还原原版
python3 fix_antigravity_context.py --restore --target ~/.local/bin/agy
```

---

## 合规与免责声明（Disclaimer）

1. **不分发任何专有二进制文件**：本仓库仅包含原创的 Python 标准库脚本与批处理包装器，**不包含、亦不分发**任何 Google Antigravity（`agy` / `language_server`）可执行文件或其压缩包。请勿将任何 `.exe`、`agy.gz` 或 `.bak` 二进制文件提交至版本控制。
2. **不涉及鉴权、计费与服务端配额绕过**：本工具不会修改或绕过任何账号登录认证（OAuth）、权限校验、安全沙箱或服务端速率/配额限制；仅用于修正本地客户端在合并配置时将前端已公示的 1.0M 上下文窗口回退为 256K 的问题，以及调整本地工作区规则文件（`AGENTS.md`）的读取截断阈值。
3. **风险自担**：修改本地客户端二进制属于非官方行为，可能随上游更新而失效。本仓库仅供个人技术研究、调试与互操作性学习使用，使用本脚本产生的一切后果由使用者自行承担。
