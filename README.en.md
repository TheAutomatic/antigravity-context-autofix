# antigravity-context-autofix

**[简体中文](README.md) | [English](README.en.md)**

A cross-version, zero-dependency automatic symbol locator and one-click patcher to unlock the full **1M context window (`983,040` tokens)** and **`AGENTS.md` rules budget (`1 MiB` / `131,072` tokens)** for **Antigravity IDE**, **Antigravity Desktop**, and **`agy` CLI** across Windows and Linux.

Requires only the Python 3 standard library. Does not distribute any proprietary binaries.

---

## Acknowledgments & Background

- Special thanks to **[@lmxxf](https://github.com/lmxxf)** for the root-cause investigation and sharing.
- Also thanks to **Antigravity IDE** — the Windows backend architecture discovery, cross-version Go `pclntab` auto-locator script, and end-to-end session database verification in this repository were built collaboratively with the Agent running inside Antigravity IDE itself.

For the full investigation into why Antigravity's `/context` panel displays **1.0M tokens** for Gemini 4 Argon while actual requests truncate history at **256K**, and why large `AGENTS.md` files get truncated or excluded due to per-file and token budget caps, please refer to [@lmxxf](https://github.com/lmxxf)'s upstream repository and write-up:
- Upstream repository: [https://github.com/lmxxf/antigravity-context-fix](https://github.com/lmxxf/antigravity-context-fix)
- Detailed write-up: [Article 340-A](https://github.com/lmxxf/ai-theorys-study/blob/main/wechat/340-A.md)

**What this repository adds:**
While the upstream repository maintains fixed-offset binary patches for specific Linux `agy` builds, this project provides a **cross-platform, cross-version pure-script auto-locator (`autofix`)**:
- Parses Go `pclntab` symbol tables and getter instructions directly from the local binary to dynamically resolve function addresses and struct field offsets — **when the client auto-updates, simply re-run the script without waiting for manual offset updates**;
- Supports both **Windows (`x86_64` PE)** (**Antigravity IDE**, **`agy` CLI**, and **Antigravity Desktop**, including automatic `agy.version.json` sidecar synchronization) and **Linux (`x86_64` / `ARM64` ELF)**.

**Summary of changes (aligned with upstream):**
1. Sets `max_token_limit = 1,000,000` (resulting in an actual request limit of **`983,040` tokens** after the 65,536 output reservation) at the final config merge exit for Gemini 4 Argon High / Medium / Low;
2. Short-circuits automatic checkpoint predicate (`hooks.checkpointNeeded`) to return `(false, nil)` and uses its unreachable body for the trampoline without changing file size;
3. Raises single-file rule/skill read cap: `24,000` → `1,048,576` bytes (`1 MiB`);
4. Raises aggregate `rules` and `customizations` token budgets: `20,000` → `131,072` tokens each.

---

## Supported Targets

- **Windows (`x86_64` PE)** (auto-discovered by default):
  - `C:\Users\<User>\.gemini\bin\agy.exe` (shared backend for **Antigravity IDE** and **`agy` CLI**)
  - `C:\Users\<User>\AppData\Local\Programs\antigravity\resources\bin\language_server.exe` (**Antigravity Desktop** backend)
- **Linux (`x86_64` / `ARM64` ELF)**:
  - `~/.local/bin/agy` or `~/.gemini/bin/agy`

---

## Quick Start

### Windows (Double-Click or CLI)

1. **Read-only status check (can be run while IDE is open)**:
   Double-click `check-status.cmd`, or run:
   ```powershell
   python fix_antigravity_context.py --check
   ```

2. **One-click auto-locate & patch (re-run after client updates)**:
   Close Antigravity IDE / Desktop windows first, then double-click `fix-all.cmd`, or run:
   ```powershell
   python fix_antigravity_context.py --kill
   ```
   > Original binaries are backed up to `C:\Users\<User>\.gemini\agy-patches\`. Restart the client to take effect.

3. **Verify session SQLite database (`983040` limit)**:
   Double-click `verify-latest.cmd`, or run:
   ```powershell
   python verify_session.py
   ```

4. **Restore original binaries**:
   Double-click `restore-all.cmd`, or run:
   ```powershell
   python fix_antigravity_context.py --kill --restore
   ```

### Linux (`x86_64` / `ARM64`)

```bash
# Read-only check
python3 fix_antigravity_context.py --check --target ~/.local/bin/agy

# Auto-locate and patch
python3 fix_antigravity_context.py --target ~/.local/bin/agy

# Verify session database
python3 verify_session.py <conversation_id> --agents /path/to/AGENTS.md

# Restore original binary
python3 fix_antigravity_context.py --restore --target ~/.local/bin/agy
```

---

## Disclaimer

1. **No Proprietary Binary Redistribution**: This repository contains only original Python standard-library scripts and batch wrappers. It **does not contain or distribute** any Google Antigravity (`agy` / `language_server`) executables or archives. Do not commit `.exe`, `agy.gz`, or `.bak` binaries to version control.
2. **No Auth, Billing, or Quota Circumvention**: This tool does not modify or bypass any authentication (OAuth), permission checks, sandboxing, or server-side rate/quota limits. It only aligns local client configuration merging with the 1.0M context window advertised in the UI and adjusts local workspace rule (`AGENTS.md`) truncation thresholds.
3. **Use at Your Own Risk**: Modifying local client binaries is unofficial and may break with upstream changes. Provided strictly for personal technical research, debugging, and interoperability study.
