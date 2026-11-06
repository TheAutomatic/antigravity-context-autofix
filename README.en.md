# antigravity-context-autofix

**[简体中文](README.md) | [English](README.en.md)**

Patch the local Antigravity backend to raise the Argon High / Medium / Low request context window and auto-compaction threshold to **900000 tokens** (leaving headroom for local-vs-server tokenizer variance below the 1048576 server hard limit), **preserve native `hooks.checkpointNeeded` automatic `<CONTEXT_SUMMARY>` compaction**, and raise rule budgets. One Python script provides discovery, compatibility checks, recorded-context inspection, backup and patching after confirmation, and original-byte restoration. **Python 3.9+ standard library only.** No proprietary binaries are distributed.

## Expected compatibility

| System | Backend architecture / format | Intended clients | Validation |
|---|---|---|---|
| Windows | x86_64 / PE | Antigravity IDE, Antigravity Desktop, agy CLI | Locally verified on IDE / CLI (`agy.exe` 1.4.12 & 1.5.0) and Desktop (`language_server.exe` CL 1009437749 & 1013060670): patching, startup and new request window |
| Windows | ARM64 / PE | Outside the expected scope for now | Unvalidated; compatibility is not guaranteed |
| Linux | x86_64 / ELF | agy CLI; IDE / Desktop installations using a compatible backend | Patch support implemented; current builds have not been tested on a Linux machine |
| Linux | ARM64 (aarch64) / ELF | agy CLI; IDE / Desktop installations using a compatible backend | Patch support implemented; current builds have not been tested on a Linux machine |
| macOS | ARM64 (Apple Silicon) / thin Mach-O | Antigravity IDE, agy CLI | Patch support implemented; the IDE 2.6.0 / agy 1.4.12 & 1.5.0 runs on this machine used the earlier trampoline scheme and do **not** validate the 900000 + native-auto-compaction change |
| macOS | x86_64 (Intel) or Universal Mach-O | Unsupported | The parser only supports thin ARM64 Mach-O |

Each backend must pass local structural checks; compatibility across all versions is not guaranteed. Intended clients do not imply that every installation layout has been tested.

### Client architecture (backends vs. conversation databases)

Across Antigravity IDE, Desktop App, and CLI (`agy` / Remote Control), binaries and SQLite conversation stores are cross-shared:

| Client surface | Go backend binary | Conversation DB directory (`*.db`) | Sharing relationship |
|---|---|---|---|
| **Antigravity IDE** | `~/.gemini/bin/agy(.exe)` | `~/.gemini/antigravity/conversations` | **Shares backend with CLI** (add `~/.gemini/bin` to `PATH` to avoid a duplicate CLI install) and **shares conversation DBs with Desktop App** |
| **Antigravity Desktop App** | `<app>/resources/bin/language_server(.exe)` | `~/.gemini/antigravity/conversations` | Uses its own bundled `language_server` binary, but **shares conversation DBs with IDE** (IDE chats appear in Desktop App) |
| **agy CLI / Remote Control** | `~/.gemini/bin/agy(.exe)` (or standalone `agy`) | `~/.gemini/antigravity-cli/conversations` | **Shares `agy` backend with IDE**, but uses an isolated `antigravity-cli` DB directory (avoiding SQLite lock contention while IDE/App is open) |

## Run (Quick Launchers by OS)

The repository root provides OS-specific launchers by function, while the core Python scripts and unit tests live inside `scripts/`:

| OS | Check Status & Live Context Usage Bar (Read-Only) | Back Up & Patch All | Restore Original |
|---|---|---|---|
| **Windows** (Double-click) | `windows-check-status.cmd` | `windows-fix-all.cmd` | `windows-restore-all.cmd` |
| **macOS** (Double-click in Finder) | `macos-check-status.command` | `macos-fix-all.command` | `macos-restore-all.command` |
| **Linux** (One-line command) | `./linux-autofix.sh --status` | `./linux-autofix.sh` | `./linux-autofix.sh --restore` |

You can also invoke the Python scripts in `scripts/` directly (`python` on Windows, `python3` on macOS / Linux):

```bash
# Read-only discovery, compatibility and live session token usage report
python3 scripts/fix_antigravity_context.py --status
# Review targets and type Y before backups / patching
python3 scripts/fix_antigravity_context.py
# Verify matching backups, review targets and type Y to restore
python3 scripts/fix_antigravity_context.py --restore
```

## Workflow

1. Discover current-user default locations, PATH and known application directories. Resolve symlinks and deduplicate real paths.
2. Report each backend's format, architecture, SHA256, patch state, selected trampoline host symbol, and compatibility.
3. Report the most recently active database separately for IDE/App and CLI (considering both the main file and `-wal` mtime), showing a **live token usage progress bar (`Used / Limit tokens` and percentage)**, time since last activity, and first-prompt topic preview, followed by the **Top 5 Recent Active Conversations** leaderboard. No model launch or request is sent.
4. In patch mode, stop before changes if any selected backend is incompatible or partially patched. Use repeated `--target PATH` options to select a supported subset. Restore independently verifies current-file and backup hashes without requiring patch-parser compatibility.
5. List actual action paths and backup directory. Only explicit Y at `Continue? [y/N]` proceeds. Enter, other input and EOF cancel. If all files are patched already, exit without changes.
6. Patch mode then asks how to treat old backups: `1` (default, just press Enter) prunes backups that do not belong to the installed build after a successful patch, keeping only this build's original and manifest; `2` keeps every existing backup. No input or an unrecognised answer keeps them; restore never prunes.
7. List running backend process names and PIDs. Close the IDE / CLI and type Y to check again; cancel otherwise. Processes are not terminated by default.
8. Back up and verify original SHA256, patch a temporary file, sign / verify on macOS, and record the final hash. Recheck processes and current file hash before atomic replacement.
9. Update the version sidecar and recheck patch state. Old-version backups are pruned only when every action succeeded and step 6 chose `1`, and only for files with the same binary name whose hashes match neither the current file; debug paths and files outside the backup directory are never touched. Each backend is independent: failure midway through multiple targets does not roll back completed targets, which retain their backups.

`--status`, `--check` and `--dry-run` are equivalent read-only modes: no prompt, termination or backend writes. `--json-out` writes the requested report; database access may use a temporary read-only snapshot.

Linux matches /proc/PID/exe paths to avoid truncated process names. Windows / macOS use conservative name matching, which may include another installation. Process inspection failure stops writes; it is not exhaustive file-lock inspection. Replacement permissions / lock failures also prompt for Y to retry after fixing the issue. Automatic process termination is opt-in with `--kill` and occurs only after confirmation; same-name processes from another installation may be affected.

## Installation discovery

On every system, discovery starts with the current user's .gemini/bin and .local/bin directories and PATH, then checks Antigravity-named products in these directories:

- Windows: LOCALAPPDATA/Programs, ProgramFiles and ProgramFiles(x86).
- macOS: /Applications and ~/Applications.
- Linux: /opt, /usr/share, /usr/lib and ~/.local/share.

Within applications, discovery checks known bin, resources/bin, resources/app/bin and extension bin layouts; macOS uses Contents/Resources. Candidate names include agy, language_server and known platform variants.

Discovery is bounded, not a disk-wide scan or other-user scan. Portable copies, arbitrary paths, containers, remote hosts and unknown layouts can be missed. `--target` replaces discovery and is repeatable:

```bash
python3 scripts/fix_antigravity_context.py --status --target /actual/path/agy
python3 scripts/fix_antigravity_context.py --target /one/agy --target /two/language_server
```

## Status interpretation and live context inspection (`/context` alternative for IDE & App)

Because Antigravity IDE and Desktop App do not expose the CLI's `/context` slash command in the GUI, double-clicking `windows-check-status.cmd` / `macos-check-status.command` (or running `./linux-autofix.sh --status`) acts as a live context dashboard:

1. **Latest Session Snapshot per Surface**: Decodes both `gen_used_tokens` and `gen_max_context_tokens` from the latest turn in `gen_metadata`, rendering a color-coded progress bar (`<75%` green, `75%–90%` yellow, `>=90%` red).
2. **Top 5 Recent Active Conversations**: Ranked by real-time `.db` / `-wal` write timestamps, showing **elapsed time since last turn** (e.g. `5s ago`), **short conversation ID**, **token usage bar**, and the **first user prompt preview** from `transcript.jsonl` so you can immediately tell which open window is which.

The two conversation directories inspected by default are:

- `~/.gemini/antigravity/conversations/*.db` (shared by Antigravity IDE and Antigravity Desktop App)
- `~/.gemini/antigravity-cli/conversations/*.db` (used by `agy` CLI and Remote Control daemon)

These databases are not mapped to a particular discovered executable. They may belong to an older build, another install or another model. Empty, unreadable or changed-schema databases produce UNKNOWN. Truncated protobuf fields, overflowed varints and wrong wire types also fail parsing instead of passing acceptance.

| State | Meaning |
|---|---|
| UNPATCHED / compatible=True | Recognized original patch sites |
| ALREADY_PATCHED / compatible=True | On-disk expected patch; running processes may still use old code |
| UNSUPPORTED_OR_UNRECOGNIZED | Format, symbols or instructions cannot be matched |
| UNKNOWN_OR_PARTIAL | Neither recognized original nor complete patch; refuse patching, but hash-verified restoration remains available |
| LIMITED_256K | Both recorded request and executor limits are 256000 |
| EXPECTED_WINDOW | Both are 900000 or 983040 (older patches and turns recorded before a restart may still read 983040) |
| MIXED_LIMITS / OTHER_WINDOW | Differing limits or another window; inspect model choice |
| UNKNOWN | Insufficient evidence |

Restart the IDE / CLI after patching, send a new Argon High / Medium / Low request and inspect that conversation:

```bash
python3 scripts/fix_antigravity_context.py --status --conversation-id UUID
python3 scripts/fix_antigravity_context.py --status --db /path/session.db
python3 scripts/verify_session.py UUID
python3 scripts/verify_session.py --db /path/session.db
```

Acceptance reports `latest_limit_ok: true` when both limits match. A stored window does not prove future requests, all models or retention beyond 256K. Recheck after changing models. Lost or summarized history is not restored. No test request is sent automatically.

## Changes and signing

- At final config merge, set `max_token_limit=900000` for Argon High / Medium / Low (IDs 1417–1419) so both the request window and native auto-compaction trigger sit safely below the 1,048,576 server hard limit.
- **Keep `hooks.checkpointNeeded` 100% intact** so native automatic `<CONTEXT_SUMMARY>` compaction still triggers at 900K tokens. The 46/48-byte trampoline goes into one (*CheckpointConfig) method chosen at patch time: `SetSessionSummaryPromptOverride` first, otherwise any other `(*CheckpointConfig).*` method that nothing enters from outside (CALL/JMP and B/BL/B.cond/CBZ are checked; a jump inside the body does not count), whose address is not stored in any non-debug segment (constants and pointers inside executable segments count too; `__DWARF`/`.debug` are ignored because they list every function address), and that is large enough. The chosen symbol is written to the manifest.
- Raise per-file rule / skill cap from 24000 bytes to **1 MiB**.
- Raise rules and customizations budgets from 20000 to **131072 tokens** each. Rule budget changes are not gated by the three-model window condition.
- When the running Python (for example the Microsoft Store build) refuses `os.replace` in the target directory (WinError 6), it retries and then uses a verified in-place write with rollback; without verified rollback bytes it reports the failure instead of truncating the target.

Code edits preserve length; macOS signing may change final size. System codesign performs ad-hoc signing with `--force --sign -` on a temporary file, without a developer certificate. Signing and patch checks must pass before replacement. Vendor identity / notarization trust is not retained. Gatekeeper and SIP are not disabled.

## Updates and relocation limits

Thanks to [@lmxxf](https://github.com/lmxxf) for the investigation and patch strategy, and Antigravity IDE for collaboration on Windows architecture, relocation and verification.

- [Upstream](https://github.com/lmxxf/antigravity-context-fix)
- [ARM64 maintenance notes](https://github.com/lmxxf/antigravity-context-fix/blob/main/arm-linux/readme.md)
- [Original investigation](https://github.com/lmxxf/ai-theorys-study/blob/main/wechat/340-A.md)

Upstream absolute offsets are build-specific. This script relocates functions using Go pclntab and decodes getter field offsets, handling ordinary address movement and changes such as max_token_limit +16 to +12 in 1.4.7. ARM64 model getters support LDR and LDRSW; both x86_64 and ARM64 config exits and budget assignments support the 1.4.12 and 1.5.0 compiler layouts.

Future builds are not guaranteed. Symbols, table formats, instruction patterns, model IDs, return conventions and protobuf fields remain assumptions. The ARM64 entry check accepts both stack-check layouts (with and without the frame subtraction); an unrecognised prologue is refused unless a backup manifest or the trusted-backup path confirms the bytes. The trampoline host is chosen per build: if every `(*CheckpointConfig).*` method is referenced or too small, patching is refused with the rejection reasons and **never** falls back to short-circuiting `hooks.checkpointNeeded`. Unsupported changes require code adaptation, not old offsets or removed validation. Structural compatibility is not real-request validation.

Updates overwrite patches. Check first after upgrading, then apply as needed. Hash-specific backups cannot be forced onto a mismatching new build.

## Backups, options and exit codes

Original backups mean exact pre-patch bytes, not authenticated vendor originals. Supported Go stack-check instructions and branch targets are validated, and known partial patches are rejected. This does not authenticate the entire binary or replace vendor signature verification.

Default backup directory: `~/.gemini/agy-patches/` (relative to the Windows user profile there). Original .bak files and JSON manifests contain original / patched hashes and patch locations. Restore verifies a matching current hash and backup hash without requiring patch-parser compatibility, restoring original signature bytes too. Original backups are flushed to disk before replacement; backup directory changes are also persisted on supported platforms.

```bash
python3 scripts/fix_antigravity_context.py --restore --target /actual/path/agy
python3 scripts/fix_antigravity_context.py --restore --backup-dir /backups --target /actual/path/agy
python3 scripts/fix_antigravity_context.py --status --json-out report.json
```

| Option | Purpose |
|---|---|
| No flags | Discover, inspect, confirm and patch original targets |
| --status / --check / --dry-run | Inspect only |
| --target PATH | Repeatable explicit targets; replaces discovery |
| --conversation-id UUID / --db PATH | Choose one precise session |
| --restore | Verify backups, confirm and restore; --json-out includes before/after hashes and backup source |
| --backup-dir PATH | Custom backup / manifest directory; also required on restore if customized |
| --json-out PATH | Inspection / operation JSON report; requires a new filename and rejects backup-directory / protected file types |
| --kill | Opt-in termination of selected backend names after confirmation |

Inspection exits 0 if all selected binaries match, 2 if none found or any incompatible; session limits do not affect that code. Verification exits 0 on acceptance, 1 on limit mismatch, 2 on unavailable data. Restore and read-only modes cannot be combined. No unattended confirmation bypass is provided.

## Validation and tests

See the opening table for validation on actual installations: on Windows (`agy.exe` 1.4.12 / 1.5.0 and `language_server.exe` CL 1009437749 / 1013060670), the **900000** window patch, startup, automatic `<CONTEXT_SUMMARY>` compaction past 870K tokens, and live usage progress bars have all been verified on live sessions. On macOS (IDE 2.6.0 / agy 1.4.12 & 1.5.0 ARM64), signing and startup were verified under the earlier 983040 scheme; the 900000 + native auto-compaction scheme is covered by unit tests and awaits live Mac re-verification.

```bash
python3 -m unittest discover -s scripts -v
# Optional macOS copy-only integration; supply an original binary / backup
AGY_TEST_BINARY=/path/original.bak python3 -m unittest discover -s scripts -p test_macos.py -v
```

## Scope

Do not commit proprietary executables, backups or conversation databases. These are unofficial local-client modifications, not authentication, billing or server-quota bypasses. They do not expand server capabilities. Keep backups and verify actual requests.
