# antigravity-context-autofix

**[简体中文](README.md) | [English](README.en.md)**

修复 Antigravity 本地后端的 Argon High / Medium / Low 上下文窗口限制，将请求与自动压缩水位设为 **900000 tokens**（预留安全余量，避免本地字符估算偏低导致冲破云端 1048576 硬上限报 HTTP 400），**完整保留 `hooks.checkpointNeeded` 原生自动摘要压缩（`<CONTEXT_SUMMARY>`）功能**，并调整规则读取预算。同一份 Python 脚本提供自动发现、适配检查、上下文查询、确认后备份修改，以及原版恢复。仅需 **Python 3.9+ 标准库**，不分发专有二进制。

## 预期适用范围

| 系统 | 后端架构 / 格式 | 预期适用客户端 | 验证情况 |
|---|---|---|---|
| Windows | x86_64 / PE | Antigravity IDE、Antigravity Desktop、agy CLI | 本机 IDE / CLI (`agy.exe` 1.4.12 & 1.5.0) 与 Desktop (`language_server.exe` CL 1009437749 & 1013060670) 已实测修改、启动与新请求窗口 |
| Windows | ARM64 / PE | 暂不列入预期范围 | 未验证，不保证适配 |
| Linux | x86_64 / ELF | agy CLI；使用兼容后端的 IDE / Desktop 安装 | 已实现补丁支持；当前版本未完成 Linux 实机验证 |
| Linux | ARM64（aarch64）/ ELF | agy CLI；使用兼容后端的 IDE / Desktop 安装 | 已实现补丁支持；当前版本未完成 Linux 实机验证 |
| macOS | ARM64（Apple Silicon）/ 薄格式 Mach-O | Antigravity IDE、agy CLI | 本机 IDE 2.6.0 / agy 1.4.12 & 1.5.0 已实测修改、签名、启动与新请求窗口 |
| macOS | x86_64（Intel）或 Universal Mach-O | 暂不支持 | 解析器只支持薄格式 ARM64 Mach-O |

适用与否以本机后端的结构检查结果为准，不能保证所有版本。表中的客户端是预期范围，不代表每种安装布局均已实测。

### 三端架构关系（后端与会话数据库）

Antigravity 的三个客户端（IDE、Desktop App、CLI / Remote Control）在底层采用**“两套后端、两套会话数据库”交叉复用**的设计：

| 客户端形态 | 使用的 Go 后端二进制 | 使用的会话数据库目录 (`*.db`) | 共用关系说明 |
|---|---|---|---|
| **Antigravity IDE** | `~/.gemini/bin/agy(.exe)` | `~/.gemini/antigravity/conversations` | **与 CLI 共用后端**（加进 `PATH` 即可免重复安装 CLI），**与 Desktop App 共用会话数据库** |
| **Antigravity Desktop App** | 安装目录 `resources/bin/language_server(.exe)` | `~/.gemini/antigravity/conversations` | 拥有独立的 `language_server` 后端，但**与 IDE 读写同一个会话数据库**（IDE 里的对话在 App 中直接可见） |
| **agy CLI / Remote Control** | `~/.gemini/bin/agy(.exe)`（或独立安装的 `agy`） | `~/.gemini/antigravity-cli/conversations` | **与 IDE 共用 `agy` 后端**，但使用独立的 `antigravity-cli` 会话库（避免与正在运行的 IDE / App 发生 SQLite 锁冲突） |

## 如何运行

进入仓库目录执行。Windows 用 `python`，macOS / Linux 用 `python3`。

```bash
# 只检查：发现安装、检查适配、查询 IDE / CLI 最近会话
python3 fix_antigravity_context.py --status

# 正式运行：先汇总目标，只有输入 Y 才备份并修改
python3 fix_antigravity_context.py

# 恢复：先核验匹配备份，再输入 Y 恢复原始字节
python3 fix_antigravity_context.py --restore
```

也可用脚本绝对路径从任意目录运行：

```bash
python3 /你的路径/antigravity-context-autofix/fix_antigravity_context.py --status
```

Windows 可双击 `check-status.cmd`、`fix-all.cmd`、`restore-all.cmd`、`verify-latest.cmd`。包装器默认不终止进程。

## 执行流程

1. 发现当前用户默认位置、PATH 和已知应用目录的后端，解析符号链接并按真实路径去重。
2. 逐个显示路径、格式、架构、SHA256、补丁状态及是否兼容。
3. 分别查询 IDE / CLI 各自最近活跃的数据库（同时考虑主文件和 -wal 修改时间），显示实际请求上限与 executor 配置上限。不启动模型、不发送请求。
4. 修改模式下，存在不兼容或部分修改的目标时停止，不修改任何目标；可用 `--target` 只选择确认过的目标。恢复模式独立核验当前文件与备份哈希，不要求通过补丁适配检查。
5. 列出实际待修改或恢复的路径与备份目录，询问 `Continue? [y/N]`。只有明确输入 Y 才继续；回车、其他输入或无交互输入均取消。全部已修补则报告无需修改。
6. 检查同名后端进程，显示名称和 PID。关闭 IDE / CLI 后输入 Y 重查，仍占用则继续提示，其他输入取消。默认不杀进程。
7. 备份原版并核验 SHA256，在临时文件上应用补丁；Mac 自动签名并校验，记录签名后的最终哈希。替换前再次检查进程和目标哈希，避免自动升级造成误写。
8. 原子替换、更新 `agy.version.json` 缓存并复查补丁。各目标独立处理；多目标中途失败时，已完成的目标保留备份，不自动全部回滚。

`--status`、`--check`、`--dry-run` 等效，只查询、不询问、不停止进程、不修改后端。指定 `--json-out` 时会写报告文件；查询可能使用临时只读数据库副本。

Linux 通过 /proc/PID/exe 匹配所选后端真实路径，避免长进程名截断漏检；Windows / macOS 按进程名保守匹配，可能包含另一安装的同名后端。进程检测不是文件锁完整枚举。读取进程列表失败则停止修改。替换遇到占用或目录权限问题，也会提示处理后输入 Y 重试。确需自动终止进程时可使用 `--kill`，仍需先确认操作，且可能影响其他安装的同名后端。

## 如何发现安装位置

所有系统先检查当前用户主目录下的 .gemini/bin、.local/bin 及 PATH，再检查以下目录中名称含 Antigravity 的产品：

- Windows：LOCALAPPDATA/Programs、ProgramFiles、ProgramFiles(x86)。
- macOS：/Applications、~/Applications。
- Linux：/opt、/usr/share、/usr/lib、~/.local/share。

应用内只检查已知 bin、resources/bin、resources/app/bin、扩展 bin 等位置；macOS 对应 Contents/Resources。候选文件名包括 agy、language_server 及已知平台后缀名称。

**不是全盘扫描，不查其他用户。** 自定义目录、便携安装、容器、远端主机或未知布局可能漏掉，使用 `--target` 补充。该参数替代自动发现，可重复：

```bash
python3 fix_antigravity_context.py --status --target /实际路径/agy
python3 fix_antigravity_context.py --target /路径一/agy --target /路径二/language_server
```

## 状态解读与上下文查询

默认分别查这两个目录各自最近活跃的数据库（同时考虑主文件和 -wal 修改时间）：

- `~/.gemini/antigravity/conversations/*.db`（Antigravity IDE 与 Antigravity Desktop App 共用）
- `~/.gemini/antigravity-cli/conversations/*.db`（agy CLI 与 Remote Control 守护进程共用）

会话**不强行关联到某个发现的后端**，可能属于旧版本、另一安装或其他模型。最新空会话、数据库不可读、schema 变化报告 UNKNOWN。protobuf 截断、越界、非法 varint 或字段类型错误同样返回 UNKNOWN，不会验收通过。

| 状态 | 含义 |
|---|---|
| UNPATCHED / compatible=True | 当前结构和字节可匹配，尚未修补；出现已知 checkpoint 局部补丁会拒绝修改 |
| ALREADY_PATCHED / compatible=True | 磁盘已包含补丁，不代表运行中的进程已重启 |
| UNSUPPORTED_OR_UNRECOGNIZED | 当前脚本无法匹配文件格式、符号或指令 |
| UNKNOWN_OR_PARTIAL | 不能认定为完整原版或完整补丁，拒绝打补丁；恢复仍可按哈希核验 |
| LIMITED_256K | 历史请求的 gen / executor 均为 256000 |
| EXPECTED_WINDOW | gen / executor 均为 900000 或 983040（旧版补丁、重启前的历史记录可能仍是 983040） |
| MIXED_LIMITS / OTHER_WINDOW | 两处不一致或其他窗口，结合模型排查 |
| UNKNOWN | 数据不足，不能推断锁在256K或已解锁 |

修改后重开 IDE / CLI，用 **Argon High / Medium / Low** 发新请求，再查对应会话：

```bash
python3 fix_antigravity_context.py --status --conversation-id <会话UUID>
python3 fix_antigravity_context.py --status --db /实际路径/session.db

# 查询上下文 JSON：latest_limit_ok 应为 true
python3 verify_session.py <会话UUID>
python3 verify_session.py --db /实际路径/session.db
```

记录的请求窗口不等于未来请求、所有模型或超过256K的历史保留效果。切换模型后再查；已丢失/已摘要的历史不会恢复。脚本不自动发送测试请求。

## 修改内容与 Mac 签名

- Argon High / Medium / Low（当前编号1417/1418/1419）最终配置出口写入 `max_token_limit=900000`（请求与自动压缩窗口 **900000**，为本地估算与云端分词器误差预留余量，防止超过服务端 1048576 上限报 400）。
- **完整保留 `hooks.checkpointNeeded` 原版指令**（不短路自动压缩判断），改为借用全二进制零外部调用的空闲方法 `(*CheckpointConfig).SetSessionSummaryPromptOverride` 放置 46/48 字节跳板，使对话接近 900K 时自动触发原生 `<CONTEXT_SUMMARY>` 压缩。
- 规则 / skill 单文件读取上限从24000字节提高到 **1 MiB**。
- Rules / Customizations 总预算从20000各提高到 **131072 tokens**。规则预算的修改不限于三档窗口选择条件。

代码补丁保持长度；Mac 签名可能改变最终大小。使用系统 `codesign --force --sign -` 做本地 ad-hoc 签名，无需证书；签名和补丁校验通过才替换。不保留原厂开发者身份/公证信任，不关闭 Gatekeeper 或 SIP。

## 版本适配边界

感谢 [@lmxxf](https://github.com/lmxxf) 的调查与方案，以及 Antigravity IDE 对 Windows 架构梳理、定位脚本和验证的协作贡献。

- [原仓库](https://github.com/lmxxf/antigravity-context-fix)
- [ARM64 维护说明](https://github.com/lmxxf/antigravity-context-fix/blob/main/arm-linux/readme.md)
- [原始文章](https://github.com/lmxxf/ai-theorys-study/blob/main/wechat/340-A.md)

上游的绝对地址只适用于对应构建。这里通过 Go pclntab 重找函数、从 getter 解码部分字段，支持普通地址移动，以及1.4.7那类 max_token_limit +16 → +12；ARM64 模型 getter 兼容 LDR / LDRSW，x86_64 与 ARM64 的配置出口及预算赋值均兼容 1.4.12 与 1.5.0 的两种编译器布局。

**不保证所有未来版本。** 函数名、Go 表格式、指令模式、模型编号、返回约定及数据库字段仍有假设；ARM64 外层 checkpoint 指针目前要求 +16。变化超出模式时需要适配，不能删除校验或试填旧偏移；结构匹配不能替代真实请求测试。

自动升级会覆盖补丁，升级后先查状态再决定是否重打。备份按构建哈希区分，不把旧备份硬套到新版。

## 备份、参数与退出码

“原版备份”指修改前文件的逐字节备份，不是原厂身份认证。脚本校验已支持的 Go 栈检查入口指令及分支关系，并排除已知部分补丁；无法确认则停止。该检查不能证明整个二进制未被第三方修改，也不能替代厂商签名验证。

备份默认保存到用户主目录 `~/.gemini/agy-patches/`：原版 .bak 与记录原版/修改版 SHA256、补丁位置的 JSON 清单。恢复要求当前哈希匹配清单，并核验备份；不要求当前文件通过补丁适配检查，原始签名字节也会恢复。替换程序前确保原版备份写入磁盘；支持的平台同时保存备份目录变更。

```bash
python3 fix_antigravity_context.py --restore --target /实际路径/agy
python3 fix_antigravity_context.py --restore --backup-dir /备份目录 --target /实际路径/agy
python3 fix_antigravity_context.py --status --json-out report.json
```

| 参数 | 作用 |
|---|---|
| 无参数 | 自动发现、检查，确认后修改未修补目标 |
| --status / --check / --dry-run | 只检查 |
| --target PATH | 指定目标，支持重复，替代自动发现 |
| --conversation-id UUID / --db PATH | 二选一，指定查询会话 |
| --restore | 核验备份、确认并恢复；与 --json-out 一起使用可输出恢复前后哈希和备份来源 |
| --backup-dir PATH | 自定义备份与清单目录；恢复时需指定同一目录 |
| --json-out PATH | 输出本次检查/修改报告；必须使用不存在的新文件，拒绝备份目录及受保护文件类型 |
| --kill | 可选，确认后终止选中目标的同名后端进程；默认不用，可能影响其他安装的同名进程 |

检查退出码0=全部目标兼容，2=没找到或不兼容；会话窗口不影响此退出码。verify_session.py：0=验收通过，1=窗口未达标，2=无法读取数据。恢复和只读模式不能混用，没有跳过 Y 确认的无人值守选项。

## 验证与测试

实机验证范围见开头表格；该 Mac 的新请求 gen / executor 均记录为 **983040**。agy 1.5.0 ARM64 已通过临时副本修改、Mac 签名与精确恢复，并已应用到本机；修改后新会话的 request / executor 均验证为 **983040**。开发测试另覆盖重复运行、异常处理及三系统发现布局模拟。未做超过256K长会话压力测试或全部模型验证。

```bash
python3 -m unittest -v test_regressions test_status test_macos
# Mac 可选集成：只修改临时副本，提供未修补原版或原版备份
AGY_TEST_BINARY=/路径/原版备份.bak python3 -m unittest -v test_macos
```

## 使用边界

本仓库不分发 Google 专有程序，不要提交可执行文件、备份或数据库。属于非官方本地客户端修改，不涉及鉴权、计费或服务端配额绕过；不提高服务端能力。保留备份，效果以实际请求与使用验证为准。
