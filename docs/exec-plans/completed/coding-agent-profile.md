# 执行计划: coding-agent profile（@file argfile 预处理）

> 设计: `docs/arch/coding-agent-profile/design.md`
> 审查: `docs/arch/coding-agent-profile/review.md`
> ADR: `docs/adr/0005-profile-argfile.md`

## 设计摘要（subagent 必读）

- **机制**：`@file` flag 文本在 clap 解析前经 `src/profile.rs::preprocess()` 展开进 argv，
  走同一个 clap 解析器。**不提供内置预设**（无 `--profile`/`Profile` 类型/预设表）。
- **占位符**：`{workspace}` → 主进程 cwd、`~` → `$HOME`；仅 `@file` 来源 token
  （**含** `--bind`/`--ro-bind`/`--tmpfs` 的 SRC/DST）替换，手动 flag 原样。
  运行时 `expand_tilde`（`config.rs:545`）只兜底 landlock path 与 cwd，**不兜底 mount 路径**。
- **作用域**：只展开首个裸 `--` 之前；`--` 后命令区 `@x` 原样。command 是
  `trailing_var_arg + allow_hyphen_values`（main.rs:304），**无 `--` 时选项区 `@` 也展开**。
- **嵌套**：`@file` 内可再 `@other`，depth≤8 + 环检测。
- **错误**：`@file` 不存在 / 非 UTF-8 → `anyhow` 报错，错误含文件名。
- **测试**：`tests/profile_test.rs`，复用 `tests/landlock_test.rs` 的 OnceLock 探针跳过模板
  （`is_landlock_available` 在 landlock_test.rs:41、`landlock_probe_cached` 在 146-165）。
  profile 测试用 tempfile 写 /tmp，**不碰工程文件**。

## 任务列表

### Task 1: `src/profile.rs` 预处理 + main.rs 接入（CLI-only）

**文件**: `src/profile.rs`（新增）、`src/lib.rs`、`src/main.rs`

**改动**:
1. 新增 `src/profile.rs`：
   - `pub fn preprocess(argv: impl IntoIterator<Item = impl AsRef<OsStr>>, cwd: &Path, home: Option<&Path>) -> anyhow::Result<Vec<OsString>>`
   - 单遍扫描选项区（首个裸 `--` 前）：`@file` → 读文件（`read_to_string`，错误含文件名）→
     空白切分（支持引号/反斜杠转义/注释）→ 占位符替换 → 展开进原位
   - 占位符：`{workspace}`→cwd、`~`→home（复用 `config::expand_tilde`）
   - 嵌套 `@file`：depth≤8 + 环检测（用展开路径集合）
   - `--` 后命令区不展开；无 `--` 时选项区 `@` 也展开
2. `src/lib.rs`：`pub mod profile;`（平台无关，`pub mod config` 之后）
3. `src/main.rs`：在 `Cli::command().get_matches()`（main.rs:329）**之前**调
   `seabox::profile::preprocess(env::args_os(), &cwd, home)`，用返回的 argv 替代
   `env::args()` 进 clap。注意保留后续 `from_arg_matches` 两步法结构。

**测试**: `tests/profile_test.rs`（本任务先写纯解析类，全部无内核依赖）：
- 展开顺序：`@file` 内容插入 argv 原位
- `--` 边界：命令区 `@x` 不展开；无 `--` 时选项区 `@` 展开
- 占位符：`{workspace}`→cwd、`~`→home
- 引号/注释切分
- 嵌套：`@a`→`@b` 正常；`@a`→`@b`→`@a` 环检测报错；depth 超限报错
- 错误：缺文件 / 非 UTF-8 报错含文件名

### Task 2: 管线下沉进 lib + `SandboxConfig::from_flag_args`

**文件**: `src/config.rs`、`src/main.rs`、`src/lib.rs`、`tests/profile_test.rs`

**改动**:
1. **管线下沉**：把 `Cli`（clap derive enum）、`build_config`、`collect_mount_actions`、
   `collect_cap_actions`、`resolve_network_config`、`MountAction`/`CapAction` 相关逻辑
   从 main.rs 移入 lib（建议新 `src/cli.rs` 或并入 config.rs），main.rs 变薄为调用方。
   迁移后 CLI 行为必须零变化（现有 main.rs 单测 + tests/ 兜底）。
2. `src/config.rs` `impl SandboxConfig` 末尾（`into_sandbox` 之后）加：
   ```rust
   pub fn from_flag_args<I, S>(args: I) -> anyhow::Result<Self>
   where I: IntoIterator<Item = S>, S: AsRef<str>;
   ```
   合成 argv `["seabox", "run", ...args, "--", "true"]`，走与 CLI 同一条
   preprocess + clap 解析 + build_config 管线。
3. scalar 覆盖：给 `--uid`/`--gid`/`--chdir`/`--timeout`/`--timeout-max`/`--hostname`
   加 `.args_override_self(true)`（用户 flag 在后覆盖 `@file` 预设）；`--env` map 追加不受影响。

**测试**: `tests/profile_test.rs` 追加：
- `from_flag_args` 与 CLI 等价（同一 flag 集，两者 `SandboxConfig` 字段一致）
- 端到端：`run @p.txt -- true` 实际执行（探针式跳过，无 Landlock 等依赖则跳过）
- scalar 覆盖：`@file` 设 `--timeout 10` + 用户 `--timeout 30` → 30 生效

## 执行顺序

串行执行（每次 subagent 实现 → review subagent 审查 → 通过后下一个）：
1. Task 1（profile.rs + main.rs 接入）— 新文件为主，独立
2. Task 2（管线下沉 + from_flag_args）— 依赖 Task 1 的 preprocess

每次 subagent 派发后 orchestrator 用 `Read` 验证文件已写入，不信任返回消息。
