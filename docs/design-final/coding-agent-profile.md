# coding-agent profile（`@file` argfile 预处理）

> 状态：**已实现**
> 日期：2026-08-11
> 来源：`docs/arch/coding-agent-profile/`（context.md + design.md + review.md）+ `docs/adr/0005-profile-argfile.md`
> 模块：`src/profile.rs`（新增）/ `src/cli.rs`（新增，下沉）/ `src/config.rs` / `src/main.rs` / `src/lib.rs`
> 测试：`src/profile.rs`（18 单测）+ `tests/profile_test.rs`（7 集成）

---

## 1. 目标（D1-D8）

| # | 目标 |
|---|---|
| D1 | profile = **`@file` flag 文本**（argfile 模式），展开进 argv 走同一 clap 解析器 |
| D2 | 展开在 clap 解析**之前**单遍预扫描；`--` 之后命令区不展开 |
| D3 | 合并：`@file` 在前、用户 flag 在后；scalar 用 `args_override_self` 后者覆盖 |
| D4 | 占位符：`{workspace}` → 主进程 cwd、`~`/`~/`/`~:` → `$HOME`；**含 mount SRC/DST 全 token 替换** |
| D5 | **不提供内置预设**：无 `--profile NAME` / `Profile` 类型 / 预设表 |
| D6 | 嵌套 `@file` depth≤8 + 环检测 |
| D7 | 管线下沉：`Cli`/`build_config`/`collect_*` 从 main.rs 进 lib，`from_flag_args` 复用同一解析器 |
| D8 | 不引入新依赖；serde/toml 保持 dev-dependency |

## 2. 实现说明

### 2.1 `src/profile.rs`（新增）

- `pub fn preprocess(argv, cwd, home) -> Result<Vec<OsString>>`：单遍扫描选项区（首个裸 `--` 前），
  展开 `@file`（`read_to_string` + 空白切分，支持引号/反斜杠转义/`#` 注释），
  嵌套展开（depth≤8 + canonicalize 环检测），占位符替换
- 占位符替换仅作用于 `@file` 来源 token，手动 flag 原样
- 已核实：运行时 `expand_tilde` 只兜底 landlock path 与 cwd，**不兜底 mount 路径**——
  profile 替换必须覆盖所有 token（含 `--bind`/`--ro-bind`/`--tmpfs` 的 SRC/DST）

### 2.2 `src/cli.rs`（新增，管线下沉）

- 收纳 `Cli` clap derive 枚举、`collect_mount_actions`/`collect_cap_actions`（indices_of 保序）、
  `resolve_network_config`、`build_config`（自原 main.rs，行为零变化）
- `pub fn parse_run(cli, run_matches) -> (SandboxConfig, RunSpec)`：CLI 与 crate API 共享的解析管线
- `pub fn config_from_flag_args(args) -> SandboxConfig`：合成 `["seabox","run",...args,"--","true"]` argv →
  `profile::preprocess` → clap → `parse_run` → 取 config
- `#[command(args_override_self = true)]`：scalar（`--uid`/`--chdir`/`--timeout` 等）重复时后者覆盖；
  Vec（`--landlock`/`--bind`/`--env` 等）保持追加

### 2.3 `src/config.rs` / `src/main.rs` / `src/lib.rs`

- `SandboxConfig::from_flag_args(args)`（config.rs impl 末尾，委托 `cli::config_from_flag_args`）
- main.rs 变薄为 ~80 行：preprocess → clap → `parse_run` → `cmd_run(config, spec)` → execute
- lib.rs 注册 `pub mod cli; pub mod profile;`

## 3. 使用方式

```bash
# CLI：@file 提供 flag 文本（内容由使用方决定，seabox 不内置预设）
seabox run @dev.profile -- cargo build
```

```rust
// Crate API：走同一解析管线
use seabox::config::SandboxConfig;
let config = SandboxConfig::from_flag_args(["--landlock", "/:ro", "--unshare-all"])?;
```

```txt
# dev.profile 示例（占位符：{workspace}→cwd、~→$HOME）
--landlock '/:ro'
--landlock '/tmp:rw'
--landlock '{workspace}:rw'
--unshare-all
--allow-network
```

## 4. 关键决策与权衡

- **不做内置预设**（2026-08-11）：机制与内容解耦，内容责任归使用方；省去 `--profile` flag 与预设表
- **不引 serde**：内容结构不做，`@file` 文本解析手写即可（GCC/rustc response-file 惯例）
- **管线下沉**（D7）：`from_flag_args` 复用同一 clap 解析器，避免 CLI/crate 双语义漂移
- **否决 4 类型抽象**（registry + 2 trait + ArgSource）：占位符仅 2 个、来源仅 1 种，trait 化过重

## 5. 测试

| 位置 | 数量 | 覆盖 |
|------|------|------|
| `src/profile.rs` 单测 | 18 | 展开顺序/`--` 边界/无 `--` 展开/占位符/引号注释/嵌套/环/深度/缺文件/空文件 |
| `tests/profile_test.rs` | 7 | `from_flag_args` 与 CLI 等价、`{workspace}`/`~` 占位符、scalar 覆盖、嵌套复用、缺文件、端到端 |

全量：`cargo test` 199 通过、`cargo clippy -- -D warnings` 零警告、`cargo fmt` 合规。

## 6. 已知限制

- `@` 前缀歧义：选项区某 flag 值以 `@` 开头会误判为 file（罕见，R3）
- `--` 边界：无 `--` 时选项区 `@` 也展开（trailing_var_arg 语义，测试已固化）
- 占位符仅 `@file` 来源替换，手动 flag 写 `{workspace}` 不会展开（文档约定）
