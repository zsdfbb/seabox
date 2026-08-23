# CodeWhale 集成 — 设计方案

> 设计时间：2026-08-14
> 状态：**已批准**（决策 D1-D6 已确认，见 `context.md`）
> 上下文：`docs/arch/codewhale-integration/context.md`

> ⚠️ **基线注记（2026-08-14 修正）**：集成对象为 CodeWhale **个人 fork**（入口
> `Integration/CodeWhale` → `/home/zs/Develop/CodeWhale_seabox`，origin `zsdfbb/CodeWhale_seabox`，
> 非上游 `Hmbown/CodeWhale`）。文中文件级改动清单基于上游调研，开工前在个人 fork 上复核。

---

## 1. 背景与决策摘要

将 seabox 以 **crate 依赖（库级）** 方式集成进 CodeWhale，替换并删除 bwrap 后端，覆盖前台同步、后台非 tty、后台 tty 三条执行路径，并修复 context.md 中 P0-P2 共 7 项批判（6 项批判 + 1 项双旋钮）。

已确认决策：

| # | 决策 | 结论 |
|---|---|---|
| D1 | 集成策略 | **方案 B 库级**（`Sandbox::execute` / `Sandbox::spawn` 直连） |
| D2 | bwrap 处置 | **删除** `sandbox/bwrap.rs` |
| D3 | pid namespace | **开启**，child 经 SCM_RIGHTS 回传 business pid |

> **修正（2026-08-14，ADR 006 A2）**：D3 的「SCM_RIGHTS 回传 business pid」在技术上不成立——
> pid-ns 内 business 进程 `getpid()` 是 ns 内 pid，它不知道自己的宿主 pid；SCM_RIGHTS 只能传 fd。
> 实际机制为 **SO_PASSCRED + SCM_CREDENTIALS**（内核 recvmsg 自动附发送者 pid，按接收者
> pid-ns 解释，已实测）。详见 `docs/adr/0006-spawn-api-business-pid.md` 与 `design-spawn-api.md`。
| D4 | 后台/tty | **覆盖**（后台 `spawn`，tty `StdioConfig::Fd` + openpty） |
| D5 | SafetyLevel 收紧 | `Safe` → `network_access=false` |
| D6 | persist 服务 | 保持 DangerFullAccess 无沙箱 |

---

## 2. 阶段 0 — seabox 库能力扩展

目标：补齐 CodeWhale 集成所需的 seabox 侧能力。**本阶段不触碰 CodeWhale**。

### 0.1 `CommandOutput` 扩展（`src/lib.rs:358`）

```rust
pub struct CommandOutput {
    pub exit_code: Option<i32>,
    pub blocked_syscall: Option<(u32, u32)>,   // 现有，保留
    pub stdout: Vec<u8>,                       // NEW
    pub stderr: Vec<u8>,                       // NEW
    pub timed_out: bool,                       // NEW
}
```

### 0.2 `CommandSpec` 扩展（`src/lib.rs:279`）

- `pub stdin: Option<Vec<u8>>` + `with_stdin(Vec<u8>)`：同步执行的便捷 stdin（`execute` 内部写入管道）。
- 现状 `timeout` 字段**不强制**，本阶段改为真实强制（见 0.4）。

### 0.3 spawn API（`src/linux/mod.rs` 重构）

`execute` 拆为 `spawn` + `wait` 两段共享核心：

```rust
pub enum StdioConfig {
    Inherit,                                  // 继承父进程 fd
    Piped,                                    // 内部建 pipe，handle 持有读写端
    Fd { stdin: i32, stdout: i32, stderr: i32 }, // 预开 fd → dup2（pty slave）
}

pub struct SandboxChild {
    wait_pid: i32,        // waitpid 目标：外层链 pid1（pid ns 下阻塞至整棵树退出）
    kill_pid: i32,        // kill 目标：business 进程组（SCM_RIGHTS 回传）
    stdout: Option<OwnedFd>,   // Piped 时 Some（读端）
    stderr: Option<OwnedFd>,   // Piped 时 Some（读端）
    stdin: Option<OwnedFd>,    // Piped 时 Some（写端）
    notif_worker: UserNotifHandle,  // USER_NOTIF worker，随 child 管理生命周期
    blocked: Arc<Mutex<Option<(u32, u32)>>>,
    reaped: bool,
}

impl SandboxChild {
    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>>;  // WNOHANG 轮询
    fn wait(&mut self) -> io::Result<ExitStatus>;
    fn wait_timeout(&mut self, d: Duration) -> io::Result<Option<ExitStatus>>; // 超时 kill(-kill_pid)
    fn kill(&mut self) -> io::Result<()>;                       // kill(-kill_pid, SIGKILL)
    fn id(&self) -> u32;                                        // business pid（kill 目标）
    fn take_stdout(&mut self) -> Option<OwnedFd>;
    fn take_stderr(&mut self) -> Option<OwnedFd>;
    fn take_stdin(&mut self) -> Option<OwnedFd>;
    fn blocked(&self) -> Option<(u32, u32)>;                    // 供 ExitReason 分类
}
```

签名刻意镜像 `std::process::Child`（`try_wait`/`wait`/`kill`/`id`），使 CodeWhale 现有 `ShellChild` / `kill_child_process_group` / reader-thread 模式可直接复接。

**执行语义**：

```text
Sandbox::spawn(spec, stdio) -> SandboxChild     // fork + child_setup + worker 启动，不阻塞
SandboxChild::wait_timeout(d)                    // WNOHANG 循环；超时 → kill(-kill_pid) → reap
Sandbox::execute(spec) = spawn(spec, Piped) + wait_timeout(spec.timeout)  // 行为与现状等价
```

### 0.4 `child_setup.rs` 改动（ADR 0003 零堆约束内，纯 syscall）

1. **`setpgid(0,0)`**：business 进程（pid ns double-fork 后）建立进程组 → `kill_pid = getpid()`。
2. **stdio dup2**：在 landlock/seccomp 之后、exec 之前，按 `StdioConfig` 将 fd dup2 到 0/1/2（`-1` = 不修改）。
3. **business-pid 回传（D3）**：在现有传 USER_NOTIF listener fd 的 SCM_RIGHTS 通道上追加一条消息，携带 business pid。父侧 worker 依次读取 → 填充 `SandboxChild.kill_pid`。

顺序：`unshare → mount → chdir → NO_NEW_PRIVS → uid/gid map → hostname → landlock → seccomp(USER_NOTIF+SCM_RIGHTS) → [setpgid + dup2 stdio + 回传 pid] → execve`。

### 0.5 CLI `cmd_run`（`src/main.rs:37`）

`execute` 改为捕获 stdout/stderr 后，`cmd_run` 需把捕获输出打印回终端（stdout/stderr 分别写，保持现有交互不变）。

> **修正（2026-08-14，评审修订）**：cmd_run **不走 `execute` 捕获**，改走 `spawn(StdioConfig::Inherit)`
> 保持流式 + 交互 stdin（CLI 是给人用的门面；库 `execute` 捕获服务 CodeWhale 结构化输出）。
> 详见 `design-spawn-api.md` §6.5。

### 0.6 feature 门控

```toml
[features]
default = ["cli"]
cli = ["dep:clap", "dep:dirs"]   # 仅 CLI 二进制的解析依赖；anyhow 为核心库依赖保持常开
```

> **修正（2026-08-14 复核）**：`profile` 模块（`src/profile.rs`）是纯 std `@file` 预处理，
> 只需 std + anyhow，**不需要 serde/toml**；serde/toml 仅为 dev-dependencies（示例/测试）。
> 故 profile 归入核心库，不单独设 feature；`cli` 只 gate `clap` + `dirs`。
> `anyhow` 被 lib.rs/config.rs/linux/* 全程使用，是核心依赖，不可随 `cli` 走。

CodeWhale 依赖用 `default-features = false`，避免拉入 CLI 依赖。

### 0.7 单元/集成测试

- `CommandOutput` 新字段断言（stdout/stderr/timed_out）
- `spawn` 的 try_wait/wait/kill/wait_timeout 生命周期测试
- pid ns + `SandboxChild.kill_pid` 回传验证（`--unshare-all` 下 kill(-kill_pid) 能杀整个业务树）
- `StdioConfig::Fd` 注入测试（预开 fd → 子进程 0/1/2）
- 超时强制测试（`timeout` 到期 → timed_out + 进程组被杀）
- **全量回归**：`cargo test` + `cargo clippy -- -D warnings` + `cargo fmt`

---

## 3. 阶段 1 — CodeWhale 同步路径 + 后端替换 + 批判修复

### 3.1 新后端 `crates/tui/src/sandbox/seabox.rs`（NEW）

```rust
pub struct SeaboxSandbox;    // 实现/替代 SandboxExecutor 契约

impl SeaboxSandbox {
    fn prepare(&self, spec: &CommandSpec) -> Result<SeaboxExecEnv>;
    // 产出 seabox::SandboxConfig（landlock / ns / seccomp-deny / network 映射）
    // 产出 seabox::CommandSpec（env / chdir / stdin / timeout）
}
```

**配置映射**（bwrap → seabox，参考 context.md 语义映射表）：

| CodeWhale 策略 | seabox 配置 |
|---|---|
| `ReadOnly` / `Safe` | `--landlock /:ro` + `with_ro_bind` 覆盖 `.codewhale`/`.deepseek` 等例外（自动 mnt ns） |
| `WorkspaceWrite` | `--landlock /:ro` + 工作目录 rw |
| `network_access` | `true` = 不 unshare net；`false` = `--unshare-net` |
| `SafetyLevel::Safe`（D5） | 强制 `network_access=false` |
| seccomp deny 清单 | `with_seccomp_deny_nr(nr...)` |
| 默认隔离 | user + pid(ns) + UTS + IPC + cgroup |

### 3.2 `SandboxType` / 后端分发（`sandbox/mod.rs`）

- 新增 `SandboxType::Seabox`。
- `get_platform_sandbox_with_bwrap_preference` 改为 **Linux 默认返回 Seabox**（修复 P0-1）。
- `PUBLIC_SANDBOX_BACKENDS` 纳入 Seabox。
- `prefer_bwrap` 字段与逻辑随 bwrap 删除一并移除（修复 P2-1）；`sandbox_mode` 收敛为唯一旋钮。

### 3.3 `execute_sync_sandboxed` 分叉（`shell.rs:1592`）

- sandbox 策略有效且后端为 Seabox → `SeaboxSandbox::execute(spec)`（阻塞全权执行，返回 `CommandOutput`）。
- 无沙箱（DangerFullAccess / ExternalSandbox / persist）→ 保留现有 std::process 路径。

### 3.4 接线 `map_safety_level_to_behavior`（修复 P0-2，`policy.rs:435`）

- 在策略 → seabox 配置的映射中调用该函数，使 SafetyLevel 真正生效。
- **D5**：`SafetyLevel::Safe` 映射为 `network_access=false`。

### 3.5 拒绝检测结构化（修复 P1-2，`shell.rs:1110` `was_denied`）

- 同步路径：`ExitReason` / `blocked_syscall` 直接判定（Denied → 结构化拒绝消息），替换 stderr 文本启发式。
- `classify_exit()` 语义对齐 seabox 的 `blocked: Option<(u32,u32)>`。

### 3.6 删除 bwrap / seccomp 死代码

- 删除 `sandbox/bwrap.rs`（D2）。
- 删除 `sandbox/seccomp.rs` 死代码（修复 P1-3）——deny 清单改由 seabox `--seccomp-deny-nr` 承担。
- 清理 `bwrap` 相关依赖（如 `bwrap` 解析 crate）、测试与配置项。

### 3.7 依赖与入口

- `crates/tui/Cargo.toml`：`seabox = { path = "../../../seabox", default-features = false }`（个人 fork 与 seabox 同目录树：`/home/zs/Develop/` 下兄弟目录，`crates/tui` 上三级）。

---

## 4. 阶段 2 — CodeWhale 后台 / tty 路径

### 4.1 `ShellChild` 扩展（`shell.rs:675-699`）

```rust
enum ShellChild {
    Process(std::process::Child),          // 现有（无沙箱路径）
    #[cfg(unix)]
    Pty(portable_pty::Child),              // 现有（无沙箱 tty）
    Seabox(seabox::SandboxChild),          // NEW
}
```

- `try_wait()` / `kill()` 增加 `Seabox` 分支：`child.try_wait()` / `child.kill()`（内部 `kill(-kill_pid, SIGKILL)`）。
- `id()`（`shell.rs:329`）返回 `SandboxChild::id()`（business pid），`kill_child_process_group`（353/374）复用。
- 新增 `ShellExitStatus::from_seabox` 转换（`waitpid` 原始 status → 结构化退出码）。

### 4.2 后台非 tty（`spawn_background_sandboxed`，`shell.rs:1881`）

- sandbox 策略有效 → `Sandbox::spawn(spec, StdioConfig::Piped)`：
  - `take_stdout()/take_stderr()` → 现有 `spawn_reader_thread`（`shell.rs:725`）+ `BackgroundShell` 的 `stdout_buffer/stderr_buffer`（**job table 机制不变**）。
  - `take_stdin()` → `StdinWriter::Fd`（`Box<dyn Write>`，类似现有 `Pty` 变体）。
  - 轮询完成事件：`child.try_wait()` + `blocked()` → `ExitReason` 分类 → `exit_code` / 拒绝诊断。
- persist（D6）：仅在 DangerFullAccess 启用 → 走现有 std::process 路径，不受影响。

### 4.3 tty/PTY 路径

- CodeWhale openpty（保留 `native_pty_system` / `PtySize` / 尺寸协商逻辑）。
- `Sandbox::spawn(spec, StdioConfig::Fd { stdin: slave, stdout: slave, stderr: slave })`。
- CodeWhale 读 **pty master** fd（`combined_output` 语义天然成立——pty 单流）。
- 杀进程树：`SandboxChild::kill()` → `kill(-kill_pid)`。
- 无沙箱 tty → 保留现有 portable_pty `Pair.slave.spawn_command` 路径。

### 4.4 `was_denied`（后台）

后台完成事件用 `ExitReason` 结构化判定（同步/后台共用同一判定函数）。

---

## 5. 阶段 3 — 测试与文档

### seabox 侧（本仓库）

- 0.7 的 spawn / pid 回传 / Fd 注入 / 超时测试（见阶段 0）。
- `docs/arch/codewhale-integration/` 本组文档定稿后，归档一个 ADR：**spawn API 与 business-pid 回传设计**（可并入 `docs/adr/` 或本目录）。

### CodeWhale 侧

| 测试 | 验证点 |
|---|---|
| 同步 sandbox parity | `execute_sync_sandboxed` seabox 路径下 landlock 只读 / 例外可写 / 拒绝分类 |
| SafetyLevel 收紧 | `Safe` 命令 `network_access=false`（无法访问外部 IP，loopback 可达） |
| 后台 sandbox | `spawn` 后台任务 stdout 流式缓冲 + 完成事件 + kill 进程组 |
| tty sandbox | `StdioConfig::Fd` + master 读写，`combined_output` 一致 |
| deny 结构化 | 拦截 syscall → 结构化 `ExitReason`（非文本启发式） |
| 无 bwrap 残留 | `rg -n bwrap crates/tui` 为空 |

### 文档

- 更新 `docs/development-phases.md` Phase 4 状态（进行中）。
- 更新 CodeWhale 侧相关文档/配置说明（Linux 默认沙箱后端变更）。

---

## 6. 文件级改动清单

### seabox（`/home/zs/Develop/seabox`）

| 文件 | 改动 |
|---|---|
| `src/lib.rs` | `CommandOutput` + `CommandSpec.with_stdin` + `StdioConfig` + `SandboxChild` + `Sandbox::spawn` |
| `src/linux/mod.rs` | `execute` 拆为 spawn+wait；USER_NOTIF worker 生命周期接入 `SandboxChild`；超时强制 |
| `src/linux/child_setup.rs` | `setpgid(0,0)` + stdio dup2 + business-pid SCM_RIGHTS 回传 |
| `src/main.rs` | `cmd_run` 走 `spawn(Inherit)` 流式 + SIGINT/SIGTERM 转发（修订，见 §0.5 注记） |
| `Cargo.toml` | feature 门控 `cli`/`profile`（default 保留两者） |
| `tests/*` | 0.7 新增测试 + 全量回归 |

### CodeWhale（个人 fork：`Integration/CodeWhale` → `/home/zs/Develop/CodeWhale_seabox`）

| 文件 | 改动 |
|---|---|
| `crates/tui/src/sandbox/seabox.rs` | NEW 后端 + 配置映射 + `map_safety_level_to_behavior` 接线（D5） |
| `crates/tui/src/sandbox/mod.rs` | `SandboxType::Seabox`；Linux 默认 Seabox（P0-1）；移除 `prefer_bwrap`（P2-1） |
| `crates/tui/src/sandbox/bwrap.rs` | **删除**（D2） |
| `crates/tui/src/sandbox/seccomp.rs` | **删除**（P1-3） |
| `crates/tui/src/sandbox/policy.rs` | `SandboxExecutor` 契约接线（P1-1） |
| `crates/tui/src/tools/shell.rs` | `ShellChild::Seabox`；同步/后台/tty 分叉；`was_denied` 结构化（P1-2） |
| `crates/tui/src/config.rs` | 移除 `prefer_bwrap`；`sandbox_mode` 收敛 |
| `crates/tui/src/core/engine.rs` | 移除 `prefer_bwrap` 字段与 setter |
| `crates/tui/Cargo.toml` | `seabox` 依赖 + 清理 bwrap 依赖 |

---

## 7. 风险与回滚

| 风险 | 缓解 |
|---|---|
| `execute` 重构回归 | 阶段 0 内全量 `cargo test` + clippy + fmt，先于 CodeWhale 改动合入 |
| USER_NOTIF worker 泄漏 | `SandboxChild` Drop 时关闭 socketpair + join worker（有界超时） |
| pid ns kill 语义错误 | 阶段 0 专项测试：`--unshare-all` + 后台长任务 → kill(-kill_pid) 全树回收 |
| tty+seccomp 冲突 | 阶段 2 端到端 tty parity 测试兜底 |
| Landlock 例外翻译错漏 | 阶段 1 同步 parity 测试逐一对照 bwrap 例外清单 |
| 回滚 | 阶段按序合并，每阶段可独立 revert；bwrap 删除前确保同步路径 parity 测试通过 |

---

## 8. 集成基线测试结果（2026-08-17 复核）

> 本段记录集成开工前对 **个人 fork**（`Integration/CodeWhale` → `/home/zs/Develop/CodeWhale_seabox`，
> origin `zsdfbb/CodeWhale_seabox`）的基线复核。基线对象：fork `main`，HEAD `c9b9559a7`，
> 工作区干净且与 origin 同步（2026-08-17 `git pull` 显示已最新，无新代码）。本段**不是改动计划**——
> fork 代码未改动，下述失败均为 fork `main` 现状，待集成各阶段按序处理（见 §3-§6）。

### 8.1 环境前提（一次性，已就绪）

| 项 | 说明 |
|---|---|
| crates.io 镜像 | 本机 `static.crates.io` 直连超时 → 已配置 `~/.cargo/config.toml` 走 **USTC** sparse 镜像（实测 ~2 MB/s），影响机器所有 Rust 项目 |
| `libdbus-1-dev` | `libdbus-sys`（引入链 `codewhale-secrets → keyring → dbus-secret-service → dbus`）需系统 `dbus-1.pc`，Ubuntu 26.04 上已安装 |

### 8.2 构建

`cargo build --workspace` ✅ 通过（22 个 crate，约 2m44s）。

### 8.3 测试

本机默认 locale 为 `zh_CN.UTF-8`（i18n 会把 UI 文案翻译为中文）。基线测试命令：

```bash
LC_ALL=C LANG=C cargo test --workspace -- --skip dispatcher_diagnostics_are_in_process_and_read_only
```

| 运行条件 | 结果（codewhale-tui lib，其余 31 套件全过） |
|---|---|
| 默认 `zh_CN` locale | 10358 passed / **34 failed** |
| `LC_ALL=C` | 10381–10383 passed / **9–11 failed**（9 稳定 + 2 偶发 flaky） |

`--skip` 跳过的是 1 个本机挂死用例（见下，属环境问题，CI 不触发）。

### 8.4 失败分类

| 类别 | 数量 | 说明 | 与本机/环境关联 |
|---|---|---|---|
| locale 文案失败 | ~25 | `zh_CN` 下 i18n 输出中文文案，断言英文文案的测试失败（如 `"verifying"` ≠ `"校验中"`） | **环境**：`LC_ALL=C` 后全部消失；CI 用英文 locale 不暴露，非 fork 缺陷 |
| 挂死 1 个 | 1 | `cli/tests/diagnostic_dispatch_read_only.rs`：`env_clear` 密封 HOME 后 `doctor` 流程 spawn `rustc --version`，本机 `rustc` 为 rustup shim，在密封 HOME 找不到 toolchain 即触发下载 → 网络超时挂死 | **环境**：rustup CDN 亦超时。CI 网络正常不触发。TUI 侧同场景已有 `preserve_host_rustup_home` 正解（`crates/tui/tests/integration/diagnostic_read_only.rs:772`，re-inject `RUSTUP_HOME`），CLI 侧缺失，集成阶段可一并补 |
| 确定性失败 | 9 | reasoning-effort / provider 序列化 8 个 + unicode 过滤 1 个（详见下） | **fork `main` 现状**，与 locale 无关，各次运行稳定复现 |
| 偶发 flaky | 2 | `skills::cached_discovery_reuses_unchanged_registry_without_rewalking`、`test_support::settings_save_waits_for_foreign_state_io_transaction` | **环境**：timing / `EnvGuard` 全局环境锁并行竞争，两次运行间翻转 |

**9 个确定性失败清单**（`LC_ALL=C` 下稳定复现）：

- reasoning-effort / provider 序列化（8）：`settings::reasoning_effort_setting_normalizes_and_clears`、`terminal_mode_tests::cli_reasoning_effort_normalizes_aliases_and_rejects_typos`、`fleet::profile::profile_loader_normalizes_reasoning_aliases`、`commands::groups::config::config_reasoning_effort_uses_codex_provider_labels`、`tui::app::fixed_route_thinking_cycle_persists_raw_preference`、`tui::app::reasoning_cycle_persists_through_the_same_owner_as_the_picker`、`tui::model_picker::picker_keeps_default_when_catalog_has_no_reasoning_options`、`tui::ui::ctrl_t_key_event_reaches_reasoning_effort_cycle`
- unicode 过滤（1）：`tui::views::config_view_filter_accepts_j_k_and_unicode_case`

根因（reasoning-effort 类）：测试期望**配置存储 provider 中立的 canonical 值 `"max"`**（`xhigh`/`ultra`/`ultracode` → `max`，Codex 仅在 provider 边界把 `Max` 显示/发送为 `xhigh`），而 `ReasoningEffort::as_setting(XHigh)` 当前返回 `"xhigh"`。即测试预期与 code 现状不一致，属 fork `main` 未收敛状态。

### 8.5 复核结论

- **构建基线 ✅**；**测试基线**在 `LC_ALL=C` 下为「9 个确定性失败 + 2 个偶发 flaky + 1 个环境挂死」，均属 fork `main` 现状，非 seabox 引入。
- 集成改动面（阶段 1-2：`sandbox/*`、`tools/shell.rs`、`config.rs`、`engine.rs`）与上述失败测试的模块**无直接重叠**，集成可在此基线上叠加。
- 涉及 reasoning-effort 相关路径时需留意「配置存储应为 provider 中立 `max`」这一预期，避免新代码与其相悖。
- 每次拉取 fork 新代码后按 §8.3 命令复测，跟踪上述失败是否随 fork `main` 演进（本段是移动基线，非一次性快照）。

---

## 9. 实施状态（2026-08-22）

> 阶段 1+2 已在 **个人 fork**（`/home/zs/Develop/CodeWhale_seabox`）实施完成。
> 执行计划（T1-T9）见 `docs/exec-plans/2026-08-22-codewhale-seabox.md`，上下文注记见 `context.md`。

### 9.1 已落地（阶段 1+2）

- **三路径 seabox 化**：后台非 tty + 后台 tty + 前台（经 job table，见 §9.2）。
- **`SandboxType::Seabox`** Linux 默认后端（修复 P0-1）：`get_platform_sandbox` 直接返回 Seabox，
  `get_platform_sandbox_with_bwrap_preference` 删除；`PUBLIC_SANDBOX_BACKENDS` 更新为
  「seabox (Linux, default)」。
- **`ExecEnv.seabox: Option<SeaboxPlan>`** 载体（P1-1）：`SandboxManager::prepare()` 产出 seabox
  配置/命令规格；`DangerFullAccess` / `ExternalSandbox` → `None`；后端为 Seabox 但 `seabox.is_none()`
  → fail-closed 报错，不降级。
- **`ShellChild::Seabox(seabox::SandboxChild)`**（D4）：`process_id()` / `try_wait()` / `kill()` 委托
  （kill 走 seabox 进程组组杀）。
- **非 tty `StdioConfig::Piped`**（`take_stdout/take_stderr` → 现有 `spawn_reader_thread` + job table
  机制不变，`take_stdin` → `StdinWriter::Fd`）；**tty `StdioConfig::Fd`** + CodeWhale openpty（读 master）。
- **结构化拒绝**（修复 P1-2）：后台完成事件用 `child.blocked()`（`BackgroundShell.seabox_blocked`）判定
  `sandbox_denied`；同步/其它路径保留 `was_denied` stderr 文本兜底。
- **`map_safety_level_to_behavior` 生产接线**（修复 P0-2）：`SafetyLevel::Safe` → `network_access=false`
  （D5，`force_no_network` 钳制 `WorkspaceWrite`/`ExternalSandbox` 的 network 字段）。
- **删除** `sandbox/bwrap.rs`（D2）与 `sandbox/seccomp.rs`（P1-3）；**`prefer_bwrap` 全仓移除**
  （config / engine / acp_server / lib / frame / runtime_threads / diagnostics），
  `rg -n 'bwrap|prefer_bwrap' crates/tui` 为空。

### 9.2 fork 现实修正

生产 Bash 前台**不经过 `execute_sync_sandboxed`**——它经 `execute_foreground_via_background` → job table
（`background=true`），`execute_sync_sandboxed`（`shell.rs:1752`）**生产零调用**（仅外部/测试调用）。
因此阶段 1 的同步语义实际落在 **`spawn_background_sandboxed`**（tty 一并纳入，见 §4.2-§4.3）。
`execute_sync_sandboxed` 内 seabox 分支按 §3.3 保留（`seabox::Sandbox::execute` 全权执行），供测试/外部使用。
§3.4-§3.6 的改造面（接线 / 结构化拒绝 / 删 bwrap 与 prefer_bwrap）均落地。

### 9.3 测试摘要

| 套件 | 结果 |
|---|---|
| tui lib 全量（`LC_ALL=C`） | **9 个基线确定性失败保留**（reasoning-effort 8 + unicode 1，属 fork `main` 现状，与本次改动模块无重叠） |
| sandbox / seabox / shell 新增用例 | **全绿**：映射单元测试、分发断言改写（Seabox 默认）、三路径 parity、结构化拒绝（拒绝 syscall → `sandbox_denied==true`）、进程组 kill、tty smoke |
| integration / pty | 各有 **1 个环境挂**，与 HEAD 基线相同，已由 **stash 二分**证实与本次改动无关 |

- 新增用例对 blob 一律显式指定 `SandboxPolicy`（避免依赖默认翻转）。
- `rg -n 'bwrap|prefer_bwrap' crates/tui` 为空，N9 验收：失败集 ⊆ 基线（9 确定 + 各 1 环境挂），无新增真实回归。

### 9.4 结论

阶段 1+2 库级后端集成已完成，测试失败集 ⊆ 基线（9 确定 + 各 1 环境挂），无新增真实回归。
HTTP API 维持暂缓（2026-08 决策不变）。