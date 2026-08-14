# CodeWhale 集成 — 设计方案

> 设计时间：2026-08-14
> 状态：**已批准**（决策 D1-D6 已确认，见 `context.md`）
> 上下文：`docs/arch/codewhale-integration/context.md`

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

- `crates/tui/Cargo.toml`：`seabox = { path = "../../seabox", default-features = false }`（相对路径按 workspace 布局定）。

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

### CodeWhale（`/home/zs/OpenSrc/CodeWhale`）

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