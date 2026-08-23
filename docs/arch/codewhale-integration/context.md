# CodeWhale 集成 — 架构上下文

> 调研时间：2026-08-14
> 状态：**已定稿**（决策已确认）
> 配套设计：`docs/arch/codewhale-integration/design.md`

> ⚠️ **基线注记（2026-08-14 修正）**：文中 CodeWhale 沙箱架构调研（函数位置/行号）基于上游
> `Hmbown/CodeWhale`（`/home/zs/OpenSrc/CodeWhale`）探索。集成对象实为 **个人 fork**
> `CodeWhale_seabox`（入口 `Integration/CodeWhale` → `/home/zs/Develop/CodeWhale_seabox`，
> origin `zsdfbb/CodeWhale_seabox`）。阶段 1 开工前需在个人 fork 上复核。

---

## 概述

目标：将 seabox（`/home/zs/Develop/seabox`）以 **crate 依赖（库级）** 方式集成进 CodeWhale
**个人 fork**（入口 `Integration/CodeWhale` → `/home/zs/Develop/CodeWhale_seabox`，非上游），
替换并删除 Linux bwrap 后端，同时修复对 CodeWhale 沙箱调用方式的 6 项批判发现的问题。

集成范围覆盖 CodeWhale 的三条执行路径：

| 路径 | 现状 | 目标 |
|---|---|---|
| 前台同步（`execute_sync_sandboxed`） | bwrap 包装命令 | seabox 库 `Sandbox::execute`（阻塞全权执行） |
| 后台非 tty（`spawn_background_sandboxed`） | bwrap 包装 + std::process::Command | seabox 库 `Sandbox::spawn` + `SandboxChild`（live handle） |
| 后台 tty/PTY | bwrap 包装 + portable_pty | CodeWhale openpty + seabox `StdioConfig::Fd` 传 slave，读 master |

---

## 现状调研

### CodeWhale 沙箱架构（`crates/tui/src/sandbox/`）

- **包装命令模型**：`SandboxManager::prepare(CommandSpec) -> ExecEnv`，`ExecEnv.command: Vec<String>` 是「前缀包装」——bwrap/seccomp 等后端拼出 argv 前缀，最终由 `std::process::Command`（或 portable_pty）执行。seabox 是**全权执行模型**（fork + waitpid），二者是根本性的架构差异。
- **`SandboxType` 枚举**：含 `LinuxBubblewrap` 等变体；`get_platform_sandbox_with_bwrap_preference`（mod.rs:345）选择后端。
- **`prefer_bwrap: bool`**（mod.rs:395-417）：Linux 默认 `false` → **bwrap 默认不启用，Linux 沙箱默认零强制**（批判 P0-1）。
- **`PUBLIC_SANDBOX_BACKENDS`**（mod.rs:62）：对外暴露的后端清单。
- **`SandboxExecutor` trait**（policy.rs:413）：定义了 prepare 契约，但**生产代码零调用**（批判 P1-1）。

### 调用链还原（Linux）

```
authority::sandbox_policy_for_turn        authority.rs:337   ← turn 级策略决策（含 clamp）
  └─ ToolContext.elevated_sandbox_policy  engine.rs:4783/4895 ← per-tool 提升
      └─ BashTool dispatch (analyze_command) shell.rs:3646
          └─ ShellManager.execute_*       shell.rs
              └─ CommandSpec.with_policy  shell.rs:1539/1584
                  └─ SandboxManager.prepare() sandbox/mod.rs ← 最终后端分发
```

### seabox 现状（`src/`）

- `Sandbox` trait + `SandboxConfig::with_*` builder + `CommandSpec` + `CommandOutput { exit_code, blocked_syscall }` + `ExitReason`（lib.rs:394/279/358）。
- `linux/mod.rs:95` `execute()`：fork + child_setup + USER_NOTIF worker + 阻塞 waitpid。**无 stdout/stderr 捕获、无 stdin、无超时强制、无 setpgid、无 live handle**。
- `linux/child_setup.rs` `enter_child`：零堆 pre_exec 序列（ADR 0003），unshare → mount → landlock → seccomp → execve。支持 pid ns double-fork（reaper）。
- `main.rs:37` `cmd_run`：CLI 执行入口。
- Landlock 是 **allow-list**，无法表达「root 下只读、某子目录可写」的例外 → 例外目录需 `with_ro_bind` 覆盖（自动启用 mnt ns）。

---

## 代码基线验证（2026-08-14 适配前复核）

> 本段为 arch-explore 复核记录（加法式，不改动上文已定稿内容）。逐项核对
> design.md 阶段 0 对 seabox 侧代码的假设，标注已验证、可复用积木与需修正处。

### 已验证（与 design.md 一致）

| 设计假设 | 实际代码 | 结论 |
|---|---|---|
| `CommandOutput` 仅 `exit_code` + `blocked_syscall` | `src/lib.rs:358` | ✅ 缺 stdout/stderr/timed_out |
| `CommandSpec` 无 stdin、timeout 不强制 | `src/lib.rs:279`，linux/mod.rs 从不读 timeout | ✅ `timeout` 默认 30s 仅"声明" |
| `execute` = fork + 阻塞 waitpid，无捕获/无 live handle | `src/linux/mod.rs:95` | ✅ 子进程继承父进程 stdio |
| `cmd_run` 需补打印捕获输出 | `src/main.rs:37` | ✅ |
| Landlock allow-list，例外需 ro-bind 覆盖 | `src/config.rs` `with_landlock`/`with_ro_bind`（235） | ✅ |

### 已有可复用积木（降低阶段 0 工作量）

- **SCM_RIGHTS 通道完整**：子进程 `send_fd`（`child_setup.rs:334`）+ 父侧 `recv_fd` / `spawn_user_notif_worker`（`linux/mod.rs:718/813`）。business-pid 回传（D3）可复用该 socketpair，扩展载荷即可，无需新通道。
- **`UserNotifHandle`**（`linux/mod.rs:783`）+ `join()` 已存在（现 `#[allow(dead_code)]`，因 `execute` 立即 drop 句柄）——随 `SandboxChild` 管理 worker 生命周期的基础就绪。
- **pid-ns double-fork + `do_reaper(business_pid)`**（`child_setup.rs:151/300`）：reaper 已内部跟踪业务 pid，但**当前不回报父进程**——D3 只需补回传。
- **O_PATH cwd fd + fchdir**（`linux/mod.rs:237`，`child_setup.rs:189`）已就绪。

### 设计需修正（2 处）

1. **feature 门控注释错误（design.md §0.6）**：原注释 "profile = 需要 serde/toml 的 profile 加载" 与事实不符。`src/profile.rs` 是**纯 std `@file` argfile 预处理**（仅 std + anyhow，无 serde/toml）；serde/toml 只是 dev-dependencies（`examples/cli_from_toml.rs`、测试用）。且 **anyhow 是核心库依赖**（lib.rs `create_sandbox_impl`、config.rs `with_*`、linux/* 全程用），不能随 `cli` feature 走。修正方案：
   - `cli` feature 仅 gate `clap` + `dirs`；`anyhow` 保持核心（始终启用）；
   - `profile` 模块纯 std+anyhow，归入核心或 `cli` 均可。
2. **CodeWhale sandbox 目录比 design.md 枚举多文件**：`backend.rs`（外部 OpenSandbox 抽象）、`opensandbox.rs`（HTTP 适配器）、`process_hardening.rs`（**父 TUI 进程**加固）、`seatbelt.rs`+`seatbelt/`（macOS）、`windows.rs`——**均不在 seabox 替换范围**，应记入参考索引避免误删。另：`backend.rs::SandboxOutput { stdout, stderr, exit_code }` 结构与 seabox 目标 `CommandOutput` 天然对齐，可作 CodeWhale 侧映射参考。

### 实现期需明确的细节

- **spawn API 形态**：`SandboxImpl` trait 当前为**私有**（lib.rs:375），`Sandbox::spawn` 需同时上公开 `Sandbox` struct 与 trait；`SandboxChild` 需平台无关（lib 层）+ Linux 实现。
- **wait_pid vs kill_pid 语义**：pid-ns 下外层 waitpid 目标是中间进程（ns PID 1，`do_reaper` 转发退出码），`kill_pid` 是 business 进程组（需 SCM_RIGHTS 回传）；无 pid-ns 时二者同 pid。`setpgid(0,0)` 须由 business 进程（double-fork 后 / 直接 fork 子进程）调用。
- **超时强制**：`wait_timeout` 需 WNOHANG 轮询 + 到期 `kill(-kill_pid)`；`execute = spawn(Piped) + wait_timeout(spec.timeout)` 与现状行为等价。
- **cmd_run 回归面**：`execute` 改捕获后，CLI 与全部现有测试需全量回归（同 design.md 风险表）。

---

## 核心架构矛盾

| 维度 | CodeWhale 沙箱（bwrap） | seabox |
|---|---|---|
| 执行模型 | 包装命令（`ExecEnv.command` → std::process） | 全权执行（fork + waitpid 阻塞） |
| 输出捕获 | std::process 管道（CodeWhale 侧） | 无（需新增） |
| 后台 live handle | std::process::Child | 无（需 spawn API） |
| tty/PTY | portable_pty | 无（需 `StdioConfig::Fd` 配合 CodeWhale openpty） |
| 超时强制 | CodeWhale `wait_timeout` | 无（`CommandSpec.timeout` 不强制，需实现） |
| 进程组/杀进程树 | `kill_child_process_group` | 无（需 `setpgid(0,0)` + `kill(-pgid)`） |
| 拒绝诊断 | stderr 文本启发式（`was_denied`） | 结构化 `ExitReason`（blocked + mechanism） |
| 文件系统 | bind mount | Landlock ACL（allow-list，例外需 ro-bind 覆盖） |
| pid ns | `--unshare-all` 含 | 支持，但 spawn 路径需 business-pid 回传 |

---

## 批判 + 修复映射

| # | 严重度 | 批判 | 证据 | 修复 |
|---|---|---|---|---|
| P0-1 | 高 | Linux 默认零强制——bwrap 默认关闭，Linux 沙箱形同虚设 | `prefer_bwrap` 默认 `false`（config.rs:2579） | seabox 设为 Linux 默认后端；`SandboxType::Seabox`；bwrap 删除后无空窗 |
| P0-2 | 高 | 策略是 turn 级而非命令级；`map_safety_level_to_behavior` 生产零调用 | policy.rs:435 死代码；authority.rs:337 turn 决策 | 接线 `map_safety_level_to_behavior`；按 SafetyLevel 映射 `network_access` 等 |
| P1-1 | 中 | `prepare` 抽象锁死为子进程包装模型，无法承载全权执行后端 | `ExecEnv.command: Vec<String>` 前缀模型；`SandboxExecutor` 未接线 | 方案 B 库级直连 `Sandbox::execute/spawn`，绕过 wrapper |
| P1-2 | 中 | 拒绝检测是字符串启发式 | `was_denied` 匹配 stderr 文本（shell.rs:1110） | 用 seabox 结构化 `ExitReason`（blocked: Option<(u32,u32)>） |
| P1-3 | 中 | seccomp 死代码且 x86_64-only | sandbox/seccomp.rs 自述 dormant，nr 硬编码（153） | 删除；改用 seabox `--seccomp-deny-nr` 接线 |
| P2-1 | 低 | `prefer_bwrap` 与 `sandbox_mode` 双旋钮割裂 | config.rs:2558/2579 | 收敛为单一 seabox 后端 + 策略链 |
| P2-2 | 低 | 三层决策系统（authority turn → ToolContext elevated → prepare dispatch）重叠 | authority.rs → engine.rs → sandbox/mod.rs | 语义映射显式化，文档化每层职责 |

---

## bwrap / seabox 能力差表

| 能力 | bwrap（现状） | seabox（目标） | 备注 |
|---|---|---|---|
| 文件系统只读 | `--ro-bind /` | `--landlock /:ro` | 例外目录用 `with_ro_bind` 覆盖（自动 mnt ns） |
| 工作目录白名单 | bind mount | Landlock allow-list | 例外需 ro-bind |
| seccomp | 外部原始 FD | `--seccomp-deny-nr` + USER_NOTIF 诊断 | 精确拦截 |
| 网络 | `--share-net`（二选一） | `--allow-network` / `--unshare-net` 正交 | 保留宿主 netns = `network_access=true` |
| 超时 | 无 | `CommandSpec.timeout`（需实现强制） | 新增 |
| stdout/stderr 捕获 | std::process | `CommandOutput` + spawn 管道（需新增） | 新增 |
| stdin | std::process | `with_stdin` + spawn `StdioConfig::Piped`（需新增） | 新增 |
| 后台 live handle | std::process::Child | `SandboxChild`（需新增） | 新增 |
| tty/PTY | 继承 | `StdioConfig::Fd` + CodeWhale openpty | 新增 |
| 进程组 | 外部 | `setpgid(0,0)` + `kill(-pgid)`（需新增） | 新增 |
| pid ns | `--unshare-all` | 开启 + business-pid 经 SCM_RIGHTS 回传（需新增） | 决策 D3 |
| 拒绝诊断 | 文本启发式 | `ExitReason` 结构化 | 修复 P1-2 |

---

## 已定决策

| # | 决策 | 选项 | 结论 |
|---|---|---|---|
| D1 | 集成策略 | 方案 A 包装二进制 / **方案 B 库级** | **B：crate 依赖直连** |
| D2 | bwrap 处置 | 保留 / **替换删除** | **删除** `sandbox/bwrap.rs` |
| D3 | pid namespace | 默认关 / **开启 + business-pid 回传** | **开启**：child 经 SCM_RIGHTS 回传 business pid，spawn 的 `kill_pid` 用它 |
| D4 | 后台/tty 沙箱 | 暂不沙箱 / **覆盖** | **覆盖**：后台用 `Sandbox::spawn`，tty 用 openpty + `StdioConfig::Fd` |
| D5 | SafetyLevel 收紧 | 保留网络 / **Safe 去网络** | `SafetyLevel::Safe` → `network_access=false` |
| D6 | persist 服务 | 沙箱化 / **保持 DangerFullAccess 无沙箱** | 保持既有语义（persist 仅在无沙箱模式启用） |

### 语义映射（bwrap → seabox）

| bwrap | seabox |
|---|---|
| `--ro-bind /` | `--landlock /:ro` |
| 例外（`.codewhale`/`.deepseek`） | `with_ro_bind`（自动 mnt ns） |
| `--share-net`（保留宿主 netns） | 不 unshare net（`network_access=true`） |
| `--unshare-all`（含 pid） | userns + netns + UTS/IPC/cgroup + **pid ns（业务 pid 回传）** |
| 无 | `--seccomp-deny-nr <nr>...`（USER_NOTIF） |

---

## 范围外

- macOS（Phase 3）不涉及
- IP 级网络过滤（Phase 2b / eBPF）不涉及
- HTTP API / OpenSandbox 兼容（2026-08 已暂缓）不涉及
- CodeWhale 侧 Windows / OHOS 平台路径不涉及（仅 Linux + macOS bwrap 后端区域）
- persist 持久服务沙箱化（D6，保持无沙箱）

---

## 风险与注意

| 项 | 说明 |
|---|---|
| execute 重构回归面 | `execute` 拆为 spawn + wait，波及 CLI 与全部现有 seabox 测试，需全量回归 |
| USER_NOTIF worker 生命周期 | 随 `SandboxChild` 管理 join/fd 关闭，防后台长任务线程/fd 泄漏 |
| 每沙箱后台任务 1 worker 线程 | 成本可接受，文档注明 |
| tty + seccomp USER_NOTIF 并存 | pty 走 fd dup2，与 seccomp 无冲突，需端到端验证 |
| Landlock allow-list 语义 | 「root 只读 + 子目录可写」必须 ro-bind 覆盖，CodeWhale 现有 bwrap 例外配置需翻译 |
| pid ns + spawn kill | 依赖 SCM_RIGHTS 回传 business pid；kill(-pgid) 目标必须为业务进程组 |

---

## 参考文件索引

**CodeWhale（个人 fork：`Integration/CodeWhale` → `/home/zs/Develop/CodeWhale_seabox`）**：

| 文件 | 内容 |
|---|---|
| `crates/tui/src/sandbox/mod.rs` | SandboxManager / CommandSpec / ExecEnv / SandboxType 分发；`get_platform_sandbox_with_bwrap_preference`（345）；`prefer_bwrap`（395-417）；`PUBLIC_SANDBOX_BACKENDS`（62） |
| `crates/tui/src/sandbox/policy.rs` | `SandboxPolicy`（24）；`map_safety_level_to_behavior` 死代码（435）；`SandboxExecutor` trait（413，未接线） |
| `crates/tui/src/sandbox/bwrap.rs` | 待删除；`BWRAP_PATH=/usr/bin/bwrap`（47） |
| `crates/tui/src/sandbox/seccomp.rs` | 死代码，x86_64 硬编码（153），待删除 |
| `crates/tui/src/tools/shell.rs` | `ShellManager`（1358）；`execute_sync_sandboxed`（~1592）；`spawn_background_sandboxed`（1881）；`BashTool`（3317）；dispatch `analyze_command`（3646）；`was_denied`（1110）；`ShellChild` enum（675-699）；`BackgroundShell`（782） |
| `crates/tui/src/core/authority.rs` | `sandbox_policy_for_turn`（337）含 clamp（351）；`workspace_write_policy` network_access=true（368） |
| `crates/tui/src/config.rs` | `prefer_bwrap`（2579）；`sandbox_mode`（2558） |
| `crates/tui/src/core/engine.rs` | `prefer_bwrap`（399/492）；`set_prefer_bwrap` 调用（1271） |
| `crates/tui/Cargo.toml` | 需加 `seabox = { path = "../seabox", default-features = false }` |

**seabox**（`/home/zs/Develop/seabox`）：

| 文件 | 内容 |
|---|---|
| `src/lib.rs` | `Sandbox`（394）；`CommandSpec`（279，timeout 未强制）；`CommandOutput`（358）；`ExitReason` |
| `src/config.rs` | `SandboxConfig` with_* builder；`with_ro_bind`（230） |
| `src/linux/mod.rs` | `execute()`（95，fork+waitpid）；USER_NOTIF worker |
| `src/linux/child_setup.rs` | `enter_child`（零堆，ADR 0003），pre_exec 序列 |
| `src/main.rs` | `cmd_run`（37），需改打印捕获输出 |

---

## implemented on fork（2026-08-22）

> 阶段 1+2（三路径 seabox 化 + Linux 默认 Seabox + 删 bwrap/seccomp）已在个人 fork
> （`/home/zs/Develop/CodeWhale_seabox`）实施完成。实施结果详见 `design.md` §9；
> 细粒度任务（T1-T9）见实施计划 `docs/exec-plans/2026-08-22-codewhale-seabox.md`。

- **关键行号已按 fork 复核定稿**（本文件上文行号为上游探索基线，已过时，以本段为准）：
  - `execute_sync_sandboxed` → `crates/tui/src/tools/shell.rs:1752`，**生产零调用**——生产 Bash 前台经
    `execute_foreground_via_background` → job table（`background=true`），阶段 1 语义落于 `spawn_background_sandboxed`；
  - `was_denied` 同步/后台判定位于 `crates/tui/src/tools/shell.rs`（后台完成事件改用 `child.blocked()`
    结构化判定，同步/其它路径保留 stderr 文本兜底）。
- 上文「批判 → 修复映射」「参考文件索引」中 `bwrap.rs`（47）/ `seccomp.rs`（153）/ `prefer_bwrap`
  （config.rs:2558/2579、engine.rs:399/492）等行号仅作历史基线参考——相关文件与字段已删除，
  `prefer_bwrap` / `bwrap` 在 `crates/tui` 全仓无残留。