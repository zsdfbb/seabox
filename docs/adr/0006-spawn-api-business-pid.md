# ADR 0006: spawn API 与 business-pid 回传设计

> 日期：2026-08-14
> 状态：**已批准**
> 关联：`docs/arch/codewhale-integration/design.md`（阶段 0 粗设计）+ `design-spawn-api.md`（详细设计）
> 背景：CodeWhale 库级集成需 seabox 从「阻塞 execute」扩展出「非阻塞 spawn + 活句柄」，
> 覆盖前台同步 / 后台非 tty / 后台 tty 三条路径（D1-D6 已确认）。

---

## 背景

CodeWhale 现有 `ShellChild`（`std::process::Child` / portable_pty `Child`）依赖
`try_wait`/`wait`/`kill`/`id` 生命周期语义（`shell.rs:675-699`、`kill_child_process_group`）。
seabox 是**进程内 fork + pre_exec** 模型，无法委托 `std::process::Command`——`SandboxChild`
必须手写围绕现有 execute 机制。阶段 0 的目标就是这一整套库能力扩展。

设计.md 阶段 0 已有粗设计；本 ADR 记录其中两处**推翻/精确化**（A1、A2）与关键机制决策。

## 决策

| # | 决策 | 值 |
|---|---|---|
| A1 | `CommandOutput.exit_code` 类型 | **保持 `i32`**，不采纳 design.md §0.1 的 `Option<i32>`。超时用新增 `timed_out: bool` 消歧 |
| A2 | business-pid 回传机制 | **`SO_PASSCRED` + `SCM_CREDENTIALS`**（内核 recvmsg 自动附发送者 pid，按接收者 pid-ns 解释），**非** SCM_RIGHTS 传 pid（SCM_RIGHTS 只能传 fd） |
| A3 | hello 消息 | **合并单消息**：B 在 seccomp 后一次 sendmsg（SCM_RIGHTS listener-fd + SCM_CREDENTIALS pid），父侧一次 recvmsg 原子解析 |
| A4 | spawn 阻塞 | **有界阻塞**（poll ≤2s）等 hello，`kill_pid` 在 spawn 返回时确定（镜像 std::process exec-readiness） |
| A5 | socketpair 条件 | `has_deny || ns.pid`（现状仅 `has_deny`） |
| A6 | setpgid | business 进程**恒** `setpgid(0,0)`，在 seccomp **之前**（防用户 deny 清单误伤） |
| A7 | kill 粒度 | `process_group` 配置（默认 **true**）：`kill()` = `kill(-pgid)`（组）或 `kill(pid)`（单）；cmd_run 转发 SIGINT/SIGTERM 到子进程组 |
| A8 | 超时表达 | `CommandSpec.timeout: Duration → Option<Duration>`，默认 `None`（库向后兼容）；CLI 显式 `Some(30s)`；新增 `with_no_timeout()` |
| A9 | SandboxChild 形态 | 公开具体类型 + 私有 `SandboxChildImpl` trait（与 `Sandbox`/`SandboxImpl` 同构，macOS Phase 3 扩展点） |
| A10 | wait_timeout 语义 | 到期即 `kill(-kill_pid)` + reap → 返回 `ExitStatus`（137）+ `timed_out()`；签名 `io::Result<ExitStatus>` |

> **修订（2026-08-14 评审 R6）**：A10 返回形状由 `Option<ExitStatus>` 简化为 `ExitStatus`——
> 到期必杀 + reap，恒有已退出状态，`Option` 的 None 语义（"仍运行"）与「超时被杀」冲突。
> 语义不变，仅形状简化。见 `design-spawn-api.md` §4.1 + `review.md` R6。
| A11 | feature 门控 | `cli = ["dep:clap","dep:dirs"]`；`anyhow` 核心；`expand_tilde` 改 `$HOME`（dirs 移出核心路径）；`from_flag_args` 加 `#[cfg(feature="cli")]` |
| A12 | execute 捕获 | 边读边 wait 单线程 drain loop（非阻塞 pipe + poll + WNOHANG），0 额外线程 |
| A13 | worker 生命周期 | worker 仅 `has_deny` 时存在；Drop：`has_deny && !reaped` → kill+reap → join worker（确定性退出） |

## 决策理由

1. **A1（exit_code 保 i32）**：`classify_exit(exit_code: i32, …)` 签名全链依赖 i32；
   `concurrent_fork_test.rs:35` 断言 `exit_code == 0`。超时强杀后 `exit_code=137` 已有意义，
   `timed_out: bool` 显式消歧「被杀 vs 正常 137」。Option 化是纯 API 破坏，收益为零。
2. **A2（SCM_CREDENTIALS）**：pid-ns 下 business 进程 B 的 `getpid()` 返回 ns 内 pid（=2），
   **B 不知道自己的宿主 pid**，无法作为 payload 发出；SCM_RIGHTS 也只能传 fd。SO_PASSCRED
   让内核在 recvmsg 时自动附 `SCM_CREDENTIALS`，其 pid 按接收者 pid-ns 解释——seabox 父进程
   在宿主 ns，拿到 B 的宿主 pid。**已实测验证**（2026-08-14 探针：receiver 在 init ns 收到
   B 的宿主 pid 249527 而非 ns 内 pid 2）。这是唯一让 B 的宿主 pid 跨 ns 干净的通道。
3. **A3（合并消息）**：SOCK_SEQPACKET 保证一次 recvmsg 原子拿到完整消息（SCM_RIGHTS +
   SCM_CREDENTIALS），消除候选 A「pid 先/listener 后」的顺序依赖与 worker recv_fd 竞态。
4. **A4（有界阻塞 spawn）**：等 hello（B 完成 pre-exec setup 即到）换来 `kill_pid` 确定性——
   `kill()`/`wait_timeout()` 无「pid 未初始化」轮询分支。std::process::Command::spawn 本就
   阻塞在 exec-readiness pipe 上，语义一致。setup 挂起 ≤2s 后 Err（正确失败非 hang）。
5. **A5（socketpair 条件）**：B 的 pid 回传依赖该通道，pid-ns 时即使无 deny 也需建。
6. **A6（setpgid 先于 seccomp）**：setpgid/dup2 在 seccomp 安装**前**执行，用户
   `--seccomp-deny-nr` 清单（含 2/33/39 等）不会误伤这两步；`kill(-pgid)` 目标恒为 B 自建的新组，
   绝不触碰调用方终端组。
7. **A7（process_group + 信号转发）**：design.md D4 已定组杀语义（CodeWhale `kill_child_process_group`
   需要）。默认 true 时 `setpgid` 使子进程脱离终端前台组 → CLI Ctrl+C 不再直杀子进程；cmd_run
   转发 SIGINT/SIGTERM 到子进程组消解。这是「CodeWhale 集成优先 + CLI UX 兼得」的融合解。
8. **A8（Option 超时）**：现状 `timeout` 声明 30s 但从不强制，是「事实无限等待」。改
   `Option<Duration>` 后默认 `None`（不强制）保持**库**向后兼容；CLI `--timeout` 默认 30s
   显式 `Some(30s)` 变为真实强制。`Duration::ZERO` 哨兵（候选 A）语义不干净，弃用。
9. **A9（私有 impl trait）**：`Sandbox::spawn` 需跨平台（macOS Seatbelt Phase 3）；公开 struct
   持私有 trait 对象与 `Sandbox`/`SandboxImpl` 完全同构，API 层零污染，成本仅每 child 一个
   `Box<dyn>`（与现有 `Sandbox` 一致）。
10. **A10（wait_timeout 强制）**：贴近已批准 design.md「超时 → kill(-kill_pid) → reap」。
   返回 `ExitStatus`(137) + `timed_out()` 而非 `None`：None 惯例（wait-timeout crate）表示「仍运行」，
   与「超时被杀」语义冲突（评审 R6 进一步简化 Option 形状）。CodeWhale 轮询用 `try_wait()`（单次
   syscall），不需要非杀 wait_timeout。
11. **A11（feature 门控）**：唯一挖出 `dirs` 在核心路径（`expand_tilde`）依赖的候选是 A——
   不换 `$HOME` 则 `default-features=false` 仍拉 `dirs`。`anyhow` 被 lib/config/linux 全程使用，
   是核心依赖不可随 cli 走。`profile.rs` 纯 std+anyhow，归核心（不 gate）。
12. **A13（worker 生命周期）**：reap 后 join worker，确定性返回（子死 → listener POLLHUP →
   poll 返回 → worker 退出），无需超时 detach；每沙箱 ≤1 worker 线程（栈 256KB）。

## 未被选择的方案

- **SCM_RIGHTS 传 pid（design.md D3 原文）**：技术上不成立——B 不知道自己的宿主 pid、
  SCM_RIGHTS 只能传 fd。被 A2 取代。
- **reaper 兜底 kill（杀 ns init 触发内核整 ns 清理）**：杀 A（ns PID 1）可让内核 SIGKILL
  整个 pid-ns，但 `id()` 语义变成「ns init」而非「business」，且依赖 `pid_namespaces(7)`
  init 死亡清理语义。SCM_CREDENTIALS 直接给 business 宿主 pid，更贴 design.md D4 组杀意图。
- **`/proc/<P>/task/<P>/children` 反推 B 宿主 pid**：脆弱（竞态、需遍历），仅作 A2 兜底。
- **wait_timeout 返回 None 不 kill（wait-timeout crate 惯例，候选 B）**：None 语义与「超时被杀」
  冲突；CodeWhale 不需要非杀 wait_timeout（有 try_wait）。被 A10 取代。
- **`Duration::ZERO` 哨兵表「不强制」（候选 A）**：哨兵值语义不干净；`Option<Duration>` 更明确。
  被 A8 取代。
- **无条件 setpgid（候选 A/C）**：忽略 CLI Ctrl+C 回归。被 A7（+ 信号转发）取代。
- **每条消息分两次（pid ping 先、listener 后，候选 A）**：多一次 IPC + 顺序依赖。被 A3 合并。

## 未决点与风险

- **R1 process_group 默认值**：✅ **已定案（2026-08-14，采纳推荐）**——默认 **true** + cmd_run 转发
  SIGINT/SIGTERM 到子进程组。CodeWhale 开箱即得组杀；CLI Ctrl+C 由信号转发保住。
- **R2 SCM_CREDENTIALS 容器化 caveat**：实测在 init pid-ns。seabox 若部署在容器 pid-ns 内，
  内核交付的 pid 相对容器 init-ns 有效（seabox 父与子同 ns 层级 → kill() 成立）；跨 host 边界
  场景由阶段 3 探针测试兜底。
- **R3 execute 捕获 vs CLI 流式**：✅ **修订定案（2026-08-14）**——库 `execute` 捕获（CodeWhale
  结构化全量输出所需）；**cmd_run 改走 `spawn(StdioConfig::Inherit)` 保持流式 + 交互 stdin**，
  design.md 0.5「CLI 交互 stdin 变 EOF」的退化随之消解。见 design-spawn-api.md §6.5。
- **R4 `expand_tilde` 换 `$HOME` 失 getpwuid fallback**：边缘场景，注释声明。
- **R5 execute 重构回归面**：precompute 迁入 spawn + 默认 execute 重写，全量 `cargo test` +
  clippy 兜底，先于 CodeWhale 改动合入。
