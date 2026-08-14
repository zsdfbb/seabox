# 2026-08-14 阶段 0 spawn API 执行计划

> 模式：quick（设计已定稿，exec-plan 直接引用）
> 设计：`docs/arch/codewhale-integration/design-spawn-api.md`（已批准，13 决策 + 评审落地）
> ADR：`docs/adr/0006-spawn-api-business-pid.md`（已批准）
> 上下文：`docs/arch/codewhale-integration/context.md` / `review.md`
> 硬约束：ADR 0003（fork→exec 零堆）；execute 行为等价（回归面）；签名镜像 std::process::Child

## 上下文引用

参考设计：`docs/arch/codewhale-integration/design-spawn-api.md`（§4 接口签名 / §5 child_setup 改动 / §6 数据流 / §7 feature 门控 / §10 测试 / §12 文件清单）。**Phase 3 每个 impl subagent 必须读它。**

## 任务清单

### Task 1: src/linux/child_setup.rs — ChildIo + setpgid/dup2/send_hello [type=impl]
- **涉及文件**: `src/linux/child_setup.rs`, `src/linux/mod.rs`（enter_child 调用点）
- **描述**: enter_child 新增按值传参 `ChildIo`（repr(C) POD：stdin_fd/stdout_fd/stderr_fd/setpgid/report_pid，全 i32）。在 pid-ns double-fork 之后、fchdir 之前插入 `setpgid(0,0)` + `dup2` stdio（seccomp **之前**，防 deny 误伤）；在 seccomp USER_NOTIF 之后、plain BPF 之前插入 `send_hello(child_sock_fd, listener_fd)`（复用现有 `send_fd`，扩展支持 `fd=-1` bare ping）；socket close 从 seccomp 分支移出收敛到 send_hello 后。
  **本任务 caller 传全关默认 `ChildIo`（-1/-1/-1/0/0）→ 行为与现状完全等价**，真值由 Task 3 接线。
- **验证方法**:
  - `cargo check` — 期望通过
  - `cargo test --test namespace_test` / `--test mount_test` / `--test seccomp_test` — 期望全过（行为等价回归）
- **关联测试任务**: T5, T6

### Task 2: src/lib.rs + src/child.rs — 类型层扩展 [type=impl]
- **涉及文件**: `src/lib.rs`, `src/child.rs`（新文件）, `src/main.rs`（CommandSpec 构造点）, `tests/landlock_test.rs`（L782 CommandSpec 构造）, `examples/cli_basic.rs` / `examples/crate_api.rs`
- **描述**: 新增 `StdioConfig`（Inherit/Piped/Fd{stdin,stdout,stderr}）、`SandboxChild`（公开 struct，持 `Box<dyn SandboxChildImpl>`）+ `pub(crate) trait SandboxChildImpl`（try_wait/wait/wait_timeout/kill/id/take_stdout/take_stderr/take_stdin/blocked/timed_out）。`CommandSpec` 加 `stdin: Option<Vec<u8>>` + `with_stdin()`；`timeout: Duration → Option<Duration>`，Default 改 `None`，`with_timeout` 包 `Some`，新增 `with_no_timeout()`。`CommandOutput` 加 `stdout: Vec<u8>`/`stderr: Vec<u8>`/`timed_out: bool`（`exit_code` 保持 i32）。`src/child.rs` 新建 `run_to_output()`（本轮可先放空壳/最小实现，Task 3 填真）。**修复所有 `CommandSpec{...}` struct literal 构造点**（main.rs L46、landlock_test L782、examples）补 `stdin`/`timeout` 新形状。`linux/mod.rs:366` 的 `CommandOutput` 构造补新字段（本轮 execute 仍走旧阻塞路径，stdout/stderr 置空、timed_out=false，行为等价）。`SandboxChild`/`StdioConfig` 定义先建好可 unused（允许 `#[allow(dead_code)]`，Task 3 接线后移除）。
- **验证方法**:
  - `cargo build` — 期望通过
  - `cargo test` — 期望既有测试全过（行为等价）
  - `cargo clippy -- -D warnings` — 期望通过（dead_code 可 allow）
- **关联测试任务**: T5, T6
- **依赖**: T1（无强依赖，可并行，但 enter_child 签名已定以 T1 为准）

### Task 3: src/linux/mod.rs — spawn 重构核心 [type=impl]
- **涉及文件**: `src/linux/mod.rs`, `src/linux/seccomp.rs`（如需要改签名）, `src/child.rs`, `src/lib.rs`（SandboxImpl trait）
- **描述**: 这是核心重构。把 `LinuxSandbox::execute` 拆为 `spawn` + wait 两段共享核心：
  1. `LinuxSandbox::spawn(spec, stdio) -> SandboxChild`：precompute（现 execute 第 1–4 步迁入）→ socketpair 条件扩为 `has_deny || ns.pid` + 父端 `setsockopt(SO_PASSCRED)` → Piped 建 3 条 `pipe2(O_CLOEXEC)` → fork → `recv_hello`（poll ≤2s 有界阻塞，拿 `Hello{listener_fd, business_pid}`）→ 错误路径 kill(wait_pid)+waitpid 清理（R1）→ has_deny 时 spawn worker（按值收 listener fd）→ 组装 `LinuxChild`。
  2. `LinuxChild` 实现 `SandboxChildImpl`：字段按设计 §4.2（`reaped: Option<ExitStatus>` 合并、无 `has_deny`、`notif_worker: Option`）。`try_wait`/`wait` 幂等（reaped 返回缓存）；`wait_timeout` 到期 kill(-kill_pid)+reap 返回 ExitStatus（R6）；`kill` 按 `process_group` 用 kill(-pgid) 或 kill(pid)；Drop 语义（has_deny && !reaped → kill+wait+join worker）。
  3. `SandboxImpl` trait 加 `spawn` + `execute` 默认实现（调 `run_to_output`）；`LinuxSandbox` 实现 spawn。
  4. `src/child.rs` `run_to_output` 真实现：spawn(Piped) + stdin 非阻塞写 + 边读边 wait drain loop（0 线程）+ wait_timeout + 组装 CommandOutput。
  5. **接线 Task 1 的 ChildIo 真值**：setpgid=1、stdio dup2 传 pipe/fd、report_pid 按 need_sock。business-pid 经 SCM_CREDENTIALS 回传。
  6. `Sandbox::spawn` 公开方法。`cmd_run` 暂保持 `execute`（Task 4 再改 spawn(Inherit)）。
- **验证方法**:
  - `cargo build` — 期望通过
  - `cargo test` — 期望既有测试全过（execute 行为等价）
  - `cargo clippy -- -D warnings` — 期望通过
  - 手测：`cargo run -- run --landlock '/:ro' -- cat /etc/passwd` — 期望正常输出退出 0
- **关联测试任务**: T5, T6
- **依赖**: T1, T2

### Task 4: Cargo.toml + cmd_run — feature 门控 + 流式 CLI [type=impl]
- **涉及文件**: `Cargo.toml`, `src/config.rs`, `src/lib.rs`, `src/main.rs`
- **描述**: 
  1. `Cargo.toml`：`[features] default=["cli"]`、`cli=["dep:clap","dep:dirs"]`；clap/dirs 改 optional；`[[bin]] required-features=["cli"]`。anyhow/libc/landlock 保持核心。
  2. `src/config.rs` `expand_tilde`（L559）：`dirs::home_dir()` → `std::env::var_os("HOME")`（dirs 移出核心路径）；`from_flag_args` 加 `#[cfg(feature="cli")]`。
  3. `src/lib.rs`：`#[cfg(feature="cli")] pub mod cli;`。
  4. `src/main.rs` `cmd_run`：改 `sandbox.spawn(&command, StdioConfig::Inherit)` + `wait_timeout`（流式 + 交互 stdin 恢复，§6.5）；`timed_out` → eprintln + exit 124；`blocked()` → 结构化拒绝诊断；**SIGINT/SIGTERM 转发**（`static CHILD_PGID: AtomicI32` + handler `kill(-pgid, sig)` + `_exit(128+sig)`，职责限 CLI）。
- **验证方法**:
  - `cargo build --no-default-features` — 期望 lib 可编、bin 不编
  - `cargo build`（默认 features）— 期望通过
  - `cargo test` — 期望全过
  - 手测流式：`cargo run -- run -- sh -c 'for i in 1 2 3; do echo $i; sleep 0.2; done'` — 期望逐行实时输出
  - 手测超时：`cargo run -- run --timeout 1 -- sleep 100` — 期望 ~1s 后 exit 124
- **关联测试任务**: T6
- **依赖**: T2, T3

### Task 5: tests/spawn_test.rs — spawn API 功能测试 [type=test]
- **涉及文件**: `tests/spawn_test.rs`（新文件）
- **描述**: 按设计 §10 覆盖 Task 1/2/3 的功能：
  execute_captures_stdout_stderr / execute_with_stdin_large（>64KB）/ execute_timeout_enforced / with_no_timeout_runs / spawn_try_wait_wait_idempotent / wait_twice_idempotent / **spawn_setup_failure_no_leak**（R1）/ wait_timeout_kills_group / **pid_ns_id_is_business_host_pid**（SCM_CREDENTIALS）/ **pid_ns_kill_group** / stdio_fd_inject / take_fds_manual_read / spawn_blocked_classify。
- **验证方法**:
  - `cargo test --test spawn_test -- --nocapture` — 期望全过
  - `cargo test --test spawn_test pid_ns_kill_group -- --nocapture` — 期望 pid-ns 杀树验证通过
- **关联 impl**: T1, T2, T3

### Task 6: tests/leak_test.rs + 全量回归 [type=test]
- **涉及文件**: `tests/leak_test.rs`（新文件）, `tests/landlock_test.rs`（L812 注释更新）
- **描述**: 资源专项（fd_steady / threads_steady / no_zombie / drop_kill_no_deny_reaps / pid_only_no_thread）+ `cmd_run_sigint_forward`（CLI 二进制发 SIGINT → 子进程组被收）+ 更新 landlock_test.rs:812「CommandOutput 不含 stdout」过时注释。**全量回归**：全部既有测试（config/deny_detect/landlock/seccomp/namespace/mount/network/concurrent_fork/capability/profile）。
- **验证方法**:
  - `cargo test --test leak_test -- --nocapture` — 期望全过
  - `cargo test` — 期望全过（10 个既有测试文件 + 2 个新文件）
  - `cargo clippy -- -D warnings` — 期望通过
  - `cargo fmt --check` — 期望通过
  - `cargo build --no-default-features` — 期望 lib 可编
- **关联 impl**: T1, T2, T3, T4

## 验证清单

- [ ] 所有 (impl, test) 配对均已 completed（T1→T5/T6、T2→T5/T6、T3→T5/T6、T4→T6）
- [ ] `cargo build`（默认 features）— 通过
- [ ] `cargo build --no-default-features` — 通过（lib 可编、bin 不编）
- [ ] `cargo test` — 全部通过
- [ ] `cargo clippy -- -D warnings` — 通过
- [ ] `cargo fmt --check` — 通过
- [ ] 手测：流式输出 / 超时 exit 124 / landlock 只读拒绝
