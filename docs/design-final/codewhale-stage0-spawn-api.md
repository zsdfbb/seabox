# 阶段 0 spawn API — 设计方案（定稿）

> 设计时间：2026-08-14
> 状态：**已实现**（Task 1-6 完成，全量测试绿）
> 前置文档：`docs/arch/codewhale-integration/design-spawn-api.md`（13 决策 + 接口签名 + 数据流）
> \+ `docs/arch/codewhale-integration/review.md`（评审报告，R1/R2/R3/R6 已采纳）+ `docs/adr/0006-spawn-api-business-pid.md`（决策记录）

---

## 1. 背景与目标

seabox 原模型是「阻塞 `Sandbox::execute`」：fork + 全 pre-exec setup + 等整个进程树退出，
返回 `(CommandOutput, ExitReason)`。CodeWhale 库级集成需要三条执行路径——前台同步 /
后台非 tty / 后台 tty——它们的共同基座是**非阻塞 spawn + 活句柄**（`try_wait` / `wait` /
`wait_timeout` / `kill` / `id` / `take_*`），镜像 `std::process::Child` 生命周期语义。

阶段 0 即这套库能力扩展。两个核心难点：

1. **business-pid 跨 pid-ns 回传**：pid-ns 下 business 进程 B 的 `getpid()` 返回 ns 内 pid（=2），
   B 自己不知道宿主 pid，`kill` / `id` 无法以 ns 内 pid 为锚。设计草案 D3 的
   「SCM_RIGHTS 传 pid」技术上不成立（SCM_RIGHTS 只能传 fd），实现改走
   **SO_PASSCRED + SCM_CREDENTIALS**（内核 recvmsg 时自动附发送者 pid，按接收者 pid-ns 解释）。
2. **超时强制从「声明」变「真实」**：原 `CommandSpec.timeout` 声明 30s 但从不强制，改
   `Option<Duration>` 后库默认 `None`（不强制，向后兼容），CLI `--timeout` 显式 `Some(30s)`
   变为真实 kill 语义。

---

## 2. 最终 API（以实现为准）

所有签名摘录自 `src/lib.rs` / `src/child.rs` 的真实实现（不是设计草案旧签名）。

### 2.1 `src/lib.rs`

```rust
/// 子进程标准流配置。恰好覆盖 CodeWhale 三条执行路径。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdioConfig {
    Inherit,                                       // 继承父进程 0/1/2，零额外 fd
    Piped,                                         // 内部 pipe；take_* 取出
    Fd { stdin: i32, stdout: i32, stderr: i32 },   // 预开 fd → dup2；-1 = 不修改
}

pub struct CommandSpec {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub env: HashMap<String, String>,
    pub timeout: Option<Duration>,  // None = 不强制（库默认）；CLI 显式 Some(30s)
    pub stdin: Option<Vec<u8>>,     // execute 内部写；spawn 忽略（D-A8）
}
impl CommandSpec {
    pub fn with_timeout(mut self, timeout: Duration) -> Self;   // Some(d)
    pub fn with_no_timeout(mut self) -> Self;                   // None（清除）
    pub fn with_stdin(mut self, data: impl Into<Vec<u8>>) -> Self;
    // …with_program / with_args / with_cwd / with_clearenv / with_env / with_unsetenv（现状）
}

pub struct CommandOutput {
    pub exit_code: i32,                       // D-A1：保持 i32（128+sig 约定）
    pub blocked_syscall: Option<(u32, u32)>,  // seccomp USER_NOTIF 拦截 (nr, arch)
    pub stdout: Vec<u8>,                      // NEW：execute 捕获
    pub stderr: Vec<u8>,                      // NEW
    pub timed_out: bool,                      // NEW：超时被强杀消歧
}

/// 平台无关沙箱子进程句柄。刻意镜像 std::process::Child。
pub struct SandboxChild { inner: Box<dyn SandboxChildImpl> }
impl SandboxChild {
    pub fn try_wait(&mut self)     -> io::Result<Option<ExitStatus>>; // WNOHANG；reaped 后幂等
    pub fn wait(&mut self)         -> io::Result<ExitStatus>;         // 幂等（防 ECHILD）
    pub fn wait_timeout(&mut self, d: Duration) -> io::Result<ExitStatus>;
    //   到期 kill(-pgid) + reap → 返回已退出状态（SIGKILL=137）；timed_out() 查询
    //   评审 R6：返回 ExitStatus 而非 Option——到期必杀+reap，恒有已退出状态，None 语义混淆
    pub fn kill(&mut self)         -> io::Result<()>;  // process_group ? kill(-pgid) : kill(pid)；ESRCH 视为 Ok
    pub fn id(&self)               -> u32;             // business 宿主 pid（= kill 目标）
    #[cfg(unix)] pub fn take_stdout(&mut self) -> Option<OwnedFd>;
    #[cfg(unix)] pub fn take_stderr(&mut self) -> Option<OwnedFd>;
    #[cfg(unix)] pub fn take_stdin(&mut self)  -> Option<OwnedFd>;
    pub fn blocked(&self)          -> Option<(u32, u32)>;
    pub fn timed_out(&self)        -> bool;
}

/// 后端抽象（私有 trait，与 SandboxImpl 同构，macOS Phase 3 扩展点）。
pub(crate) trait SandboxChildImpl: Send { /* 与 SandboxChild 公开方法 1:1 */ }

trait SandboxImpl: Send + Sync {          // 仍私有
    fn spawn(&self, spec: &CommandSpec, stdio: StdioConfig) -> anyhow::Result<SandboxChild>;
    fn execute(&self, spec: &CommandSpec) -> anyhow::Result<CommandOutput> {
        crate::child::run_to_output(self.spawn(spec, StdioConfig::Piped)?, spec)  // 默认实现，写一次
    }
    fn classify_exit(&self, exit_code: i32, blocked: Option<(u32, u32)>) -> ExitReason;
}

impl Sandbox {
    pub fn from_config(config: SandboxConfig) -> anyhow::Result<Self>;
    pub fn spawn(&self, spec: &CommandSpec, stdio: StdioConfig) -> anyhow::Result<SandboxChild>;
    pub fn execute(&self, spec: &CommandSpec) -> anyhow::Result<(CommandOutput, ExitReason)>;
    // 签名不变；超时在 Sandbox::execute 里补一条：timed_out → reason = InternalError("…timed out…")
    pub fn classify_exit(&self, exit_code: i32, blocked: Option<(u32, u32)>) -> ExitReason;
}
```

`ExitStatus` 复用 std：`std::os::unix::process::ExitStatusExt::from_raw(status)`（稳定 API）。

### 2.2 `src/linux/mod.rs` — `LinuxChild`

```rust
pub struct LinuxChild {
    wait_pid: i32,                    // waitpid 目标：pid-ns 下是中间进程 P，阻塞至整树退出
    kill_pid: i32,                    // business 宿主 pid（SCM_CREDENTIALS；无 pid-ns 时 = fork pid）
    stdout: Option<OwnedFd>, stderr: Option<OwnedFd>, stdin: Option<OwnedFd>,
    blocked: Arc<Mutex<Option<(u32, u32)>>>,
    notif_worker: Option<UserNotifHandle>,  // Some ⟺ has_deny（无 deny 无 worker，省线程）
    reaped: Option<ExitStatus>,       // None=未收割；Some=try_wait/wait/wait_timeout 幂等缓存
    timed_out: bool,
    process_group: bool,              // config.process_group，默认 true
}
```

### 2.3 `src/linux/child_setup.rs` — `ChildIo`（POD，零堆）

```rust
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ChildIo {
    pub stdin_fd: i32,    // -1 = 不修改（Inherit / Fd(stdin:-1)）
    pub stdout_fd: i32,
    pub stderr_fd: i32,
    pub setpgid: i32,     // 0 = 否；1 = setpgid(0,0)（seccomp 之前）
    pub report_pid: i32,  // 0 = 否；1 = send_hello（has_deny || ns.pid 时）
}
```

`enter_child` 尾部新增按值传参 `child_io: ChildIo`（无指针、无堆，ADR 0003 约束保持）。

### 2.4 hello 协议原语（类型化封装，调用方不碰 cmsg）

```rust
/// 一次 recvmsg 原子拿到的完整 hello（SOCK_SEQPACKET 保证边界）。
struct Hello {
    listener_fd: Option<OwnedFd>,   // has_deny 时 Some；bare ping 时 None
    business_pid: i32,              // B 宿主 pid（内核经 SO_PASSCRED 按接收者 pid-ns 翻译）
}

fn send_hello(socket_fd: RawFd, listener_fd: RawFd) -> Result<(), ()>; // listener_fd=-1 = bare ping
fn recv_hello(sock: RawFd) -> std::io::Result<Hello>;                  // poll ≤2s 有界等待
```

---

## 3. 关键机制

### 3.1 business-pid 回传 = SO_PASSCRED + SCM_CREDENTIALS（实测验证）

pid-ns 下 business B 的 `getpid()` 返回 ns 内 pid，**B 无法把宿主 pid 作为 payload 发出**。
正确机制：socketpair 父端 `setsockopt(SO_PASSCRED)`，内核在每次 recvmsg 时自动附
`SCM_CREDENTIALS`，其 `pid` 字段按**接收者 pid-ns** 解释——seabox 父进程在宿主 ns，
拿到 B 的宿主 pid。

**实测**（2026-08-14 探针：userns→pidns→双层 fork→SO_PASSCRED）：
`SCM_CREDENTIALS.pid = 249527`（business 宿主 pid，而非 ns 内 pid 2）。集成测试
`pid_ns_id_is_business_host_pid` 进一步断言：`id()` 的 `/proc/<id>/status` NSpid
最外层列 == `id()` 且 ns 内 pid == 2（reaper 是 ns PID 1）——任何回传 bug 都能抓住。

### 3.2 spawn 有界阻塞 + recv_hello 合并单消息

- `need_sock = has_deny || ns.pid` 时建 `socketpair(AF_UNIX, SOCK_SEQPACKET)`，父端 SO_PASSCRED。
- child 在 seccomp USER_NOTIF 装好后、plain BPF 前，**一次 sendmsg**（`send_hello`）交付：
  iov 1B `0x42` + SCM_RIGHTS(listener 或 -1 bare ping) + SCM_CREDENTIALS（内核自动附）。
  父侧 `recv_hello` **一次 recvmsg** 原子解析 `(listener_fd, business_pid)`（cmsg 缓冲 64B，
  SCM_RIGHTS `CMSG_SPACE(4)=24` + SCM_CREDENTIALS `CMSG_SPACE(12)=24` = 48B 足够）。
- spawn 是**有界阻塞**（`recv_hello` poll ≤2s 等 B 完成 pre-exec setup），换来 `kill_pid`
  在 spawn 返回时**已确定**——`kill()`/`wait_timeout()` 无「pid 未初始化」竞态，镜像
  `std::process::Command::spawn` 的 exec-readiness 语义。

### 3.3 R1：spawn 错误路径清理

`recv_hello` 失败（poll 超时 / EOF / 错误）时，fork 已产生子进程——返回 `Err` 前先
`kill(wait_pid, SIGKILL)` + `waitpid(wait_pid)` 尽力收割（防僵尸/孤儿泄漏）。pid-ns 下只杀 P，
A/B 尚未 send_hello 即未 exec、setup 中会 `_exit`，属罕见边角，「尽力而为」。错误消息
`child '{}' failed during setup`。集成测试 `spawn_setup_failure_no_leak`：deny sendmsg（=46）
使 child 的 send_hello 被 USER_NOTIF 拦截后阻塞 → 父进程 poll 2s 超时 → Err + 断言无僵尸。

### 3.4 wait_timeout / kill

```text
wait_timeout(d) : loop { try_wait → Some? 返回
                          now ≥ deadline → kill() + wait() 收割 → timed_out=true → 返回 ExitStatus(137)
                          sleep ~10ms }
kill()          : process_group ? kill(-kill_pid, SIGKILL) : kill(kill_pid, SIGKILL)
                  B 恒 setpgid(0,0) → 组 = B + 子孙；A(reaper)/P 不在组内，
                  见 B 死 → do_reaper ECHILD → P 转发 → 父 waitpid(P) 返回
try_wait()      : 1×waitpid(wait_pid, WNOHANG)；reap 成功 → 缓存 reaped；幂等
wait()          : 阻塞 waitpid(wait_pid)；pid-ns 下阻塞至 P 退出 = 整树退出
```

`wait_timeout_kills_group` 实测：`sh -c 'sleep 100'` + 300ms 到期 → 组杀，sh 与 sleep 孙进程
都消失、返回 137、`timed_out()==true`。

### 3.5 execute（`run_to_output`，平台无关，0 额外线程）

```text
child = spawn(spec, Piped)；stdin/stdout/stderr 三端全部置非阻塞
deadline = now + spec.timeout.unwrap_or(∞)
loop {
    drain(stdout) ; drain(stderr)                  // 先读，解除子进程 stdout 反压
    stdin 非阻塞写（EAGAIN 等 POLLOUT；EPIPE/EOF 停止，非错误）
    try_wait → Some? 退出
    now ≥ deadline → kill() + wait() → timed_out=true → 退出
    poll([stdout, stderr, (stdin?)], 10ms)          // 每 tick ≈ 2 syscall
}
read_to_end 两读端到 EOF → CommandOutput
```

**单循环交错**是防 64KB pipe 死锁的关键：先读解除 stdout 反压 → 子进程才能继续读 stdin →
父进程才能继续写（实测 `cat` + ≥2MB 回显输入完成且输出 == 输入）。deadline 检查在 loop 内
可达，不依赖 EAGAIN 触发——`execute_timeout_enforced` 用 200ms + `sleep 30` 验证。

### 3.6 LinuxChild 生命周期（Drop，零泄漏）

```text
Drop(LinuxChild)：
  has_deny (notif_worker.is_some()) && !reaped  → kill() + wait() 阻塞收割
    （必须 kill：不 kill 只关 listener，子进程下次命中 deny syscall 时永久阻塞）
  !has_deny && !reaped                           → try_wait() 机会收割；仍在跑则放生（std 语义）
  然后 join worker（子死 → listener POLLHUP → 确定性退出，无需超时 detach）
  stdout/stderr/stdin OwnedFd RAII 自动关
```

worker 线程栈 256KB；每沙箱 ≤1 worker（仅 has_deny）。

### 3.7 cmd_run：spawn(Inherit) 流式 + 信号转发（CLI 层）

`cmd_run` 走 `spawn(StdioConfig::Inherit)`（流式输出 + 交互 stdin，不走 execute 捕获）；
库 `execute` 保持捕获服务 CodeWhale 结构化全量输出，两条路各有其主。

信号转发（**职责限定 CLI，不进库**——库可被多线程并发调用，全局 pgid 会串扰；CodeWhale
用 `tokio::signal`）：

```rust
static CHILD_PGID: AtomicI32 = AtomicI32::new(0);   // 当前子进程 kill_pid（= 进程组 id）
extern "C" fn forward(sig: libc::c_int) {           // 全 async-signal-safe，无锁无堆
    let pgid = CHILD_PGID.load(Ordering::Relaxed);
    if pgid > 0 { unsafe { libc::kill(-pgid, sig) }; }
    unsafe { libc::_exit(128 + sig) };              // GNU 惯例
}
// cmd_run：signal(SIGINT/SIGTERM, forward) → spawn → CHILD_PGID.store(id) → wait_timeout → store(0)
```

`timed_out` → exit 124（timeout 惯例）。`cmd_run_sigint_forward` 实测：SIGINT 发出后 seabox
退出 130、子进程组（sh + sleep）被收。

---

## 4. 决策记录（汇总 ADR 006 + 评审修订）

| # | 决策 | 值 |
|---|---|---|
| D-A1 | `CommandOutput.exit_code` | **保持 `i32`**（128+sig 约定），超时用 `timed_out: bool` 消歧 |
| D-A2 | business-pid 回传 | **SO_PASSCRED + SCM_CREDENTIALS**（非 SCM_RIGHTS；实测 `id()==宿主 pid`） |
| D-A3 | hello 消息 | **合并单消息**：一次 sendmsg（SCM_RIGHTS listener + SCM_CREDENTIALS），一次 recvmsg 原子解析 |
| D-A4 | spawn 阻塞 | **有界阻塞**（poll ≤2s 等 hello），`kill_pid` 在 spawn 返回时确定 |
| D-A5 | socketpair 条件 | `has_deny \|\| ns.pid` |
| D-A6 | setpgid | business 恒 `setpgid(0,0)`，**在 seccomp 之前**（防 deny 清单误伤 setpgid/dup2） |
| D-A7 | kill 粒度 | `process_group` 默认 **true**（`kill(-pgid)` 组杀）；cmd_run 转发 SIGINT/SIGTERM |
| D-A8 | 超时表达 | `Option<Duration>`，默认 `None`（库向后兼容）；CLI 显式 `Some(30s)`；新增 `with_no_timeout()` |
| D-A9 | SandboxChild 形态 | 公开具体类型 + 私有 `SandboxChildImpl` trait（macOS 扩展点） |
| D-A10 | wait_timeout 语义 | 到期 kill(-kill_pid) + reap → 返回 `ExitStatus`(137) + `timed_out()` |
| D-A11 | feature 门控 | `cli = ["dep:clap","dep:dirs"]`；anyhow 核心；`expand_tilde` 改 `$HOME` |
| D-A12 | execute 捕获 | 边读边 wait 单线程 drain loop，0 额外线程 |
| D-A13 | worker 生命周期 | worker 仅 has_deny；Drop：has_deny && !reaped → kill+reap → join worker |

**评审修订（review.md，已采纳进实现）**：

| # | 修订 | 落点 |
|---|---|---|
| R1 | spawn 错误路径清理：recv_hello 失败 → kill + waitpid 尽力收割 | `linux/mod.rs` 步骤 7 + 测试 `spawn_setup_failure_no_leak` |
| R2 | 信号转发机制：`AtomicI32 CHILD_PGID` + 手写 handler（async-signal-safe），职责限 CLI | `main.rs` §3.7 |
| R3 | `reaped: bool`+`last_status` → `reaped: Option<ExitStatus>`（wait 幂等，防 ECHILD） | `LinuxChild.reaped` |
| R6 | wait_timeout 返回 `ExitStatus` 非 `Option`（到期必杀+reap，恒有已退出状态） | `SandboxChild::wait_timeout` 签名 |

---

## 5. 实现状态

| Task | 内容 | 状态 |
|---|---|---|
| Task 1 | `child_setup.rs`：`ChildIo` POD + setpgid/dup2（seccomp 前）+ `send_hello`（合并单消息，`send_fd` 复用支持 fd=-1 bare ping） | ✅ |
| Task 2 | `lib.rs` 类型层（`StdioConfig`/`SandboxChild`/`SandboxChildImpl`/`CommandSpec(+stdin, timeout→Option)`/`CommandOutput(+3)`/`SandboxImpl` 默认 execute）+ `child.rs` `run_to_output`（单循环交错 drain） | ✅ |
| Task 3 | `linux/mod.rs`：spawn 重构核心（precompute 迁入、socketpair 条件扩 `\|\| ns.pid`、SO_PASSCRED、recv_hello 有界阻塞、R1 错误路径清理、worker 按值收 fd、`LinuxChild` + Drop） | ✅ |
| Task 4 | `Cargo.toml` feature 门控 + `cmd_run` 改 spawn(Inherit) 流式 + SIGINT/SIGTERM 转发 + timed_out→124 | ✅ |
| Task 5 | `tests/spawn_test.rs`：spawn API 功能测试 | ✅（15 tests） |
| Task 6 | `tests/leak_test.rs`：资源专项 + 全量回归 | ✅（5 tests） |

新增 20 个测试全绿；既有测试文件（config / deny_detect / landlock / seccomp /
namespace×21 / mount / network / concurrent_fork）无回归——`concurrent_fork_test.rs:35`
依赖 `exit_code == 0`，因 D-A1（i32 保留）不破。

---

## 6. 测试与回归

### 新增 `tests/spawn_test.rs`（15 项，库 API + CLI）

| 测试 | 验证点 |
|---|---|
| `execute_captures_stdout_stderr` | stdout/stderr 内容 + exit_code 0 + timed_out false |
| `execute_with_stdin_small` | 小 stdin 回显 |
| `execute_no_stdin_reads_stdin_eof` | 无 stdin → cat 立即见 EOF 退出（重构挂死回归） |
| `execute_with_stdin_large` | `cat` + 2MB 回显输入 → 输出 == 输入（防 64KB 死锁） |
| `execute_timeout_enforced` | 200ms 超时 + `sleep 30` → timed_out、exit 137 |
| `with_no_timeout_runs` | timeout None + `sleep 0.3` → 自然完成不 timed_out |
| `spawn_try_wait_wait_idempotent` | 先 None 后 Some；try_wait / wait 二次幂等（CodeWhale 轮询关键） |
| `wait_timeout_kills_group` | `sleep 100` + 300ms → 组杀 sh+sleep、返回 137、timed_out |
| `pid_ns_id_is_business_host_pid` | `id()` == /proc 反推的 B 宿主 pid（SCM_CREDENTIALS 正确性） |
| `pid_ns_kill_group` | `sh -c 'sleep 30 & wait'` → kill() → 整树快速回收 |
| `stdio_fd_inject` | `StdioConfig::Fd` 预开 fd → 子进程 0/1/2 生效 |
| `take_fds_manual_read` | Piped + take_stdout 手动 Read（CodeWhale reader-thread 模式） |
| `spawn_blocked_classify` | deny syscall_probe → blocked() Some → classify_exit Denied(Seccomp) |
| `spawn_setup_failure_no_leak` | deny sendmsg → spawn Err「failed during setup」+ 无僵尸（R1） |
| `cmd_run_sigint_forward` | CLI `run -- sh -c 'sleep 100'` 发 SIGINT → 组被收 + 退出 130 |

### 新增 `tests/leak_test.rs`（5 项，资源专项）

| 测试 | 验证点 |
|---|---|
| `fd_steady` | `/proc/self/fd` 计数，spawn+wait×200 前后相等 |
| `threads_steady` | `/proc/self/status` Threads，spawn+wait×100 前后相等 |
| `no_zombie` | spawn+wait×100 后 `/proc/<wait_pid>` 不存在 |
| `drop_kill_no_deny_reaps` | 带 deny 立即 drop → 子被 SIGKILL + worker 已 join |
| `pid_only_no_thread` | 仅 pid-ns（无 deny）→ spawn 返回后无新增线程（省线程） |

leak_test 用进程级 fd / Threads 计数，`cargo test` 并行会互相污染，故每个测试先取全局
串行锁再测量；计数用 `settle()`（连续 5 次读数相等）消化 libtest 线程懒启动/退场的瞬时扰动。

### 命令清单

```bash
cargo test --test spawn_test          # 15 项 spawn/execute 功能
cargo test --test leak_test           # 5 项资源泄漏专项
cargo test                           # 全量（含既有 21+ 项回归）
cargo clippy -- -D warnings && cargo fmt
cargo build --no-default-features     # feature 门控验证
```

---

## 7. 已知限制与后续

- **child_setup exec 前未 close listener fd**：listener fd 来自 `seccomp(...NEW_LISTENER)`
  原生返回，未设 CLOEXEC，exec'd 程序继承（report_pid=0 旧路径与 report_pid=1 新路径均如此）。
  仅 `has_deny` 时存在、父进程侧 worker 已按值持有其副本，风险是 fd 泄漏进目标进程空间——
  低风险 fd 卫生项，后续可在 `install_user_notif_filter` 返回值后补 `fcntl(FD_CLOEXEC)`。
- **threads_steady 测不出「worker 自行退出 vs join」**：测试断言 spawn+wait+drop 后 Threads
  数稳定，能抓住 worker 泄漏，但无法区分「worker 因 POLLHUP 自行退出」与「Drop 显式 join」
  两条路径——两者都是确定的，属已知测试边界。
- **scm_creds_container_caveat 阶段 3 补探针**：SCM_CREDENTIALS 语义实测于 init pid-ns。
  seabox 若部署在容器 pid-ns 内，内核交付的 pid 相对容器 init-ns 有效（seabox 父与子同 ns
  层级 → kill() 成立）；跨 host 边界的容器化部署需阶段 3 补一条探针测试兜底。
- **孙进程继承 1/2 不退出 → drain 挂起**：与 `std::process` 同病（`run_to_output` 等子进程
  exit 后 `read_to_end` 到 EOF），不在本阶段解。
