# 阶段 0 详细设计 — spawn API / SandboxChild / stdio / 超时强制

> 设计时间：2026-08-14（arch-design，3 候选并行 + 对比）
> 状态：**待确认**（含 2 个行为变更决策点，见 §9）
> 上下文：`docs/arch/codewhale-integration/context.md`
> 上层设计：`docs/arch/codewhale-integration/design.md`（阶段 0 粗设计，本文件是它的详细落地）
> 决策记录：`docs/adr/0006-spawn-api-business-pid.md`

---

## 0. 摘要

seabox 从「阻塞 `execute`」扩展到「非阻塞 `spawn` + 活句柄」，为 CodeWhale 三条执行路径
（前台同步 / 后台非 tty / 后台 tty）打地基。本文件是 design.md 阶段 0 的详细设计：
完整接口签名、数据流时序、child_setup 零堆改动、feature 门控、测试计划与风险。

**3 个候选方案**（最小复杂度 / 可扩展 / 性能优先）并行产出后融合，共识与分歧见 §8 对比矩阵。
核心修正：design.md D3 的「business-pid 经 SCM_RIGHTS 回传」**技术不成立**，改用
**SO_PASSCRED + SCM_CREDENTIALS**（§2，已实测验证）。

---

## 1. 决策摘要

| # | 决策 | 结论 | 来源 |
|---|---|---|---|
| D-A1 | `CommandOutput.exit_code` 类型 | **保持 `i32`**，不采纳 design.md §0.1 的 `Option<i32>`。超时用 `timed_out: bool` 消歧；改 Option 破坏 `classify_exit(i32,…)` 签名与 `concurrent_fork_test.rs:35`，无收益 | 三候选一致 |
| D-A2 | business-pid 回传机制 | **SO_PASSCRED + SCM_CREDENTIALS**，非 SCM_RIGHTS。SCM_RIGHTS 只能传 fd；SCM_CREDENTIALS 由内核在 recvmsg 时自动附发送者 pid，**按接收者 pid-ns 解释**（实测：宿主 ns 的父进程收到 business 的宿主 pid） | 三候选一致 + 实测 |
| D-A3 | hello 消息格式 | **合并单消息**：B 在 seccomp 后一次 sendmsg（SCM_RIGHTS listener-fd + SCM_CREDENTIALS pid 自动），父侧一次 recvmsg 原子解析。无消息顺序依赖 | 候选 C |
| D-A4 | spawn 阻塞行为 | **有界阻塞**（poll ≤2s）等 hello，`kill_pid` 在 spawn 返回时**已确定**。镜像 `std::process::Command::spawn` 的 exec-readiness 语义；kill/wait_timeout 无「pid 未初始化」竞态 | 候选 C |
| D-A5 | socketpair 创建条件 | `has_deny || ns.pid`（现状仅 has_deny） | 三候选一致 |
| D-A6 | setpgid 执行 | business 进程**恒** `setpgid(0,0)`（在 seccomp **之前**，避免用户 deny 清单误伤 setpgid/dup2） | 候选 A/B |
| D-A7 | kill 粒度 + CLI 回归 | `process_group` 配置（默认 **true**）控制 `kill()` 用 `kill(-pgid)` 还是 `kill(pid)`；cmd_run 加 **SIGINT/SIGTERM 转发**到子进程组，消解 setpgid 导致的 Ctrl+C 回归 | 候选 B 提出回归 + 融合 |
| D-A8 | 超时表达 | `CommandSpec.timeout: Duration → Option<Duration>`，**默认 `None`**（库向后兼容不强制）；CLI 显式传 `Some(30s)`（`--timeout` 现有默认）。新增 `with_no_timeout()` | 候选 B |
| D-A9 | SandboxChild 形态 | 公开具体类型 + 私有 `SandboxChildImpl` trait（与 `Sandbox`/`SandboxImpl` 同构，macOS Phase 3 扩展点） | 候选 B/C |
| D-A10 | wait_timeout 语义 | 到期即 `kill(-kill_pid)` + reap + 返回 `ExitStatus`（137）+ `timed_out()`；签名 `io::Result<ExitStatus>`（评审 R6 简化：到期必杀+reap，恒有已退出状态，`Option` 的 None 语义混淆） | 候选 A + 评审 |
| D-A11 | feature 门控 | `cli = ["dep:clap","dep:dirs"]`；`anyhow` 核心常开；`expand_tilde` 改 `$HOME`（dirs 移出核心路径）；`from_flag_args` 加 `#[cfg(feature="cli")]`；`profile` 归核心 | 候选 A 深入分析 |
| D-A12 | execute 捕获 | 边读边 wait 单线程 drain loop（非阻塞 pipe + poll + WNOHANG），**0 额外线程**；stdin 非阻塞写+poll | 候选 C |
| D-A13 | worker 生命周期 | worker 仅 `has_deny` 时存在（每 child ≤1 线程，栈 256KB）；Drop：`has_deny && !reaped` → kill+reap → join worker（子死 → listener POLLHUP → 确定性退出） | 候选 A/C |

---

## 2. 关键修正：business-pid 回传 = SCM_CREDENTIALS（实测验证）

design.md D3 写「child 经 SCM_RIGHTS 回传 business pid」。**这在技术上不成立**：

1. **B 不知道自己的宿主 pid**：pid-ns 下 business 进程 B 的 `getpid()` 返回 ns 内 pid（=2，PID 1 是 reaper）。它无法把「宿主 pid」作为数据 payload 发出去。
2. **SCM_RIGHTS 只能传 fd，不能传 pid**。

正确机制：在 socketpair 父端设 `SO_PASSCRED`，内核在每次 recvmsg 时自动附 `SCM_CREDENTIALS`，
其 `pid` 字段按**接收者的 pid-ns** 解释——seabox 父进程在宿主 ns，拿到 B 的**宿主 pid**。

**实测验证**（2026-08-14，本机探针 userns→pidns→双层 fork→SO_PASSCRED）：

```
fork child P host pid = 249525
P's child A host pid = 249526 (ns PID 1)
A's child B host pid = 249527 (business, ns PID 2)
SCM_CREDENTIALS.pid   = 249527  →  是 business 宿主 pid ✓
```

> **部署 caveat**：实测中接收者在 init pid-ns。若 seabox 本身跑在容器 pid-ns 内，内核交付的 pid
> 相对容器 init-ns 有效（seabox 父进程与沙箱子进程同 ns 层级 → `kill()` 仍成立）。跨 host 边界的
> 容器化部署需在阶段 3 补一条探针测试（§7 测试 12）。

**消息格式（D-A3，合并单消息）**：B 在 seccomp USER_NOTIF 装好后、plain BPF 前，一次 sendmsg：

```
child(B) → parent(sv[0])   SOCK_SEQPACKET 原子交付
  iov  : 1B 0x42（沿用 CTRL_PAYLOAD）
  cmsg : SCM_RIGHTS    → listener fd（仅 has_deny；无 deny 时 send_fd 传 -1，bare ping）
  cmsg : SCM_CREDENTIALS → 内核自动附（父端 SO_PASSCRED），ucred.pid = B 宿主 pid
```

父侧 cmsg buffer 需同时容纳 SCM_RIGHTS（`CMSG_SPACE(4)=24B`）+ SCM_CREDENTIALS（12B→24B），
栈上 `MaybeUninit<[u8;64]>` 足够。**顺序无关**——原子到达，主线程一次解析。

---

## 3. 模块 / 结构布局

```
src/lib.rs             StdioConfig / CommandSpec(+stdin, timeout→Option) / CommandOutput(+3) /
                       Sandbox::spawn / SandboxChild(公开) + SandboxChildImpl(私有 trait) /
                       SandboxImpl(+spawn, execute 默认实现) / ExitStatus 复用 std
src/child.rs  [NEW]    run_to_output()（平台无关 execute：drain + 超时 + kill 组合，写一次）/
                       私有辅助：exit_code_from_status()
src/linux/mod.rs       LinuxSandbox::spawn()（现 execute 的 precompute 迁入）/
                       LinuxChild(impl SandboxChildImpl) / recv_hello / worker 按值收 fd / Drop
src/linux/child_setup.rs  ChildIo(POD) / setpgid / dup2 stdio / send_hello(SCM_RIGHTS+SO_PASSCRED)
src/main.rs            cmd_run：回打捕获输出 + timed_out→exit 124 + SIGINT/SIGTERM 转发
Cargo.toml             [features] cli；[[bin]] required-features
```

**`SandboxImpl` 保持私有**，`spawn` 经公开 `Sandbox::spawn` 暴露（沿用现有模式）。

---

## 4. 核心接口签名

### 4.1 `src/lib.rs`

```rust
/// 子进程标准流配置。恰好覆盖 CodeWhale 三条路径。
#[derive(Debug, Clone, Copy)]
pub enum StdioConfig {
    Inherit,                                          // 继承父进程 0/1/2，零额外 fd
    Piped,                                            // 内部 pipe；take_* 取出
    Fd { stdin: i32, stdout: i32, stderr: i32 },      // 预开 fd → dup2；-1 = 不修改
}

pub struct CommandSpec {
    // ...现有字段...
    pub timeout: Option<Duration>,   // None = 不强制；默认 None（库向后兼容）
    pub stdin: Option<Vec<u8>>,      // 同步便捷 stdin（execute 内部写；spawn 忽略）
}
impl CommandSpec {
    pub fn with_timeout(mut self, d: Duration) -> Self { self.timeout = Some(d); self }
    pub fn with_no_timeout(mut self) -> Self { self.timeout = None; self }
    pub fn with_stdin(mut self, data: impl Into<Vec<u8>>) -> Self;
}

pub struct CommandOutput {
    pub exit_code: i32,                      // 保持现状（128+sig 约定）
    pub blocked_syscall: Option<(u32, u32)>, // 保留
    pub stdout: Vec<u8>,                     // NEW
    pub stderr: Vec<u8>,                     // NEW
    pub timed_out: bool,                     // NEW
}

/// 平台无关沙箱子进程句柄。刻意镜像 std::process::Child。
pub struct SandboxChild { inner: Box<dyn SandboxChildImpl> }

pub(crate) trait SandboxChildImpl: Send {
    fn try_wait(&mut self)      -> io::Result<Option<ExitStatus>>; // WNOHANG；reaped 后幂等
    fn wait(&mut self)          -> io::Result<ExitStatus>;
    fn wait_timeout(&mut self, d: Duration) -> io::Result<ExitStatus>;
    //  到期 → kill(-kill_pid) + reap → 返回已退出状态（超时被强杀为 137）；timed_out() 查询
    //  评审采纳：返回 ExitStatus 而非 Option——到期必杀+reap，恒有已退出状态，None 语义混淆
    fn kill(&mut self)          -> io::Result<()>;  // process_group ? kill(-pgid) : kill(pid)
    fn id(&self)                -> u32;             // business 宿主 pid（= kill 目标）
    fn take_stdout(&mut self)   -> Option<OwnedFd>;
    fn take_stderr(&mut self)   -> Option<OwnedFd>;
    fn take_stdin(&mut self)    -> Option<OwnedFd>;
    fn blocked(&self)           -> Option<(u32, u32)>;
    fn timed_out(&self)         -> bool;
}

impl Sandbox {
    pub fn spawn(&self, spec: &CommandSpec, stdio: StdioConfig) -> anyhow::Result<SandboxChild>;
    pub fn execute(&self, spec: &CommandSpec) -> anyhow::Result<(CommandOutput, ExitReason)>; // 签名不变
}

trait SandboxImpl: Send + Sync {  // 仍私有
    fn spawn(&self, spec: &CommandSpec, stdio: StdioConfig) -> anyhow::Result<SandboxChild>;
    fn execute(&self, spec: &CommandSpec) -> anyhow::Result<CommandOutput> {
        crate::child::run_to_output(self.spawn(spec, StdioConfig::Piped)?, spec)  // 默认实现
    }
    fn classify_exit(&self, exit_code: i32, blocked: Option<(u32, u32)>) -> ExitReason;
}
```

- `ExitStatus` 用 std：`std::os::unix::process::ExitStatusExt::from_raw(status)`（稳定 API）。
- `Sandbox::execute` 保持 `(CommandOutput, ExitReason)` 签名不变；超时在 `Sandbox::execute`
  里补一条：`if output.timed_out { reason = ExitReason::InternalError("timed out …") }`
  （`classify_exit` 保持纯函数）。

### 4.2 `src/linux/mod.rs` — `LinuxChild`

```rust
pub struct LinuxChild {
    wait_pid: i32,                    // 外层 waitpid 目标（pid-ns 下是中间进程 P，阻塞至整树退出）
    kill_pid: i32,                    // business 宿主 pid（kill 目标；SCM_CREDENTIALS / 无 pid-ns 时 = wait_pid）
    stdout: Option<OwnedFd>, stderr: Option<OwnedFd>, stdin: Option<OwnedFd>,
    blocked: Arc<Mutex<Option<(u32, u32)>>>,
    notif_worker: Option<UserNotifHandle>,  // Some ⟺ has_deny（无 deny 无 worker，省线程）
    reaped: Option<ExitStatus>,       // None = 未收割；Some = try_wait/wait/wait_timeout 幂等返回缓存
    timed_out: bool,
    process_group: bool,
}
```

> **字段精简（评审采纳）**：`reaped: Option<ExitStatus>` 合并原 `reaped: bool` + `last_status: ExitStatus`
> （消除"两个字段必须一致"的不变量，wait 幂等 = 直接返回 Some）；删除 `has_deny: bool`
> （由 `notif_worker.is_some()` 推出，消除第二处不变量）。`kill_pid: i32` 非 Option——有界阻塞
> spawn（A4）保证构造时已确定。

---

## 5. child_setup 改动清单（ADR 0003 零堆内，纯 syscall）

### 5.0 进程树心智模型（所有 pid 语义的源头）

```
宿主 pid-ns                    新 pid-ns（仅 ns.pid 时）
─────────                      ─────────
seabox 父进程
   │ fork
   P ─── 等 A 退出，转发退出码     ← wait_pid：父进程 waitpid 收割目标（阻塞至整树退出）
   │ fork (unshare NEWPID 后)
   A（PID 1）reaper ─ 等 B 退出    ← ns init；杀它 = 内核 SIGKILL 整个 ns（备用机制）
   │ fork
   B（PID 2）business ── exec     ← kill_pid：SCM_CREDENTIALS 回传 B 的宿主 pid
                 setpgid(0,0) 建组 → kill(-kill_pid) 杀 B + 子孙，reaper 链逐层转发退出码
```

> **三个 pid，各司其职**：`wait_pid`（P，父进程收割对象）、`kill_pid`（B，杀进程树的目标）、
> business pid（B 在宿主 ns 的 pid，由内核经 SO_PASSCRED 隐式翻译，B 自己不知道）。
> 无 pid-ns 时 P ≡ B ≡ 直接 fork 子进程，三者合一。

新增 POD（全 `Copy` / `repr(C)`，零堆）：

```rust
#[repr(C)]
pub struct ChildIo {
    pub stdin_fd: i32,    // -1 = 不修改（Inherit / Fd(stdin:-1)）
    pub stdout_fd: i32,
    pub stderr_fd: i32,
    pub setpgid: i32,     // 0 = 否；1 = setpgid(0,0)
    pub report_pid: i32,  // 0 = 否；1 = send_hello（has_deny || ns.pid 时）
}
```

`enter_child` 增加一个按值传参 `child_io: ChildIo`（尾部，无指针/无堆）。

**插入位置**（相对现有序列，`child_setup.rs:119` 之后）：

| 步骤 | 位置 | 操作 | 零堆 |
|---|---|---|---|
| 新增 1 | pid-ns double-fork **之后**、fchdir **之前** | `setpgid(0,0)`（失败 `_exit(1)`）；business 进程执行 | 是 |
| 新增 2 | 紧随 1 | `dup2(stdin_fd,0) / (stdout_fd,1) / (stderr_fd,2)`（各 `>=0` 才做；src≠dst 时 dup2 自动清目标 CLOEXEC） | 是 |
| 调整 | 第 10 步 seccomp | `install_user_notif_filter` 后 **不立即 close** child/parent_sock_fd | 是 |
| 新增 3 | seccomp 之后、plain BPF **之前** | `send_hello(child_sock_fd, listener_fd)`（`has_deny ? listener : -1`；复用现有 `send_fd`，支持 `fd=-1` bare ping）；然后 close child/parent_sock_fd | 是 |
| 调整 | execve 前 | 原 plain BPF / execve 顺序不变 | — |

> **setpgid/dup2 在 seccomp 之前**：避免用户 `--seccomp-deny-nr` 清单误伤这两个 syscall
> （候选 A/B 一致）。hello 在 seccomp **之后**：listener fd 此时才存在；且 plain BPF 之前发，
> 即便后续 plain BPF 杀进程，spawn 也先成功、wait 再收割（与现状「listener 先发、plain BPF 后装」一致）。

### 5.1 hello 协议原语（评审采纳：类型化封装，调用方不碰 cmsg）

内核「SO_PASSCRED 隐式附 pid」是对调用方不透明的魔法——封装成有名字的类型，协议布局单点定义：

```rust
/// 一次 recvmsg 原子拿到的完整 hello（SOCK_SEQPACKET 保证边界）。
struct Hello {
    listener_fd: Option<OwnedFd>,   // has_deny 时 Some（seccomp USER_NOTIF listener）
    business_pid: i32,              // B 的宿主 pid（内核按接收者 pid-ns 翻译，来自 SCM_CREDENTIALS）
}

// child_setup（零堆，child 侧）：payload 1B 0x42 + SCM_RIGHTS(listener 或 -1)；
// SCM_CREDENTIALS 由父端 SO_PASSCRED 自动附加，child 零额外工作
fn send_hello(sock: RawFd, listener_fd: i32) -> Result<(), ()>;   // listener_fd=-1 = bare ping

// linux/mod（父侧）：poll ≤2s 等 hello；EOF/poll 超时 → 错误（见 R1 清理）
fn recv_hello(sock: RawFd) -> io::Result<Hello>;
```

> 原有 `recv_fd`（返回单个 fd）被 `recv_hello` 取代；`send_fd` 复用为 `send_hello`（已支持 `fd=-1`）。
> `blocked`/`kill_pid` 的解析集中在此一处，消息协议不散落。

---

## 6. 关键数据流

### 6.1 spawn（`LinuxSandbox::spawn`）

```
1. precompute（fork 前，现 execute 第 1–4 步原样迁入）：ruleset_fd / bpf_filter(has_deny) /
   ns_ops / uid·gid map / hostname / argv·envp / cwd O_PATH fd / mount_ops / caps_plan
2. need_sock = has_deny || ns.pid；若 need_sock：socketpair(SOCK_SEQPACKET)；父端 setsockopt(SO_PASSCRED)
3. stdio：Piped → pipe2(O_CLOEXEC)×3（stdin 写端 / stdout 读端 / stderr 读端）；Fd → 调用方 fd；Inherit → -1
4. fork()
5. 子进程 enter_child(..., child_io, child_sock_fd, parent_sock_fd_for_child, ...)
6. 父进程：drop(child_sock)；关 3 个 child 侧 pipe 端
   → recv_hello(parent_stream, poll≤2s)：
       ├─ POLLHUP/EOF/超时 → 清理已 fork 的子进程：kill(wait_pid, SIGKILL) + waitpid(wait_pid) 尽力收割
       │                      → Err("child exited during setup")（镜像 std::process exec 失败检测）
       └─ 成功 → (listener_fd_opt, business_host_pid)
           kill_pid = business_host_pid（无 pid-ns 时 = fork 返回值，无 hello 也已知）
           wait_pid = fork 返回值（pid-ns 下是中间进程 P）
           → has_deny ? spawn_user_notif_worker(listener_fd_by_value, &blocked) : 无
           → 关 parent_sock；组装 LinuxChild
```

> **R1 — spawn 错误路径清理（评审采纳）**：hello 未到即 spawn 失败时，`fork()` 已产生子进程，
> 必须 kill + waitpid 收割，否则僵尸/孤儿泄漏。pid-ns 下 `kill(wait_pid)` 只杀 P，A/B 可能孤儿
> （但 B 尚未 send_hello 即未 exec，setup 中会 `_exit`），属罕见边角——「尽力而为」，文档注明。
> 补测试：`spawn_setup_failure_no_leak`（触发 setup 失败 → 断言无僵尸）。

**spawn 是「有界阻塞」**（结构性的：hello 只在 B 完成 pre-exec setup 后到达），但比现状
（阻塞到整个进程退出）轻得多，且换来 `kill_pid` 确定性 + kill 无竞态。文档注明。

### 6.2 wait_timeout / try_wait / kill

```text
try_wait()      : 1×waitpid(wait_pid, WNOHANG)；reap 成功 → 缓存 ExitStatus、置 reaped；幂等
wait()          : 阻塞 waitpid(wait_pid)；pid-ns 下阻塞至 P 退出 = 整树退出
wait_timeout(d) : loop { try_wait → Some? 返回
                          now ≥ deadline → kill() + wait() 收割 → timed_out=true → 返回 ExitStatus(137)
                          sleep ~10ms }
kill()          : process_group ? kill(-kill_pid, SIGKILL) : kill(kill_pid, SIGKILL)
                  pid-ns 下 kill(-B_pgid)：B setpgid 过，组 = B + 子孙；
                  A(reaper)/P 不在组内，见 B 死 → do_reaper ECHILD → P 转发 → 父 waitpid(P) 返回
id()            : kill_pid（business 宿主 pid）
blocked()       : 读 Arc<Mutex<Option<(nr,arch)>>>（reap 后必为最终值：USER_NOTIF 下被拦 syscall
                  阻塞到 NOTIF_SEND 回复，故所有 notif 在子进程继续→退出前被 worker 处理完）
```

### 6.3 execute（`run_to_output`，平台无关）

```text
child = spawn(spec, Piped)
if let Some(input) = spec.stdin { 写 stdin（非阻塞+poll，防 >64KB 写满死锁）；drop 写端 → EOF }
(stdout_r, stderr_r) = (take_stdout, take_stderr)；set_nonblocking
deadline = now + spec.timeout.unwrap_or(∞)
loop {
    drain(stdout_r, &mut out); drain(stderr_r, &mut err);   // 边读边 wait（防 64KB 死锁）
    if let Some(es) = child.try_wait()? { exit_code = es; break; }
    if now ≥ deadline { child.kill()?; child.wait()?; timed_out=true; break; }
    poll([stdout_r, stderr_r], 10ms)                        // 每 tick ≈ 1×poll + 1×waitpid = 2 syscall
}
read_to_end 两读端到 EOF（子已死 → pipe EOF）
CommandOutput { exit_code: 128+sig 换算, blocked_syscall: child.blocked(), stdout, stderr, timed_out }
```

### 6.4 Drop（零泄漏，仅 has_deny 需 kill）

```text
Drop(LinuxChild)：
  has_deny && !reaped && 子仍在跑 → kill() + waitpid 阻塞收割
     （必须 kill：不 kill 只关 listener，子进程在下次命中 deny syscall 时永久阻塞）
  !has_deny && !reaped            → waitpid(WNOHANG) 机会收割；仍在跑则放生（std 语义）
  has_deny                         → join worker（子死 → listener POLLHUP → 确定性返回，无需超时 detach）
  OwnedFd RAII 关 3 个 pipe fd
```

### 6.5 cmd_run 信号转发（R2 评审采纳：职责限 CLI，不进库）

`process_group` 默认 true 使子进程脱离终端前台组 → Ctrl+C 只杀 seabox 自己。cmd_run 转发
SIGINT/SIGTERM 到子进程组。**实现机制（不引新依赖，手写，全 async-signal-safe）**：

```rust
static CHILD_PGID: AtomicI32 = AtomicI32::new(0);   // 当前正在执行子进程的 kill_pid（进程组 id）

extern "C" fn forward(sig: libc::c_int) {
    let pgid = CHILD_PGID.load(Ordering::Relaxed);
    if pgid > 0 { unsafe { libc::kill(-pgid, sig) }; }   // 转发到子进程组
    unsafe { libc::_exit(128 + sig); }                    // seabox 也退出（GNU 惯例）
}

// cmd_run：execute 前 signal(SIGINT/ SIGTERM, forward)；spawn 后存、wait 后清 CHILD_PGID
```

- `kill` / `_exit` / `AtomicI32::load` 均 async-signal-safe；handler 内无锁、无堆。
- **职责边界**：信号处理**只在 cmd_run（CLI 层）**。库的 `execute` 是同步阻塞、可被多线程
  并发调用——全局 `CHILD_PGID` 在并发下会串扰，故库不碰信号；调用方（CodeWhale）用自己的
  tokio 信号机制（`tokio::signal`）处理。
- 备选 `signal-hook` 依赖：为 3 个信号引依赖略重，倾向手写；若日后需要多 handler 再引入。

---

## 7. feature 门控（D-A11）

```toml
[features]
default = ["cli"]
cli = ["dep:clap", "dep:dirs"]     # anyhow/libc/landlock 恒为核心依赖

[dependencies]
clap   = { version = "4", features = ["derive"], optional = true }
dirs   = { version = "6", optional = true }
anyhow = "1"                       # lib.rs/config.rs/linux/* 全程使用，核心
libc   = "0.2"
landlock = "0.4"

[[bin]]
name = "seabox"
path = "src/main.rs"
required-features = ["cli"]        # --no-default-features 下不构建二进制
```

**前置清理（dirs 移出核心路径）**：
- `src/config.rs:559` `expand_tilde`：`dirs::home_dir()` → `std::env::var_os("HOME")`
  （父进程侧展开；损失 getpwuid fallback，边缘场景注释声明）。此后 `dirs` 只剩 cli.rs/main.rs 用。
- `src/config.rs` `from_flag_args`（引用 `crate::cli`）：加 `#[cfg(feature = "cli")]`。
- `src/lib.rs`：`#[cfg(feature = "cli")] pub mod cli;`。
- `src/profile.rs`：纯 std + anyhow 的 `@file` 预处理，**归核心**（不单独 gate，cli off 时仍编译，零 cfg 复杂度）。

CodeWhale：`seabox = { path = "../seabox", default-features = false }`，零 CLI 依赖。

---

## 8. 三候选对比矩阵

| 维度 | A 最小复杂度 | B 可扩展优先 | C 性能/资源 | 推荐 |
|---|---|---|---|---|
| SandboxChild 形态 | 具体类型（无 trait 层） | 具体类型 + 私有 `SandboxChildImpl` trait | 同 B | **B**（与 SandboxImpl 同构，macOS 扩展点，零成本） |
| pid 回传 | SCM_CREDENTIALS + 两条消息（pid ping 先、listener 后） | 同 SCM_CREDENTIALS | **合并单消息**（原子） | **C**（少一次 IPC，无顺序依赖） |
| spawn 阻塞 | kill_pid 可能为 None，kill() 内轮询 50ms | （未明确） | **有界阻塞 ≤2s 等 hello** | **C**（kill_pid 确定性，kill 无竞态） |
| setpgid | 无条件 | **process_group flag**（默认 false 保 CLI） | 无条件 | **融合**：恒 setpgid + process_group 默认 true + cmd_run 信号转发 |
| 超时表达 | Duration + ZERO 哨兵 | **Option\<Duration\>** + with_no_timeout | Duration（默认实现未展开） | **B**（无哨兵，库默认 None 兼容） |
| wait_timeout | 到期 kill+reap → Some(137)+flag | 到期返回 None **不 kill**（wait-timeout crate 惯例） | 到期 kill+reap → Some | **A** + 评审 R6 简化 `ExitStatus` |
| execute 实现 | 读线程 + join（简单） | drain 线程（run_to_output） | **非阻塞 drain loop，0 线程** | **C**（每 execute 省 2 线程） |
| 超时 kill 粒度 | kill(-pgid) | kill(-pgid) | kill(-pgid) | 一致 |
| Drop 语义 | kill_on_drop 开关（默认 true） | kill-on-drop + join | has_deny→kill+reap+join；无 deny→放生 | **C**（无 deny 不杀，最贴 std） |
| 资源账本 | 未量化 | 未量化 | **线程 = has_deny?1:0；fd = Piped?3:0** | **C**（可验证基线） |
| feature 门控 | **dirs 非纯 CLI → 换 $HOME**（唯一挖出此坑） | cli=dep:clap+dirs | 同 B | **A** 的挖掘 + B/C 的结构 |

**融合原则**：C 提供资源效率（合并消息/有界阻塞/0 线程 execute），B 提供扩展点与向后兼容
（trait/`Option<timeout>`/process_group 回归意识），A 提供正确性细节（setpgid 先于 seccomp、
dirs 移除）。A 的「两条消息」被 C 的合并消息取代；B 的「wait_timeout 不 kill」被 A 的强制语义取代
（贴近已批准 design.md）。

---

## 9. 行为变更决策点（已确认）

1. **process_group 默认 true + cmd_run 信号转发（D-A7）**：✅ **已定案（2026-08-14，采纳推荐）**。
   `setpgid(0,0)` 使沙箱子进程脱离终端前台进程组 → `seabox run -- sleep 100` 后 Ctrl+C 不再直接
   命中子进程。cmd_run 转发 SIGINT/SIGTERM 到子进程组，CLI Ctrl+C 行为由信号转发保住；
   CodeWhale 开箱即得组杀语义。
2. **execute 从继承改捕获（design.md 0.5 已接受）**：CLI 交互式 stdin（`seabox run -- cat`）
   从读终端变读 EOF；交互/tty 走阶段 2 `StdioConfig::Fd`。属已批准变更。

---

## 10. 测试计划 + 回归面

### 新增 `tests/spawn_test.rs`（库 API）

| 测试 | 验证点 |
|---|---|
| execute_captures_stdout_stderr | stdout/stderr 内容 + exit_code 0 + timed_out false |
| execute_with_stdin_large | `cat` + 输入 >64KB → 输出 == 输入（验证 drain 不卡） |
| execute_timeout_enforced | `with_timeout(200ms)` + `sleep 2` → timed_out、exit 137 |
| with_no_timeout_runs | timeout None + `sleep 1` → 正常完成 |
| spawn_try_wait_wait_idempotent | 先 None 后 Some；二次 try_wait 幂等（CodeWhale 轮询关键） |
| wait_twice_idempotent | `wait()` 两次返回相同 ExitStatus（reaped 缓存，防 ECHILD） |
| **spawn_setup_failure_no_leak** | 触发子进程 setup 失败 → spawn 返回 Err + 无僵尸/孤儿（R1 错误路径清理） |
| wait_timeout_kills_group | `sleep 100` + 100ms → kill + 组回收 |
| **pid_ns_id_is_business_host_pid** | `ns.pid=true`：`id()` == /proc 反推的 B 宿主 pid（SCM_CREDENTIALS 正确性） |
| **pid_ns_kill_group** | `sh -c 'sleep 30 & wait'` → kill() → 整树回收、wait 快速返回 |
| stdio_fd_inject | `StdioConfig::Fd` 预开 pipe fd → 子进程 0/1/2 生效 |
| take_fds_manual_read | Piped + take_stdout → 手动 Read（CodeWhale reader-thread 模式） |
| spawn_blocked_classify | `--seccomp-deny-nr` + syscall_probe → blocked() Some → classify_exit Denied |
| **cmd_run_sigint_forward** | （CLI 二进制）`run -- sleep 100`，发 SIGINT → 子进程组被收 + seabox 退出（§6.5） |
| **scm_creds_container_caveat** | （阶段 3）若在容器 pid-ns 内运行 seabox，验证 kill() 语义 |

### 新增 `tests/leak_test.rs`（资源专项）

| 测试 | 验证点 |
|---|---|
| fd_steady | `/proc/self/fd` 计数，spawn+wait×500 前后相等 |
| threads_steady | `/proc/self/status` Threads，spawn+wait×200 前后相等 |
| no_zombie | spawn+wait×200 后 `/proc/<wait_pid>` 不存在 |
| drop_kill_no_deny_reaps | 带 deny 立即 drop → 子被 SIGKILL、worker 已 join |
| pid_only_no_thread | 仅 pid-ns（无 deny）→ spawn 返回后无新增线程（省线程验证） |

### 回归面（硬约束）

- 全部既有测试文件原样通过：config / deny_detect / landlock / seccomp / namespace×21 /
  mount / network / concurrent_fork。`concurrent_fork_test.rs:35` 依赖 `exit_code == 0`——
  因 D-A1（i32 保留）不破。
- `cargo test` / `cargo clippy -- -D warnings` / `cargo fmt` / `cargo build --no-default-features`。
- `tests/landlock_test.rs:812`「CommandOutput 不含 stdout」注释随实现更新。
- 现有测试皆短命令，新强制超时（CLI 30s）不会误杀。

---

## 11. 风险与缓解

| 风险 | 缓解 |
|---|---|
| SCM_CREDENTIALS 跨 ns 语义依赖内核（实测通过） | 测试 7 直接断言 `id()`==宿主 pid；容器化 caveat 测试 12 |
| process_group 默认 true 改变 CLI Ctrl+C 行为 | cmd_run 转发 SIGINT/SIGTERM；决策点 §9.1 |
| spawn 有界阻塞（setup 挂起→2s 超时 Err） | 与 std::process exec 失败检测同类，属正确失败非 hang |
| execute 从 inherit 改 capture（流式→缓冲） | cmd_run 回打；全量回归；tty 走阶段 2 |
| Drop 杀子语义偏离 std（仅 has_deny 才杀） | 安全默认（不杀则子进程下次 deny 永久阻塞）；文档写明 |
| worker 每沙箱 1 线程 | 栈 256KB；生命周期确定性 join（§6.4） |
| 孙进程继承 1/2 不退出 → drain 挂起 | 与 std::process 同病；文档注明，不在此阶段解 |

---

## 12. 文件级改动清单

| 文件 | 改动 |
|---|---|
| `src/lib.rs` | `StdioConfig` / `CommandSpec`(+stdin, timeout→Option) / `CommandOutput`(+3) / `Sandbox::spawn` / `SandboxChild`+`SandboxChildImpl` / `SandboxImpl`(+spawn, execute 默认) / `pub mod child` |
| `src/child.rs` | NEW：`run_to_output()` + 私有辅助 |
| `src/linux/mod.rs` | `LinuxChild` / `spawn` 全流程（precompute 迁移、socketpair 条件扩 `\|\| ns.pid`、SO_PASSCRED、recv_hello、worker 按值收 fd）/ Drop |
| `src/linux/child_setup.rs` | `ChildIo` POD / `setpgid`+dup2（seccomp 前）/ `send_hello`（seccomp 后，`send_fd` 支持 `fd=-1`） |
| `src/main.rs` | `cmd_run` 回打 + `timed_out`→124 + SIGINT/SIGTERM 转发 |
| `src/config.rs` | `expand_tilde` 用 `$HOME`；`from_flag_args` 加 `#[cfg(feature="cli")]` |
| `Cargo.toml` | `[features] cli`；`clap`/`dirs` optional；`[[bin]] required-features` |
| `tests/spawn_test.rs` / `tests/leak_test.rs` | 上述测试 |
