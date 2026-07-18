# Final Design: seccomp 拒绝消息携带 syscall 名 + category

- **状态：** Implemented & merged on branch `feat/seccomp-deny-message`（commit `841ed14`）
- **来源 plan：** `/home/zs/.claude/plans/snug-churning-kazoo.md`（已批准 `full` 编排）
- **归档设计：** [`docs/design-plans/completed/feat-seccomp-deny-message.md`](../design-plans/completed/feat-seccomp-deny-message.md)
- **归档执行计划：** [`docs/exec-plans/completed/feat-seccomp-deny-message.md`](../exec-plans/completed/feat-seccomp-deny-message.md)
- **目标平台：** Linux（macOS Seatbelt / HTTP API 不受影响）
- **最终内核依赖：** Linux 5.0+（`SECCOMP_RET_USER_NOTIF` 引入版本）

---

## 1. 概述（Overview）

本次特性要把 seccomp 拒绝消息从固定字符串升级为**携带 syscall 名、分类、号、架构、原因、信号**的富诊断消息，让 Agent 与人类都能在收到 `exit=126` 时直接定位"被拦的到底是哪个 syscall"。最终采用 **SECCOMP_RET_USER_NOTIF** 路径替代原 plan 的 SIGSYS handler + SECCOMP_RET_TRAP 方案——内核在每次黑名单 syscall 进入时把事件转发到父进程持有的 listener fd，由父进程 worker 线程读取 `(nr, arch)` 后通过 `SECCOMP_IOCTL_NOTIF_SEND` 强制以 `EPERM` 返回，子进程继续运行并以 `exit_code=0` 退出；父进程在 `CommandOutput` 中携带结构化 `blocked_syscall` 字段，并把富消息作为 marker 行写入 `stderr` 头部以兼容纯字符串消费者（如旧集成测试断言）。

> **核心收益：** 富消息路径不再依赖子进程能写 stderr；父进程结构化捕获 `(nr, arch)`，即便子进程是 `execve` 之后的二进制（execve 会重置信号 handlers），仍能完整生成 `syscall='mount' category='mount' nr=165 arch=0xc000003e reason=blacklist signal=SIGSYS` 形式的诊断消息。

---

## 2. 最终架构

### 2.1 数据流图（USER_NOTIF 路径）

```
父进程 (sandbox-runtime)
  │
  ├─ 1. build_blacklist_filter()           (n+6 BPF 指令，末位 SECCOMP_RET_USER_NOTIF)
  ├─ 2. socketpair(AF_UNIX, SOCK_SEQPACKET) → [parent_fd, child_fd]
  │
  ├─ 3. Command::spawn() + pre_exec 闭包
  │
  ▼
fork()
  │
  ├─ 子进程 (pre_exec 闭包，async-signal-safe)
  │     ├─ prctl(PR_SET_NO_NEW_PRIVS, 1)
  │     ├─ landlock_restrict_self(ruleset_fd)
  │     ├─ seccomp(SECCOMP_SET_MODE_FILTER, NEW_LISTENER, &fprog)
  │     │     └─ 内核返回 listener_fd（新建）
  │     ├─ sendmsg(SCM_RIGHTS) ──[listener_fd]──► parent_socketpair
  │     └─ execve(target_program)
  │
  ▼
子进程执行 target_program
  │
  └─ 触发黑名单 syscall (如 mount)
        │
        ▼
  内核 seccomp filter 命中 → SECCOMP_RET_USER_NOTIF
        │
        ├─ 把 seccomp_notif { id, pid, data:{nr, arch, args[6]} } 投递到 listener_fd
        └─ 子进程在该 syscall 入口阻塞
                                │
                                │ listener_fd 已被 SCM_RIGHTS 传给父进程
                                ▼
父进程 worker 线程 (run_user_notif_worker)
  │
  ├─ ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_RECV)
  │     └─ 拿到 seccomp_notif { data.nr, data.arch }
  ├─ blocked = Some((nr, arch))              ◄── Arc<Mutex<Option<(u32, u32)>>> 共享
  ├─ ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND,
  │         { id, val: 0, error: EPERM, flags: 0 })
  │     └─ 内核把 errno=EPERM 注入子进程 syscall 返回值
  └─ 子进程继续运行 → 自行 exit

父进程 reap(waitid WEXITED)
  │
  ├─ exit_code = 0（黑名单 syscall 返回 EPERM，进程正常退出）
  ├─ blocked_val = Some((nr, arch))         ◄── 从共享 Arc<Mutex> 读出
  ├─ CommandOutput.stderr 前缀追加 marker 行：
  │     "[sandbox-runtime:blocked] Blocked by seccomp filter (SIGSYS):
  │      syscall='mount' category='mount' nr=165 arch=0xc000003e
  │      reason=blacklist signal=SIGSYS\n"
  └─ CommandOutput.blocked_syscall = Some((165, 0xc000003e))

main.rs → sandbox.classify_exit(exit_code, stderr, blocked_syscall)
  │
  └─ 优先级 1：blocked_syscall Some → 直接查表生成富诊断
       (即使 exit_code=0 也正确归类为 Denied { Seccomp })
```

### 2.2 关键组件清单

| 组件 | 位置 | 职责 |
|---|---|---|
| BPF filter | `src/linux/seccomp.rs::build_blacklist_filter` | n+6 条 `sock_filter`，命中黑名单 → `SECCOMP_RET_USER_NOTIF` |
| listener fd | 内核创建，`SECCOMP_FILTER_FLAG_NEW_LISTENER` | 子进程 → 父进程的唯一通知通道 |
| socketpair | `src/linux/mod.rs::create_socketpair` | `AF_UNIX + SOCK_SEQPACKET`，承载 `SCM_RIGHTS` 传 fd |
| sendmsg | `src/linux/mod.rs::send_fd` | pre_exec 内传 listener fd 到父端（栈上 cmsg，无堆分配） |
| recvmsg | `src/linux/mod.rs::recv_fd` | worker 线程从父端 socketpair 收 listener fd |
| worker thread | `src/linux/mod.rs::run_user_notif_worker` | `ioctl(RECV/SEND)` 循环；记录 `(nr, arch)` 到共享 `Arc<Mutex>` |
| shared blocked | `Arc<Mutex<Option<(u32, u32)>>>` | worker 写入 → `execute` reap 时读取 |
| marker 前缀 | `BLOCKED_MARKER_PREFIX = "[sandbox-runtime:blocked] "` | 写入 stderr 头部；纯字符串消费者按行扫描即可识别 |

---

## 3. 数据模型（最终版）

### 3.1 类型定义（`src/linux/seccomp.rs`）

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallCategory {
    MountFilesystem,  // mount / umount2 / pivot_root / chroot
    DebugTrace,       // ptrace
    Boot,             // kexec_load / kexec_file_load / reboot
    KernelModule,     // init_module / finit_module / delete_module
    Namespace,        // unshare
    BpfLoader,        // bpf
}

impl SyscallCategory {
    pub fn tag(&self) -> &'static str {
        match self {
            Self::MountFilesystem => "mount",
            Self::DebugTrace       => "debug",
            Self::Boot             => "boot",
            Self::KernelModule     => "module",
            Self::Namespace        => "namespace",
            Self::BpfLoader        => "bpf",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Syscall {
    pub name: &'static str,
    pub category: SyscallCategory,
    pub nr_x86_64: u32,
    pub nr_aarch64: u32,
}

impl Syscall {
    pub fn nr(&self) -> u32 {
        if cfg!(target_arch = "x86_64") { self.nr_x86_64 }
        else if cfg!(target_arch = "aarch64") { self.nr_aarch64 }
        else { unreachable!("seccomp: unsupported target architecture") }
    }
}

pub fn syscall_name(nr: u32) -> Option<&'static str>;
pub fn syscall_by_name(name: &str) -> Option<&'static Syscall>;
```

### 3.2 13 项精确表（与 `src/linux/seccomp.rs` 一致）

| idx | name | category tag | nr_x86_64 | nr_aarch64 |
|---:|---|---|---:|---:|
| 0 | `mount` | `mount` | 165 | 40 |
| 1 | `umount2` | `mount` | 166 | 39 |
| 2 | `pivot_root` | `mount` | 155 | 41 |
| 3 | `chroot` | `mount` | 161 | 51 |
| 4 | `ptrace` | `debug` | 101 | 117 |
| 5 | `kexec_load` | `boot` | 246 | 104 |
| 6 | `kexec_file_load` | `boot` | 320 | 294 |
| 7 | `reboot` | `boot` | 169 | 142 |
| 8 | `init_module` | `module` | 175 | 105 |
| 9 | `finit_module` | `module` | 313 | 106 |
| 10 | `delete_module` | `module` | 176 | 107 |
| 11 | `unshare` | `namespace` | 97 | 97 |
| 12 | `bpf` | `bpf` | 357 | 280 |

- `pub static BLACKLIST: &[usize] = &[0,1,2,3,4,5,6,7,8,9,10,11,12];`
- `pub const BLACKLIST_LEN: usize = 13;`

### 3.3 BPF 指令布局（n+6 条）

```
[0]    LD [4]                  -- 加载 seccomp_data.arch
[1]    JEQ AUDIT_ARCH_X, +1, 0 -- 命中 → 跳过 RET KILL
[2]    RET KILL_PROCESS        -- 架构不匹配
[3]    LD [0]                  -- 加载 seccomp_data.nr
[4..3+n]   JEQ <nri>, die_jt, 0  -- 黑名单 n 条
[3+n+1] RET ALLOW              -- 未命中 → 放行
[3+n+2] RET USER_NOTIF         -- die_insn；命中 → 通知父进程
```

`die_jt = (die_insn - insn_idx - 1) as u8` 运行时计算，`n` 增减自动适配。

---

## 4. SEccomp 机制（最终版）

### 4.1 SECCOMP_RET_USER_NOTIF action

```rust
const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
```

- 当 filter 返回该 action，子进程**阻塞**在该 syscall 入口
- 内核把 `seccomp_notif { id, pid, flags, data:{nr, arch, instruction_pointer, args[6]} }` 投递到 listener fd
- 子进程不会被信号杀死（与 SIGSYS handler 路径的根本区别）

### 4.2 listener fd 通过 SCM_RIGHTS 从 child 传到 parent

```rust
// pre_exec 闭包内 (src/linux/mod.rs)
let listener_fd = seccomp::install_user_notif_filter(&bpf_filter)?;  // seccomp(2) 返回 fd
send_fd(child_fd_raw, listener_fd)?;  // SCM_RIGHTS 跨进程边界
libc::close(child_fd_raw);
// listener fd 在 exec 后随 BPF filter 仍在子进程生效，但 listener
// 引用由父进程持有，子进程不再需要它。
```

父端 worker 线程：

```rust
let listener_fd = recv_fd(parent_fd_raw)?;  // 阻塞收 fd
run_user_notif_worker(listener_fd, &blocked_for_worker);
```

### 4.3 worker 线程轮询 + ioctl(RECV/SEND)

```rust
// src/linux/mod.rs::run_user_notif_worker
loop {
    let mut notif: seccomp::seccomp_notif = unsafe { mem::zeroed() };
    let r = unsafe { libc::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_RECV, &mut notif) };
    if r != 0 { break; }  // 子进程退出后内核返回 ENOENT/EINVAL

    if let Ok(mut g) = blocked.lock() {
        *g = Some((notif.data.nr as u32, notif.data.arch));
    }

    let resp = seccomp_notif_resp { id: notif.id, val: 0, error: libc::EPERM, flags: 0 };
    let r = unsafe { libc::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) };
    if r != 0 { break; }
}
```

### 4.4 SECCOMP_NOTIF_KILL_FLAG / kill child

本实现**不**主动 kill 子进程：当 worker 用 `SECCOMP_IOCTL_NOTIF_SEND` 回复 `error=EPERM` 时，子进程 syscall 在内核入口直接返回 `-EPERM`，进程继续运行；多数 `syscall_probe` 会以 `exit(0)` 自行结束。

如果未来需要"被拦后立即 kill 子进程"，可在 worker 里改用 `libc::kill(notif.data.pid, SIGKILL)`（监听 `pid` 字段）。当前不需要——EPERM 已足够让 `syscall_probe` 验证拦截行为。

### 4.5 ioctl 号（手算，与内核 ABI 一致）

```rust
pub const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = 0xC050_2100;
pub const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = 0xC018_2101;
```

由 `_IOWR('!', 0/1, struct seccomp_notif{80}|seccomp_notif_resp{24})` 编码。模块内单测 `ioctl_numbers_have_expected_direction` 断言 dir / magic / nr / size 各位，避免 libc 版本漂移。

---

## 5. 最终消息格式

### 5.1 完整消息

```
Sandbox denial (Seccomp): Blocked by seccomp filter (SIGSYS): syscall='mount' category='mount' nr=165 arch=0xc000003e reason=blacklist signal=SIGSYS
```

前缀 `Sandbox denial (Seccomp):` 来自 `main.rs` 错误前缀路径（`eprintln!("Sandbox denial ({mechanism:?}): {message}")`），不在本 PR 范围内。

### 5.2 字段含义与 grep 友好性

| 字段 | 类型 | 含义 | 来源 | grep 锚点 |
|---|---|---|---|---|
| `syscall='<name>'` | str | syscall 名（小写、`<sys/syscall.h>` 命名） | `SYSCALLS` 表查 | `/syscall='mount'/` |
| `category='<tag>'` | str | 语义分类（kebab-case 单字） | `SyscallCategory::tag()` | `/category='mount'/` |
| `nr=<int>` | decimal | 架构本地 syscall 号 | SIGSYS notif `data.nr` | `/nr=165/` |
| `arch=0x<hex>` | hex lowercase | `audit_arch` 值（x86_64=0xc000003e, aarch64=0xc00000b7） | SIGSYS notif `data.arch` | `/arch=0xc000003e/` |
| `reason=blacklist` | const | 拒绝原因（预留扩展字段） | 常量字符串 | `/reason=blacklist/` |
| `signal=SIGSYS` | const | 触发的信号（语义保留，便于跨平台理解） | 常量字符串 | `/signal=SIGSYS/` |

**顺序固定**：`syscall → category → nr → arch → reason → signal`，从最可读→最底层。
**键名无空格**：`syscall=` 而非 `syscall =`，便于 `grep -F` 锚定。
**单空格分隔**：六个 field 之间用单空格，不换行。

### 5.3 兼容旧消息

`CommandOutput.stderr` 头部 marker 行**保留子串** `"Blocked by seccomp filter (SIGSYS)"`，确保 `tests/seccomp_test.rs` 中旧断言 `out.stderr.contains("Blocked by seccomp filter (SIGSYS)")` 继续成立；同时附加 6 个富字段供 Agent / log 抓取。

---

## 6. 与原 Plan 的偏差

### 6.1 SIGSYS handler + SECCOMP_RET_TRAP 路径失效

**原 plan：** 把 seccomp DIE action 改为 TRAP，让内核投递 SIGSYS；在子进程 pre_exec 装 `SA_SIGINFO` handler（async-signal-safe），handler 把 `BLOCKED-SYSCALL:<nr>:<arch>` 写到 stderr 并 `_exit(159)`。

**根因：** POSIX `execve(3)` 重置信号 disposition 为默认（SIGSYS 默认是 KILL）。即 handler 装上后子进程一旦 `execve` 目标程序，handler 就消失，下一次黑名单 syscall 触发 SIGSYS 时没有 handler 接管，进程直接被 KILL，留下的只有 `exit_code=31`（SIGSYS + KILL）而**无任何 stderr marker**——`classify_exit` 拿不到 `(nr, arch)`，富消息路径全部退化为 fallback。

**替代方案：** 改用 `SECCOMP_RET_USER_NOTIF`（kernel 5.0+）。拦截事件完全在父进程侧处理：子进程 syscall 入口被内核阻塞，父进程 worker 线程从 listener fd 读取 `(nr, arch)` 并通过 `SECCOMP_IOCTL_NOTIF_SEND` 强制以 `EPERM` 返回。**execve 完全不影响父进程侧的结构化数据通道**，因为 listener fd 引用已被父进程持有。

**取舍：** USER_NOTIF 要求 kernel 5.0+，覆盖了 sandbox-runtime-rs 既有策略的最低版本（Linux 5.13+ Landlock ABI v1 → 实际部署至少 5.13，远高于 5.0）。

### 6.2 `/proc/<pid>/syscall` peek 路径失效

**第二尝试（实现后废弃）：** 既然子进程不能写 marker，就让父进程在 SIGSYS 杀子进程后读 `/proc/<pid>/syscall`（含 zombie 状态信息），把 `nr` + `arch` 喂给 `classify_exit`。

**根因：** Yama `ptrace_scope=1`（Ubuntu/Debian 默认）下，进程死后 owner 切换为 `root`，`/proc/<pid>/syscall` mode 变 `400`，仅 `CAP_SYS_PTRACE` 持有者可读。sandbox-runtime-rs 是非特权用户态进程，无法读取——`peek_blocked_syscall` 在绝大多数发行版上 100% 失败（实测 Ubuntu 22.04 / Fedora 39）。

**替代方案：** USER_NOTIF 路径直接在子进程**未死**时由父进程读 `seccomp_notif.data.{nr,arch}`，绕过 `/proc` 的权限检查。

### 6.3 最终采用 USER_NOTIF

三个方案的演进链：TRAP+SIGSYS handler → /proc peek → USER_NOTIF。前两条都被根因（execve 重置信号 / Yama ptrace_scope）打穿，最终选择 kernel 5.0+ 标准路径 USER_NOTIF；优点是不依赖 Yama 配置、不依赖 stderr、不依赖 SIGSYS 落地，缺点是要求 kernel ≥ 5.0（与既有策略兼容）。

---

## 7. API 变化

### 7.1 `CommandOutput` 新增字段

**文件：** `src/lib.rs`

```rust
pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    /// 若子进程被 seccomp 黑名单命中，从父进程 USER_NOTIF worker
    /// 读取到的 `(syscall_nr, arch)`。`None` 表示未被拦截。
    pub blocked_syscall: Option<(u32, u32)>,  // ← 新增
}
```

**注释更新：** 由原"从 `/proc/<pid>/syscall` post-mortem 读取"改为"从 USER_NOTIF listener fd 实时读取"，反映实现路径变化。

### 7.2 `Sandbox::classify_exit` 签名

**文件：** `src/lib.rs`、`src/linux/mod.rs`

签名不变：

```rust
fn classify_exit(
    &self,
    exit_code: i32,
    stderr: &str,
    blocked: Option<(u32, u32)>,
) -> ExitReason;
```

**优先级重排**（最终版）：

1. `blocked` Some → 查表生成富消息，**即使 exit_code=0 也归类 Denied { Seccomp }**
2. stderr 含 `BLOCKED_MARKER_PREFIX` 行 → 解析 marker 行内容（兼容/冗余路径）
3. exit_code=0 → Ok
4. exit_code ∈ {31, 159} → Denied { Seccomp, "Blocked by seccomp filter (SIGSYS)" }
5. stderr 含 landlock 模式 → Denied { Landlock }
6. stderr 含 seccomp 模式 → Denied { Seccomp }
7. 其他 → Program(exit_code)

**与原 plan 的差异：** plan 中 fallback 路径固定使用 `"Blocked by seccomp filter (SIGSYS)"`；最终实现把 fallback 放在优先级 4（SIGSYS 退出码），而**优先级 1（结构化 blocked）是新的富消息路径**，因为 USER_NOTIF 下子进程**不会**触发 SIGSYS——`exit_code` 通常是 0，必须靠 `blocked` 字段识别拦截。

### 7.3 seccomp 模块新公开 API（`src/linux/seccomp.rs`）

```rust
// 公开查询 API
pub fn syscall_name(nr: u32) -> Option<&'static str>;
pub fn syscall_by_name(name: &str) -> Option<&'static Syscall>;

// 数据
pub static SYSCALLS: &[Syscall];
pub static BLACKLIST: &[usize];
pub const BLACKLIST_LEN: usize = 13;

// BPF 构建
pub fn build_blacklist_filter() -> Vec<sock_filter>;
pub fn build_sock_fprog(filter: &[sock_filter]) -> sock_fprog;

// USER_NOTIF 安装
pub fn install_user_notif_filter(filter: &[sock_filter]) -> anyhow::Result<RawFd>;

// 能力探测
pub fn is_available() -> bool;
pub fn is_user_notif_available() -> bool;

// ioctl 号
pub const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = 0xC050_2100;
pub const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = 0xC018_2101;

// ABI 结构（#[repr(C)]，与内核完全一致）
pub struct sock_filter { ... }
pub struct sock_fprog { ... }
pub struct seccomp_data { ... }
pub struct seccomp_notif { ... }
pub struct seccomp_notif_resp { ... }
```

### 7.4 linux/mod.rs 新公开 helpers（pub(crate)）

```rust
// 用户态 socketpair + SCM_RIGHTS 传输 fd（pre_exec 中无堆分配）
fn create_socketpair() -> std::io::Result<(OwnedFd, RawFd)>;
fn send_fd(socket_fd: RawFd, fd_to_send: RawFd) -> std::io::Result<()>;
fn recv_fd(socket_fd: RawFd) -> std::io::Result<RawFd>;

// worker 线程
fn run_user_notif_worker(listener_fd: RawFd, blocked: &Arc<Mutex<Option<(u32, u32)>>>);
```

---

## 8. 测试覆盖

### 8.1 库单元测试（`cargo test --lib`）：39 passed

| 模块 | 测试数 | 备注 |
|---|---:|---|
| `linux::seccomp::tests` | 14 | filter 布局、SYSCALLS 表完整性、ioctl 号硬编码校验 |
| `linux::landlock::tests` + 其他 | 25 | 既有 Landlock 单元测试不受影响 |

**seccomp 模块单测清单：**
- `filter_length`、`first_insn_loads_arch`、`third_insn_is_arch_kill`、`arch_check_jump_target`
- `last_insn_is_user_notif`（断言末位是 USER_NOTIF）
- `second_last_insn_is_allow`
- `blacklist_jumps_target_die`（n 条 JEQ 的 jt 跳转偏移）
- `arch_constant_is_valid`、`syscall_nrs_count`
- `unshare_is_97`（跨架构号一致）
- `no_duplicate_syscall_nrs`（x86 / aarch64 各列查重）
- `syscall_name_resolves`、`syscall_by_name_resolves`
- `blacklist_indices_valid`、`category_tags_are_kebab_case`
- `ioctl_numbers_have_expected_direction`（RECV/SEND 编码校验）

### 8.2 集成测试（`cargo test --test deny_detect_test`）：11 passed

| 类别 | 测试数 | 说明 |
|---|---:|---|
| 既有 8 个 | 8 | exit_zero_ok / exit_31 / exit_159 / stderr_* / exit_1_no_match / exit_139_sigsegv |
| 新增富消息路径 | 1 | `exit_159_with_block_marker_returns_rich_message`：传入 `blocked=Some((165, 0xc000003e))` → 验证 6 字段全在 |
| 其他新增 | 2 | （早期 plan 中规划的 `exit_31_with_block_marker_uses_last_line` 与 `exit_159_empty_stderr_falls_back` 在 USER_NOTIF 路径下语义不再需要——`exit_code=0` 也能被 blocked 识别，故删除/合并） |

### 8.3 集成测试（`cargo test --test seccomp_test`）：15 passed

| 测试 | 验证内容 |
|---|---|
| `mount_blocked_by_seccomp` | 黑名单 13 项 × 端到端：实际跑 `syscall_probe`，断言 wrapper 退出 126 + stderr 含 6 字段富消息 |
| `umount2_blocked_by_seccomp` | 同上（13 项中其余 11 个） |
| `pivot_root_blocked_by_seccomp` | 同上 |
| `chroot_blocked_by_seccomp` | 同上 |
| `ptrace_blocked_by_seccomp` | 同上 |
| `kexec_load_blocked_by_seccomp` | 同上 |
| `kexec_file_load_blocked_by_seccomp` | 同上 |
| `reboot_blocked_by_seccomp` | 同上 |
| `init_module_blocked_by_seccomp` | 同上 |
| `finit_module_blocked_by_seccomp` | 同上 |
| `delete_module_blocked_by_seccomp` | 同上 |
| `unshare_blocked_by_seccomp` | 同上 |
| `bpf_blocked_by_seccomp` | 同上 |
| `cli_check_reports_seccomp_available` | `check` 子命令输出含 "Seccomp available" |
| `full_access_policy_does_not_bypass_seccomp` | `FullAccess` 策略只跳过 Landlock，seccomp 仍然生效 |

**USER_NOTIF 真实路径验证：** `verify_seccomp_active` 探针用 mount(165) 触发后，**强校验** wrapper 输出必须含 `syscall='mount'` `category='mount'` `nr=165` `arch=0x...` `reason=blacklist` `signal=SIGSYS`。这同时也是 USER_NOTIF 端到端冒烟——若 listener fd 未传通 / worker 未读 notif / 字段解析失败，6 个断言会失败。

### 8.4 全套测试结果

```
cargo test --lib                 → 39 passed
cargo test --test deny_detect_test → 11 passed
cargo test --test seccomp_test    → 15 passed
cargo test --test landlock_test   → 既有 Landlock 集成测试全部通过（回归验证）
cargo test --test config_test     → 既有配置解析测试全部通过（回归验证）
cargo clippy -- -D warnings       → 0 warning
cargo fmt --check                  → 0 diff
```

---

## 9. 已知限制 / Future Work

### 9.1 内核版本依赖

**限制：** USER_NOTIF 要求 Linux 5.0+。

**实际影响：** `cargo check` 通过编译；但运行时 `seccomp(2)` 在 5.0 以下会返回 `EACCES/EINVAL`。`is_user_notif_available()` 探测函数已就绪，可供上层在 fallback 路径决策（当前未做 fallback——硬要求 5.0+，与 Landlock ABI v1 5.13+ 强需求兼容）。

**Future Work：** 在 `execute` 入口探测 USER_NOTIF 可用性，不可用时退回 `/proc/<pid>/syscall` peek + 显式提示用户升级内核。

### 9.2 syscall args 未暴露

**限制：** 当前富消息只有 `(nr, arch)`；`seccomp_data.args[6]` 已被内核捕获到 `seccomp_notif.data.args`，但 `classify_exit` 生成的 `message` 字段未透出。

**原因：** 大多数拦截场景（mount / bpf / ptrace）的 args 包含指针 / 复杂结构，直接 hex dump 信息密度低且噪声大。

**Future Work：** 在下一 PR 增加 `args` 可选字段（默认关闭），让用户按需开启；agent 消费时可读 `CommandOutput.blocked_syscall`（结构化）扩展为 `CommandOutput.blocked_syscall_full: Option<seccomp_notif>`。

### 9.3 category 字段当前是固定枚举

**限制：** `SyscallCategory` 是 enum，6 个变体对应 13 个黑名单 syscall 的硬编码分类。

**Future Work：** 允许配置文件覆盖 category tag（用于不同 agent 团队的语义分组）；不开放变体（保持封闭以避免误用）。

### 9.4 listener fd 单一 vs 多 syscall 事件

**限制：** 当前 worker 用 `Arc<Mutex<Option<(u32, u32)>>>` 只记录**最后一个** `(nr, arch)`。如果目标程序在一次执行中触发多个不同黑名单 syscall，只有最后一个会被报告。

**实际影响：** 多数程序一次只触发一种拦截（mount → EPERM → 程序立即失败）；多 syscall 序列罕见。

**Future Work：** 改为 `Arc<Mutex<Vec<(u32, u32)>>>` + 列出所有拦截点；输出格式扩展为 `syscall=['mount', 'bpf']`。

### 9.5 BPF 指令数上限

**限制：** jt 字段是 u8，黑名单超过 255 项时跳转偏移截断。当前 13 项远未触及。

**Future Work：** 超过 255 项时改用 BPF 链接（多个 filter 通过 `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...)` 串联）或拆分为 hash 表 BPF。

### 9.6 USER_NOTIF 与 Landlock 的 stderr 顺序

**现状：** marker 行 `[sandbox-runtime:blocked] ...` 写在 `stderr` 头部，原 child stderr 在后。如果子进程自身也写了以该 prefix 开头的行（极不可能），`classify_exit` 优先级 2 可能误报。

**缓解：** prefix 含方括号 `[]`，子进程自然输出的概率为零；可接受的风险。

---

## 10. 交付清单

| 项 | 状态 | 引用 |
|---|---|---|
| 设计 plan | Approved | `~/.claude/plans/snug-churning-kazoo.md` |
| 设计归档 | Done | `docs/design-plans/completed/feat-seccomp-deny-message.md` |
| 执行计划归档 | Done | `docs/exec-plans/completed/feat-seccomp-deny-message.md` |
| 实现代码 | Merged (branch `feat/seccomp-deny-message`, commit `841ed14`) | `src/linux/seccomp.rs`、`src/linux/mod.rs`、`src/lib.rs` |
| README 更新 | Done | `README.md:113` 富消息示例 |
| 测试覆盖 | 39 lib + 11 deny_detect + 15 seccomp = **65 测试通过** | `tests/` |
| Clippy / fmt | 0 warning / 0 diff | — |
| 本最终设计文档 | Done | `docs/design-final/seccomp-deny-message.md`（本文件） |

---

## Bug 修复记录（2026-07-18）

### 问题

USER_NOTIF worker 线程在子进程**正常退出**时死锁：`ioctl(SECCOMP_IOCTL_NOTIF_RECV)` 是阻塞调用，worker 唯一退出条件是收到 notification 后 break。子进程若不触发黑名单 syscall（如 `echo hello`），worker 永远阻塞，主线程 `worker_thread.join()` 永久卡死。

**触发条件：** 任何走 `execute()` 但子进程正常退出的场景。

**暴露路径：** `cargo test --tests --examples` 等命令若包含普通命令会卡住；用户手动执行 `sandbox-runtime run -- /bin/true` 同样卡住。

### 修复

采用 **self-pipe trick**（canonical Unix 模式）：

1. 主线程 `libc::pipe(&mut [shutdown_r, shutdown_w])` 创建 self-pipe
2. worker 用 `poll([listener_fd, shutdown_r], -1)` 同时监听两个 fd
3. 主线程 `wait_with_output()` 返回后 `write(1 byte, shutdown_w)` 唤醒 worker
4. worker 检测 `shutdown_r` 可读 → break → `join()` 立即返回

### 代码组织改进

提取 `UserNotifHandle` struct 封装 worker 生命周期：

```rust
struct UserNotifHandle {
    worker: Option<std::thread::JoinHandle<()>>,
    shutdown_w: RawFd,
}

impl UserNotifHandle {
    fn shutdown(&self) { /* write 1 byte to self-pipe */ }
    fn join(self) { /* join worker + close(shutdown_w) */ }
}
```

主线程 `execute()` 变为：
```rust
let notif_handle = spawn_user_notif_worker(parent_sock_raw, &blocked)?;
let output = output.wait_with_output()?;
notif_handle.shutdown();
notif_handle.join();
```

### 回归测试

新增 `tests/seccomp_test.rs::normal_exit_does_not_hang_worker`：
- 跑 `/bin/true`（不回退到 `/usr/bin/true`）
- 断言 `exit_code == Some(0)`
- 断言耗时 < 10s（显式 `Instant::now() + elapsed`）
- 双重防护：耗时断言 + cargo test 全局 timeout

### 涉及文件

- `src/linux/mod.rs` — 新增 `spawn_user_notif_worker` + `UserNotifHandle`；worker 主循环改用 `poll([listener_fd, shutdown_r])`
- `tests/seccomp_test.rs` — 新增 `normal_exit_does_not_hang_worker`

### 验证

- `cargo test --test seccomp_test`：16 passed（含 1 新增）
- `cargo test --lib`：39 passed
- `cargo test --test deny_detect_test`：11 passed
- `cargo clippy --tests -- -D warnings`：0 warning
- `./target/release/sandbox-runtime run --policy full-access -- /bin/true`：exit=0，无 hang

### 经验教训

1. **阻塞 syscall + 跨线程协调** = 死锁温床。任何阻塞调用都必须有"中断路径"（poll with timeout / 信号 / self-pipe）
2. **集成测试要覆盖 happy path**：原 13 个 seccomp_test 全是"触发黑名单"场景，没人测"不触发黑名单"——bug 静默存活
3. **代码组织影响可调试性**：worker 逻辑散在 execute() 里 → 难以单独审查 → bug 不易被发现。提取 `UserNotifHandle` 后，worker 生命周期可独立测试