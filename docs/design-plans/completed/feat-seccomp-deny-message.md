# Feature: seccomp 拒绝消息携带 syscall 名 + category

- **状态：** Approved（plan mode 已签字）
- **来源 plan：** `~/.claude/plans/snug-churning-kazoo.md`
- **作用域：** Linux seccomp 后端（Landlock 分支、macOS、HTTP API 不受影响）
- **目标版本：** 下一个 minor 修订
- **预计净增行数：** ~200 行（不计删除的镜像表）

---

## 1. Context

### 1.1 当前行为

仓库 `seabox` 当前 seccomp 拒绝消息是**固定字符串**，不携带 syscall 名、号、架构、分类：

```
Sandbox denial (Seccomp): Blocked by seccomp filter (SIGSYS)
```

### 1.2 问题

Agent / 开发者在收到拒绝时**完全无法定位**"被拦的到底是什么 syscall"：

- **人类定位**：要打开 `strace` 二次执行，手工对上 syscall 号 → 名。
- **Agent 自动归因**：`Denied.message` 是字符串，但没有结构化字段，`match` 或正则解析无稳定锚点。
- **多 syscall 关联**：13 个黑名单 syscall 在一条 stderr 内无法区分，调试时只能二分试错。

### 1.3 目标

把"被拦 syscall"的全部关键元数据带出来——**名（字符串）、分类（语义标签）、号（int）、架构（hex）、原因（blacklist）、信号（SIGSYS）**，结构稳定、grep 友好、Agent 易解析。

### 1.4 不在动机内

- 不改 syscall 黑名单本身（13 项不变）
- 不动 Landlock 分支的消息格式
- 不动 macOS Seatbelt / HTTP API / Configuration 任何字段
- 不引入 syscall args（要 `SECCOMP_RET_USER_NOTIF`，工作量翻倍，下个 PR）

---

## 2. Goal — 目标消息格式样例

```
Sandbox denial (Seccomp): blocked syscall='mount' category='mount' nr=165 arch=0xc000003e reason=blacklist signal=SIGSYS
```

### 2.1 字段约定

| 字段 | 类型 | 含义 | 来源 |
|---|---|---|---|
| `syscall='<name>'` | str | 被拦的 syscall 名（小写，来自 `<sys/syscall.h>` 或 man page） | `SYSCALLS` 表查 |
| `category='<tag>'` | str | 语义分类标签（kebab-case 单字） | `SyscallCategory::tag()` 查 |
| `nr=<int>` | decimal | 被拦 syscall 的架构本地号 | SIGSYS handler 捕获 |
| `arch=0x<hex>` | hex lowercase | `audit_arch` 值（x86_64=0xc000003e, aarch64=0xc00000e7） | SIGSYS handler 捕获 |
| `reason=blacklist` | constant | 拒绝原因（黑名单策略），预留字段未来可能扩 | 常量字符串 |
| `signal=SIGSYS` | constant | 触发的信号 | 常量字符串 |

### 2.2 排版约束

- **顺序固定**：`syscall → category → nr → arch → reason → signal`，从最可读→最底层，便于人眼扫读
- **键名无空格**：`syscall=` 而非 `syscall =`，grep `/syscall='/` 可锚定
- **单空格分隔**：六个 field 之间用单空格，不换行（避免多行 stderr 解析复杂度）
- **前缀保留**：`Sandbox denial (Seccomp):` 来自 `main.rs` 错误前缀路径，不在本 PR 改动范围内

### 2.3 fallback 消息

当 SIGSYS handler **未触发**（handler 未装上 / 子进程非 pre_exec 路径 / 内核未带 SIGSYS）时，保留旧消息不破坏既有契约：

```
Sandbox denial (Seccomp): Blocked by seccomp filter (SIGSYS)
```

> 此 fallback 路径保证 `tests/deny_detect_test.rs` 中所有空 stderr 测试**不需要改**。

---

## 3. Design Decisions（已批准）

| # | 决策 | 选择 | 理由 |
|---|---|---|---|
| D1 | **seccomp 失败动作** | `SECCOMP_RET_KILL_PROCESS` → `SECCOMP_RET_TRAP` | 让 SIGSYS 可观测，handler 可访问 `(nr, arch)` |
| D2 | **数据模型粒度** | Granularity 3：`Syscall` + `SyscallCategory` + `SYSCALLS` 表 + `BLACKLIST: &[usize]` | 复用现有表结构、加语义层；增量而非重写 |
| D3 | **fallback 行为** | handler 未跑 / marker 缺失 → 旧消息 `"Blocked by seccomp filter (SIGSYS)"` | 不破坏 `deny_detect_test` 既有 8 个测试 |
| D4 | **category 标签** | kebab-case 单字（`mount` / `debug` / `boot` / `module` / `namespace` / `bpf`） | grep 友好、避免下划线/驼峰混用 |
| D5 | **跨架构号存储** | `Syscall { nr_x86_64, nr_aarch64 }`，运行时 `nr()` 选 | 与上游 `linux-sandbox.md` 表一致，未来加 riscv32/64 仅扩字段 |
| D6 | **handler → parent 通信** | stderr 一行 marker `BLOCKED-SYSCALL:<nr>:<arch_hex>\n` + `_exit(159)` | 利用既有 stderr pipe，无需额外 syscall |
| D7 | **multi-marker 解析** | 扫描所有行取**最后**匹配行 | 兼容程序自身输出含 `BLOCKED-SYSCALL:` 子串的边角情况 |
| D8 | **handler 实现约束** | async-signal-safe：栈缓冲 + 手写 itoa/hex + `write(2)` + `_exit(159)` | 禁止 malloc/lock/stdio；man:signal-safety(7) |
| D9 | **`SA_RESTART`** | 不设 | syscalls 必须在 SIGSYS 后中断，否则 handler 永远跑不到 |
| D10 | **syscall 名查询 API** | 线性查 13 项 `SYSCALLS`，不引入二分 | 13 项 O(n) 足够，binary search 复杂度溢价不值 |
| D11 | **BPF filter 指令数** | `n + 6` 运行时计算（`total_insns = n + 6`） | 让 `BLACKLIST` 增删项时 BPF 自动跟着变 |
| D12 | **`parse_block_marker` 解析错误处理** | 解析失败 → 当作 marker 不存在 → fallback | 不在 stderr 上报"解析失败"二次错误，避免递归 |

---

## 4. Files to Modify

| 文件 | 改动 | 估算行数 | 风险 |
|---|---|---|---|
| `src/linux/seccomp.rs` | 全量重写：新增 `Syscall`/`SyscallCategory`/`SYSCALLS`/`BLACKLIST`；BPF filter 改运行时长度 `n + 6`；模块内 5 个单测改用 `SYSCALLS`；新增 3 个单测 | +180 / -40 | 中（跨架构 BPF 长度） |
| `src/linux/mod.rs` | 加 `sigsys_handler` / `itoa_into` / `hex_into` / `parse_block_marker`；`pre_exec` 装 `SA_SIGINFO` handler；`classify_exit` Seccomp 分支改写（保留 fallback） | +130 / -5 | 中（async-signal-safety） |
| `tests/seccomp_test.rs` | 删 `blacklist_name` 13 项镜像表（~30 行）；`assert_syscall_blocked` 加 `category='X'` 断言；新增两个 helper `syscall_name_for_test` / `category_for_test` | +20 / -35 | 低（删除的镜像表由 lib 取代） |
| `tests/deny_detect_test.rs` | 增量加 3 个测试：富消息分支、multi-line marker、empty stderr fallback | +60 / 0 | 低 |
| `README.md` | 第 113 行旧消息示例改为新格式 | +1 / -1 | 0 |
| `src/bin/syscall_probe.rs` | **不改** | 0 | 0（SIGSYS 在 syscall 入口拦截，probe print 不影响） |
| **总计** | | **+391 / -81** = **+310 净** | |

---

## 5. Data Model

### 5.1 Granularity 3 设计

**Level 0**（已有）— 数字号数组 — 不再保留
**Level 1**（已弃用方案）— 完整 `Syscall` 的紧凑数组（名+号一对多）—— 不采用
**Level 2**（已弃用方案）— `Syscall` + category 但表硬编码 —— 不够 DRY
**Level 3**（本方案）— `Syscall` + `SyscallCategory` + `SYSCALLS: &[Syscall]` + `BLACKLIST: &[usize]` ——
策略（数字索引）与数据（带语义的元数据）分离，索引方式便于将来"基于 category 删除"等扩展。

### 5.2 完整代码（`src/linux/seccomp.rs` 新增部分）

```rust
// ============================================================================
// 模块顶部依赖与常量（保留）
// ============================================================================
use std::mem::size_of;

// 来源：include/uapi/linux/seccomp.h（内核 3.5+）
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
// 来源：include/uapi/linux/seccomp.h（内核 3.5+）
pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
// 来源：include/uapi/linux/elf.h
pub const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
pub const AUDIT_ARCH_AARCH64: u32 = 0xc000_00e7;

// ============================================================================
// Granularity 3: Syscall / SyscallCategory / SYSCALLS / BLACKLIST
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallCategory {
    MountFilesystem,
    DebugTrace,
    Boot,
    KernelModule,
    Namespace,
    BpfLoader,
}

impl SyscallCategory {
    /// 返回 kebab-case 单字标签，便于 grep 与 Agent 解析。
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

/// 单个被拦截的 syscall 元数据。两架构号均缓存，按编译期 cfg 选取。
///
/// 来源：
/// - x86_64:    `arch/x86/entry/syscalls/syscall_64.tbl`
/// - aarch64:   `arch/arm64/tools/syscall.tbl`
#[derive(Debug, Clone, Copy)]
pub struct Syscall {
    pub name: &'static str,
    pub category: SyscallCategory,
    pub nr_x86_64: u32,
    pub nr_aarch64: u32,
}

impl Syscall {
    /// 当前 target 的 syscall 号。cfg 控制在编译期决策，无运行时分支。
    pub fn nr(&self) -> u32 {
        if cfg!(target_arch = "x86_64") {
            self.nr_x86_64
        } else if cfg!(target_arch = "aarch64") {
            self.nr_aarch64
        } else {
            unreachable!("seccomp: unsupported target architecture");
        }
    }
}

/// 13 项黑名单的统一表。索引顺序与 `docs/linux-sandbox.md` 表格一致，
/// 变更时必须同步更新文档。
///
/// **单一数据源：** 与 `src/linux/seccomp.rs::target_arch_config()` 中的
/// 13 项硬编码表保持一致；x86_64 与 aarch64 syscall 号来自
/// `arch/x86/entry/syscalls/syscall_64.tbl` 与
/// `arch/arm64/tools/syscall_64.tbl`。
pub static SYSCALLS: &[Syscall] = &[
    // ----- MountFilesystem -----
    Syscall { name: "mount",         category: SyscallCategory::MountFilesystem, nr_x86_64: 165, nr_aarch64: 40  },
    Syscall { name: "umount2",       category: SyscallCategory::MountFilesystem, nr_x86_64: 166, nr_aarch64: 39  },
    Syscall { name: "pivot_root",    category: SyscallCategory::MountFilesystem, nr_x86_64: 155, nr_aarch64: 41  },
    Syscall { name: "chroot",        category: SyscallCategory::MountFilesystem, nr_x86_64: 161, nr_aarch64: 51  },
    // ----- DebugTrace -----
    Syscall { name: "ptrace",        category: SyscallCategory::DebugTrace,       nr_x86_64: 101, nr_aarch64: 117 },
    // ----- Boot -----
    Syscall { name: "kexec_load",    category: SyscallCategory::Boot,             nr_x86_64: 246, nr_aarch64: 104 },
    Syscall { name: "kexec_file_load", category: SyscallCategory::Boot,           nr_x86_64: 320, nr_aarch64: 294 },
    Syscall { name: "reboot",        category: SyscallCategory::Boot,             nr_x86_64: 169, nr_aarch64: 142 },
    // ----- KernelModule -----
    Syscall { name: "init_module",   category: SyscallCategory::KernelModule,     nr_x86_64: 175, nr_aarch64: 105 },
    Syscall { name: "finit_module",  category: SyscallCategory::KernelModule,     nr_x86_64: 313, nr_aarch64: 106 },
    Syscall { name: "delete_module", category: SyscallCategory::KernelModule,     nr_x86_64: 176, nr_aarch64: 107 },
    // ----- Namespace -----
    Syscall { name: "unshare",       category: SyscallCategory::Namespace,        nr_x86_64: 97,  nr_aarch64: 97  },
    // ----- BpfLoader -----
    Syscall { name: "bpf",           category: SyscallCategory::BpfLoader,        nr_x86_64: 357, nr_aarch64: 280 },
];

/// 黑名单 = 索引到 `SYSCALLS` 的引用。当前与 SYSCALLS 一一对应；
/// 未来若放开某项只需从本数组移除即可，BPF 构建自动自适应。
pub static BLACKLIST: &[usize] = &[
    0, 1, 2, 3,        // MountFilesystem (mount / umount2 / pivot_root / chroot)
    4,                 // DebugTrace (ptrace)
    5, 6, 7,           // Boot (kexec_load / kexec_file_load / reboot)
    8, 9, 10,          // KernelModule (init_module / finit_module / delete_module)
    11,                // Namespace (unshare)
    12,                // BpfLoader (bpf)
];

pub const BLACKLIST_LEN: usize = 13;

// ============================================================================
// 查询 API（沿用 + 新增）
// ============================================================================

/// 通过 syscall 号查名。返回 None 当该号不在我们已知的 13 项表里。
pub fn syscall_name(nr: u32) -> Option<&'static str> {
    SYSCALLS.iter().find(|s| s.nr() == nr).map(|s| s.name)
}

/// 通过 syscall 名查完整元数据（含 category）。
pub fn syscall_by_name(name: &str) -> Option<&'static Syscall> {
    SYSCALLS.iter().find(|s| s.name == name)
}
```

### 5.3 BPF Filter — 运行时长度

```rust
/// 来源：include/uapi/linux/filter.h — BPF 指令字 64-bit
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct sock_filter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct sock_fprog {
    pub len: u16,
    pub filter: *const sock_filter,
}

pub fn build_sock_fprog(filter: &[sock_filter]) -> sock_fprog { /* ... 旧实现 */ }

/// 运行时计算长度的 BPF 黑名单过滤器。
///
/// 指令布局（按索引）：
///   [0]   LD arch
///   [1]   JEQ <arch>  → [3]
///   [2]   RET KILL (wrong arch)
///   [3]   LD nr
///   [4..3+n]   JEQ <nri>  → [3+n]     // n 条
///   [3+n]  RET KILL                       // die_insn = 3 + n
///
/// 总指令数 = n + 4，其中 die_insn = 3 + n。
pub fn build_blacklist_filter() -> Vec<sock_filter> {
    let (target_arch, syscall_nrs) = target_arch_config();
    let n = syscall_nrs.len();
    let total_insns = n + 4;          // ←关键：随 BLACKLIST 长度自动变
    let die_insn   = total_insns - 1; // 末位

    let mut f: Vec<sock_filter> = Vec::with_capacity(total_insns);

    // [0] LD arch
    push_ld(&mut f, BPF_ABS, 4 /*offsetof(seccomp_data, arch)*/, 0);
    // [1] JEQ arch  jt=1 jf=0
    f.push(insn(BPF_JMP | BPF_JEQ | BPF_K, target_arch, 1, 0));
    // [2] RET KILL (wrong arch)
    f.push(insn(BPF_RET, SECCOMP_RET_KILL_PROCESS, 0, 0));
    // [3] LD nr
    push_ld(&mut f, BPF_ABS, 0 /*offsetof(seccomp_data, nr)*/, 0);

    // [4..3+n] JEQ <nri>
    for (i, &nr) in syscall_nrs.iter().enumerate() {
        // 最后一项 jt=0；非最后项 jt 跳到 die_insn
        let is_last = i + 1 == n;
        let jt = if is_last { 0 } else { (die_insn - (4 + i)) as u8 };
        let jf = 0;
        f.push(insn(BPF_JMP | BPF_JEQ | BPF_K, nr, jt, jf));
    }
    // [3+n] RET KILL
    f.push(insn(BPF_RET, SECCOMP_RET_KILL_PROCESS, 0, 0));

    debug_assert_eq!(f.len(), total_insns);
    f
}

fn target_arch_config() -> (u32, Vec<u32>) {
    let arch = if cfg!(target_arch = "x86_64") {
        AUDIT_ARCH_X86_64
    } else if cfg!(target_arch = "aarch64") {
        AUDIT_ARCH_AARCH64
    } else {
        panic!("seccomp: unsupported target architecture: {}", std::env::consts::ARCH)
    };
    let nrs: Vec<u32> = BLACKLIST.iter().map(|&i| SYSCALLS[i].nr()).collect();
    (arch, nrs)
}
```

### 5.4 模块内单测（5 改 + 3 新）

| 测试名 | 现状 | 改动 |
|---|---|---|
| `filter_length` | 写死 19 | 改 `assert_eq!(filter.len(), BLACKLIST.len() + 4)` |
| `blacklist_jumps_target_die` | 写死范围 | 改 `for i in 4..(BLACKLIST.len() + 4)`，`die_index = filter.len() - 1` |
| `syscall_nrs_count` | 写死 13 | 改 `assert_eq!(BLACKLIST.len(), 13)` |
| `unshare_is_97` | 数字常量化 | 改 `SYSCALLS.iter().find(\|s\| s.name == "unshare\")` 断言 x86_64=97 / aarch64=97 |
| `no_duplicate_syscall_nrs` | 数字 | 改查 `SYSCALLS` 内不同架构号无重复 |
| `syscall_name_resolves` *(new)* | — | 断言 `syscall_name(165) == Some("mount")` |
| `syscall_by_name_resolves` *(new)* | — | 断言 `syscall_by_name("mount").unwrap().category.tag() == "mount"` |
| `blacklist_indices_valid` *(new)* | — | 断言 `BLACKLIST.iter().all(\|&i\| i < SYSCALLS.len())` |

---

## 6. Seccomp Mechanism

### 6.1 KILL_PROCESS → TRAP 转换的理由

| 维度 | KILL_PROCESS（现状） | TRAP（本方案） |
|---|---|---|
| 默认行为 | 立即 SIGKILL 子进程，无任何信号处理可能 | 触发 SIGSYS，可装 handler |
| 可观察 syscall 号 | 否（仅 exit 31） | 是（`si_syscall`）|
| 可观察 arch | 否 | 是（`si_arch`）|
| 与现有 exit-code 分类兼容 | 是（31） | 是（159，我们改用此）|
| 性能 | 略微更便宜 | 一次用户/内核切换（可忽略） |

### 6.2 exit-code 变化

- `exit_code == 31`（SIGSYS + KILL_PROCESS）→ 现 handler 跑 `KILL_PROCESS`，**仍可能产生 31**
- `exit_code == 31`（SIGSYS + TRAP，handler 未装）→ 同样 31
- `exit_code == 159`（SIGSYS + TRAP，handler 跑过且 `_exit(159)`）→ 新增

`classify_exit` 必须同时检查 **31 和 159**，因为：
- 内核老版本不带 `SA_SIGINFO` 填充 → exit_code 可能是 31
- 新路径：handler 成功 → 159

### 6.3 SIGSYS Handler — Async-Signal-Safe 代码

完整实现（`src/linux/mod.rs` 内）：

```rust
use std::cell::UnsafeCell;
use std::sync::Once;

/// 全局 marker 缓冲。SIGSYS 在多线程 fork 后可能并发到达 SIGSYS，但每个子进程
/// 只触发一次（首条黑名单 syscall 之后会持续 SIGSYS），故单缓冲足够。
/// 主线程 install 时独占写，信号触发只读 + 写 stderr + _exit。
struct HandlerGlobals {
    /// 4 KiB 足够容纳最长 marker（"BLOCKED-SYSCALL:4294967295:ffffffff\n" ≈ 40B）。
    /// 非 `static mut`，避免其他 unsafe 代码也能写。
    buf: UnsafeCell<[u8; 64]>,
}
unsafe impl Sync for HandlerGlobals {} // 只在 sigaction install 前被主线程初始化

static HANDLER_GLOBALS: HandlerGlobals = HandlerGlobals {
    buf: UnsafeCell::new([0u8; 64]),
};

/// 十进制写入。返回新 pos。栈缓冲上无需 Sync。
fn itoa_into(buf: &mut [u8], mut pos: usize, mut v: u32) -> usize {
    if v == 0 {
        buf[pos] = b'0';
        return pos + 1;
    }
    let start = pos;
    while v > 0 {
        buf[pos] = b'0' + (v % 10) as u8;
        v /= 10;
        pos += 1;
    }
    // 反转 [start, pos)
    let mut i = start;
    let mut j = pos - 1;
    while i < j {
        buf.swap(i, j);
        i += 1;
        j -= 1;
    }
    pos
}

/// 小写 hex 写入（无 0x 前缀）。返回新 pos。
fn hex_into(buf: &mut [u8], mut pos: usize, mut v: u32) -> usize {
    if v == 0 {
        buf[pos] = b'0';
        return pos + 1;
    }
    let start = pos;
    while v > 0 {
        let nibble = (v & 0xf) as u8;
        buf[pos] = if nibble < 10 { b'0' + nibble } else { b'a' + nibble - 10 };
        v >>= 4;
        pos += 1;
    }
    let mut i = start;
    let mut j = pos - 1;
    while i < j {
        buf.swap(i, j);
        i += 1;
        j -= 1;
    }
    pos
}

/// SIGSYS handler — async-signal-safe。
///
/// 约束（man:signal-safety(7)）：
/// - 仅写 stack buffer / 调用 `write(2)` / `_exit(2)`
/// - 无 malloc / 无 std::fmt / 无 std::sync / 无 std::io
/// - 不修改任何 `static mut`（除 HANDLER_GLOBALS.buf 一次性预清零写）
extern "C" fn sigsys_handler(
    _sig: libc::c_int,
    info: *mut libc::siginfo_t,
    _ucontext: *mut libc::c_void,
) {
    // SAFETY: SA_SIGINFO 安装时已确保 info 非空且 si_syscall/si_arch 已填充。
    //         libc 的 si_syscall/si_arch 字段在 0.2.x 全版本稳定；若版本不可用
    //         则回退到 `(*info)._sifields._sigsys.{si_syscall, si_arch}` 原始路径。
    let nr: u32 = unsafe { (*info).si_syscall() } as u32;
    let arch: u32 = unsafe { (*info).si_arch() } as u32;

    // SAFETY: 单线程下本 handler 是唯一写者；fork 后子进程独立地址空间。
    let buf = unsafe { &mut *HANDLER_GLOBALS.buf.get() };
    let prefix = b"BLOCKED-SYSCALL:";
    let mut pos = 0;
    buf[pos..pos + prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();

    pos = itoa_into(buf, pos, nr);
    buf[pos] = b':';
    pos += 1;
    pos = hex_into(buf, pos, arch);
    buf[pos] = b'\n';
    pos += 1;

    // SAFETY: write(2) 是 async-signal-safe；buf 指向有效栈内存。
    unsafe {
        // 写入后立即 _exit(159)，故即使 write 阻塞也无所谓——子进程立刻终止。
        libc::write(2, buf.as_ptr() as *const _, pos);
        libc::_exit(159);
    }
}

/// 在 pre_exec 闭包中调用。安装 SIGSYS handler，必须早于 SECCOMP 加载。
///
/// 必须显式 SA_SIGINFO（不是 SA_SIG）才能让 `info` 字段有效；
/// 必须**不**设 SA_RESTART，让 SIGSYS 中断 syscall，handler 才有机会跑。
pub fn install_sigsys_handler() -> std::io::Result<()> {
    static INSTALLED: Once = Once::new();
    let mut result: std::io::Result<()> = Ok(());

    INSTALLED.call_once(|| {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = sigsys_handler as libc::sighandler_t;
        sa.sa_flags = libc::SA_SIGINFO; // 只要这一个 flag
        // SAFETY: sigemptyset 是 async-signal-safe
        if unsafe { libc::sigemptyset(&mut sa.sa_mask) } != 0 {
            result = Err(std::io::Error::last_os_error());
            return;
        }
        let r = unsafe {
            libc::sigaction(libc::SIGSYS, &sa, std::ptr::null_mut())
        };
        if r != 0 {
            result = Err(std::io::Error::last_os_error());
        }
    });

    result
}
```

### 6.4 Async-Signal-Safety 推导

调用栈（信号上下文内允许）：
- `cvt!(*info).si_syscall` — 纯指针解引用，无 syscall
- `itoa_into` / `hex_into` — 纯算术 + 栈上 `&mut [u8]` 写，无 syscall
- `libc::write(2, ...)` — POSIX 列入 `signal-safety(7)` 允许列表
- `libc::_exit(159)` — POSIX 列入允许列表（立刻终止，无 atexit / stdio 清理）

**禁止调用的反例（明确不在 handler 内）：** `Vec::push`、`String::from`、`format!`、`println!`、`Mutex::lock`、`std::io::Write::write_all`、`libc::malloc`、`exit(3)`（会运行 atexit handler，可能死锁）。

---

## 7. classify_exit 改写

### 7.1 函数体（保留 Landlock 与 stderr 模式分支不动的部分）

```rust
/// 来源：src/lib.rs::ExitReason / DenyMechanism（沿用不变）
pub fn classify_exit(&self, exit_code: i32, stderr: &str) -> ExitReason {
    // --- Landlock 分支（不变） ---
    if exit_code != 0
        && stderr.contains("Read-only file system")
        && stderr.contains("Operation not permitted")
    {
        return ExitReason::Denied {
            mechanism: DenyMechanism::Landlock,
            message: "filesystem access denied by Landlock ruleset".into(),
        };
    }

    // --- stderr 特征串分支（不变） ---
    if stderr.contains("Blocked by Landlock") {
        return ExitReason::Denied {
            mechanism: DenyMechanism::Landlock,
            message: stderr.to_string(),
        };
    }

    // === Seccomp 分支（重写）===
    //
    // 触发条件：exit_code == 31 (SIGSYS + TRAP, handler 未跑) 或
    //           exit_code == 159 (SIGSYS + TRAP, handler 跑了 _exit(159))
    //
    // 富消息路径：marker 存在且解析成功 → 新格式字符串
    // fallback 路径：marker 缺失 / 解析失败 → 旧消息（向后兼容）
    if exit_code == 31 || exit_code == 159 {
        if let Some((nr, arch)) = parse_block_marker(stderr) {
            let name = seccomp::syscall_name(nr).unwrap_or("unknown");
            let category = seccomp::syscall_by_name(name)
                .map(|s| s.category.tag())
                .unwrap_or("unknown");
            return ExitReason::Denied {
                mechanism: DenyMechanism::Seccomp,
                message: format!(
                    "blocked syscall='{}' category='{}' nr={} arch=0x{:x} \
                     reason=blacklist signal=SIGSYS",
                    name, category, nr, arch
                ),
            };
        }
        // ====== fallback 路径 ======
        // 兼容场景：
        //   1. SIGSYS handler 未安装（pre_exec 早 return）
        //   2. 子进程在 sandbox 装好前自己写 stderr 并触发 exit_code=31
        //   3. marker 被二进制截断 / 解析失败（malformed）
        //   4. SIGKILL 路径（极少数的内核 bug：SIGSYS 未送达）
        // 这些场景 stderr 不可读或不含 marker，但仍能由 exit_code 锁定 Seccomp 来源。
        return ExitReason::Denied {
            mechanism: DenyMechanism::Seccomp,
            message: "Blocked by seccomp filter (SIGSYS)".into(),
        };
    }

    if exit_code == 0 {
        ExitReason::Ok
    } else {
        ExitReason::Program(exit_code)
    }
}
```

### 7.2 parse_block_marker 实现

```rust
/// 扫描 stderr 中所有以 `BLOCKED-SYSCALL:<int>:<hex>` 形式的行，返回**最后**匹配的
/// (nr, arch)。多行扫描是为了兼容程序自己向 stderr 输出含此 marker 子串的情况。
///
/// 设计取舍：
/// - 返回 Option 而非 Result：解析失败等价于"marker 不存在"，统一 fallback 路径处理。
/// - 用 splitn(2, ':') 防止 arch 字段中冒号干扰（虽然 hex 不含冒号，防御性写法）。
fn parse_block_marker(stderr: &str) -> Option<(u32, u32)> {
    let mut result: Option<(u32, u32)> = None;
    for line in stderr.lines() {
        if let Some(rest) = line.strip_prefix("BLOCKED-SYSCALL:") {
            let mut parts = rest.splitn(2, ':');
            let nr_s   = parts.next();
            let arch_s = parts.next();
            if let (Some(n), Some(a)) = (nr_s, arch_s) {
                if let (Ok(nr), Ok(arch)) = (
                    n.parse::<u32>(),
                    u32::from_str_radix(a.trim(), 16),
                ) {
                    result = Some((nr, arch));
                }
            }
        }
    }
    result
}
```

### 7.3 pre_exec 中 handler 安装点

```rust
// 来源：src/linux/mod.rs::pre_exec（snapshot of new sequence）

use crate::linux::sig_handler::install_sigsys_handler;

fn pre_exec(...) -> std::io::Error {
    // 1. Landlock ruleset（先做，土地规则覆盖路径）
    landlock::apply_ruleset(...)?;

    // 2. 安装 SIGSYS handler —— 必须在 seccomp 装 BPF 之前
    //    让 SIGSYS 能被捕获，而不是被默认动作杀掉。
    install_sigsys_handler()?;

    // 3. seccomp BPF
    seccomp::apply_blacklist()?;

    Ok(())
}
```

### 7.4 stderr 完整路径示意

```
subprogram (probe)
    │
    ├─ write "BLOCKED-SYSCALL:165:c000003e\n"   ← SIGSYS handler 直接 write(2) 到 stderr
    └─ _exit(159)
                                          ↓ fork+exec 的 stderr pipe
父进程（seabox）
    │
    └─ collect stderr
        │
        ├─ exit_code = 159
        └─ stderr = "...some program output...\nBLOCKED-SYSCALL:165:c000003e\n"
              │
              └─ classify_exit(159, stderr)
                    │
                    ├─ parse_block_marker → Some((165, 0xc000003e))
                    ├─ syscall_name(165) → "mount"
                    ├─ syscall_by_name("mount").category.tag() → "mount"
                    └─ message = "blocked syscall='mount' category='mount' \
                                  nr=165 arch=0xc000003e reason=blacklist signal=SIGSYS"

最终 println:
    "Sandbox denial (Seccomp): blocked syscall='mount' category='mount' nr=165 arch=0xc000003e reason=blacklist signal=SIGSYS"
```

---

## 8. Test Contract

> **优先级：** ★★★ 必测（阻塞合并）/ ★★ 可推迟到下一 PR / ★ 仅手动冒烟

### 8.1 单元测试（在 `src/linux/seccomp.rs` 内部）

| ID | 测试名 | 验收方法 | 优先级 |
|---|---|---|---|
| U-1 | `filter_length` | `filter.len() == BLACKLIST.len() + 4` | ★★★ |
| U-2 | `blacklist_jumps_target_die` | 循环 4..(BL+4)，`die_index = filter.len() - 1`，每条 je 指令的 jt 非最后项时 = die_index 偏移 | ★★★ |
| U-3 | `syscall_nrs_count` | `BLACKLIST.len() == 13` | ★★★ |
| U-4 | `unshare_is_97` | 查 SYSCALLS by name，断言 x86_64/aarch64 都是 97 | ★★★ |
| U-5 | `no_duplicate_syscall_nrs` | SYSCALLS 内不同架构号无重复 | ★★★ |
| U-6 | `syscall_name_resolves` | 165 → "mount"；97 → "unshare"；357 → Some(_) | ★★★ |
| U-7 | `syscall_by_name_resolves` | category.tag() 命中："mount"→"mount"，"ptrace"→"debug" | ★★★ |
| U-8 | `blacklist_indices_valid` | `BLACKLIST.iter().all(\|&i\| i < SYSCALLS.len())` | ★★★ |

### 8.2 单元测试（在 `src/linux/mod.rs` 内部）

| ID | 测试名 | 验收方法 | 优先级 |
|---|---|---|---|
| U-9 | `itoa_into_zero` | `itoa_into(&mut buf, 0, 0)` → pos=1, buf=[b'0'] | ★★ |
| U-10 | `itoa_into_4294967295` | u32::MAX → "4294967295" 9字符正序 | ★★ |
| U-11 | `hex_into_0xc000003e` | → "c000003e" 8字符小写 | ★★ |
| U-12 | `parse_block_marker_simple` | `"BLOCKED-SYSCALL:165:c000003e\n"` → Some((165, 0xc000003e)) | ★★★ |
| U-13 | `parse_block_marker_last_wins` | 多行取最后一个匹配 | ★★★ |
| U-14 | `parse_block_marker_malformed` | `"BLOCKED-SYSCALL:abc:xyz"` → None | ★★ |
| U-15 | `parse_block_marker_empty` | `""` → None | ★★★ |
| U-16 | `parse_block_marker_no_prefix` | `"hello world"` → None | ★★★ |

### 8.3 集成测试（在 `tests/deny_detect_test.rs`）

**保留 8 个旧测试不动**（fallback 路径保证）。新增 3 个：

| ID | 测试名 | 验收方法 | 优先级 |
|---|---|---|---|
| D-1 | `exit_159_with_block_marker_returns_rich_message` | exit=159 + marker `(165, 0xc000003e)` → message 含 `syscall='mount'`, `category='mount'`, `nr=165`, `arch=0xc000003e`, `signal=SIGSYS` | ★★★ |
| D-2 | `exit_31_with_block_marker_uses_last_line` | exit=31 + 多行 stderr → 解析最后一行 `BLOCKED-SYSCALL:97:c000003e` → `syscall='unshare'`, `nr=97` | ★★ |
| D-3 | `exit_159_empty_stderr_falls_back` | exit=159 + `stderr=""` → message 严格等于 `"Blocked by seccomp filter (SIGSYS)"`（不破坏 8 个旧测试） | ★★★ |

### 8.4 集成测试（在 `tests/seccomp_test.rs`）

| ID | 测试名 | 验收方法 | 优先级 |
|---|---|---|---|
| S-1 ~ S-13 | `assert_syscall_blocked(165)` 等 13 个 | 改：调用 `syscall_name_for_test(nr)` 拿名（**不再用镜像表**），断言含：<br>• `syscall='<name>'`<br>• `nr=<nr>`<br>• `category='<tag>'`<br>• `arch=0x...`<br>• `reason=blacklist`<br>• `signal=SIGSYS` | ★★★ |
| S-14 | `seccomp_e2e_full_message_e2e` | 选 mount(165) 端到端跑 + 比对完整 message 字符串 | ★★ |
| S-15 | `seccomp_e2e_category_matches` | ptrace(101) → category='debug'；unshare(97) → category='namespace'；bpf(321) → category='bpf' | ★★★ |
| S-16 | `seccomp_probe_no_marker_after_handler` *(探针新)* | 验证 handler 已装：未拦的 syscall（如 getuid）正常返回，间接证明 handler 不影响非拦截路径 | ★★ |

### 8.5 Landlock 不受影响保证

| ID | 测试名 | 验收方法 | 优先级 |
|---|---|---|---|
| L-0 | `tests/landlock_test.rs` 全部测试 | `cargo test --test landlock_test` 全绿，不动 | ★★★ |

### 8.6 手动冒烟（不属于 cargo test）

| ID | 命令 | 期望输出 | 优先级 |
|---|---|---|---|
| M-1 | `./seabox run --policy full-access -- ./syscall_probe 165 0 0 0 0 0 0` | exit 126；stderr 以 `Sandbox denial (Seccomp): blocked syscall='mount' category='mount' nr=165 arch=0xc000003e ...` 结尾 | ★★ |
| M-2 | 同 M-1 但 syscall=357 (bpf) | exit 126；stderr 含 `syscall='bpf' category='bpf'` | ★★ |
| M-3 | 同 M-1 但 syscall=97 (unshare) | exit 126；stderr 含 `syscall='unshare' category='namespace'` | ★★ |
| M-4 | 同 M-1 但用 read-only 策略 + probe=17 (read) | 不被 seccomp 拦；read 系统调用正常执行；无 `Sandbox denial` 字样 | ★ |

### 8.7 总览：测试数量与覆盖矩阵

| 类别 | 数量 | 改动性质 |
|---|---|---|
| 旧单元测试（保留） | 5 (seccomp.rs) | 内容改用 SYSCALLS |
| 新单元测试 | 3 + 8 = 11 | 新 |
| 旧 deny_detect（保留） | 8 | 完全不动 |
| 新 deny_detect | 3 | 增量 |
| 旧 seccomp e2e（13 syscall × 镜像断言） | ~13 | 镜像断言改用 SYSCALLS |
| 新 seccomp e2e | 3-4 | 增量断言 |
| Landlock（不碰） | 全部 | 不动 |
| 手动冒烟 | 4 | 文档示例 |

---

## 9. Verification

按以下顺序执行，每步通过才进下一步。

```bash
# =========================================================
# 1. 静态检查：必须先通过编译
# =========================================================
cargo check                                # 主二进制编译
cargo check --tests                        # 所有集成测试编译
cargo check --bin syscall_probe            # 辅助二进制编译

# =========================================================
# 2. 代码风格
# =========================================================
cargo fmt --check
cargo clippy -- -D warnings                # 严格 lint，0 warning

# =========================================================
# 3. 库单元测试（快，先跑）
# =========================================================
cargo test --lib                           # 涵盖 U-1..U-16
cargo test --lib seccomp::                 # 仅 seccomp 模块内
cargo test --lib mod::                     # 仅 handler + classify_exit 相关

# =========================================================
# 4. 集成测试（按文件）
# =========================================================
cargo test --test deny_detect_test         # 8 旧 + 3 新 = 11 个
cargo test --test seccomp_test             # 13 e2e + 3 新增
cargo test --test landlock_test            # 回归：landlock 不受影响
cargo test --test config_test              # 回归：config 解析不受影响

# =========================================================
# 5. 全部测试 + 串行看到每个测试结果
# =========================================================
cargo test -- --nocapture --test-threads=1 2>&1 | tee /tmp/test_run.log

# =========================================================
# 6. 手动冒烟（验证 stderr 富消息）
# =========================================================
cargo build --release
cargo build --bin syscall_probe

# 测试 1: mount
./target/release/seabox run --policy full-access -- \
    ./target/debug/syscall_probe 165 0 0 0 0 0 0
# 期望:
#   - exit code = 126
#   - stderr 末行为:
#     "Sandbox denial (Seccomp): blocked syscall='mount' category='mount' \
#      nr=165 arch=0xc000003e reason=blacklist signal=SIGSYS"

# 测试 2: bpf
./target/release/seabox run --policy full-access -- \
    ./target/debug/syscall_probe 357 0 0 0
# 期望: 含 "syscall='bpf' category='bpf' nr=357 arch=0xc000003e ..."

# 测试 3: unshare
./target/release/seabox run --policy full-access -- \
    ./target/debug/syscall_probe 97 0
# 期望: 含 "syscall='unshare' category='namespace' nr=97 arch=0xc000003e ..."

# 测试 4: fallback 路径（强制 marker 缺失）
./target/release/seabox run --policy read-only -- \
    ./syscall_probe 165 0 0 0 0 0 0 2>&1 | grep -v BLOCKED-SYSCALL
# 若 landlock 拦截先发生，stderr 不一定带 marker——此 case 仅观察 stderr 富消息路径是否生效
```

### 9.1 退出期望

- 所有 `cargo test` 通过（含 skip 因内核能力缺失）
- `cargo clippy -- -D warnings` 通过
- 4 个手动冒烟按预期输出

### 9.2 跳过条件的语义保留

内核能力缺失（无 Landlock / 无 seccomp / 无 user_namespace）时测试**自动跳过**（沿用既有 `verify_*_active` 探针 + `OnceLock` 缓存），不视为失败。

---

## 10. Risks

| 风险 | 概率 | 影响 | 缓解 |
|---|---|---|---|
| `si_syscall()` / `si_arch()` 在某些 libc 版本不可用 | 低 | handler 编译失败 | 用 raw 路径 `(*info)._sifields._sigsys.{si_syscall, si_arch}` 兜底；libc 0.2.x 多年稳定（已查） |
| `SA_RESTART` 被错误设置 | 低 | syscall 自动重启、handler 不跑 | 代码评审 anchor + `tests/seccomp_test.rs` 验证 exit=126；handler 函数注释强制**只设 `SA_SIGINFO`** |
| handler 内调 malloc/lock/stdio 导致死锁 | 极低（已 review 代码路径） | 子进程 hang，父进程 pipe 阻塞 | 全部走栈缓冲 + 手写 itoa/hex + `write(2)` + `_exit(159)`；**禁止**调 `Vec::push` / `format!` / `println!` / `Mutex::lock` |
| `parse_block_marker` 多行漏匹配 | 低 | message 退化为 fallback（旧消息） | 扫描所有行取**最后**匹配；D-2 测试覆盖多行情况 |
| aarch64 上 BPF filter 长度常量不对 | 中 | 跨架构 panic | `build_blacklist_filter` 用 `n + 4` 运行时计算；模块内单测 `filter_length` 用 `BLACKLIST.len() + 4` 跨架构验证 |
| 13 项 BLACKLIST 改了但 SYSCALLS 表漏更新 | 低 | BPF 与查询不一致 | 静态数组同文件，单测 `blacklist_indices_valid` 校验所有索引 < SYSCALLS.len() |
| `deny_detect_test` 旧 8 个测试被破坏 | 低 | 阻塞合并 | fallback 路径**完全保留旧消息字面量**；新增 `exit_159_empty_stderr_falls_back` 测试断言严格相等 |
| libc::write 在 handler 内阻塞（pipe 满） | 极低 | 子进程 hang | handler 内 write 后立刻 `_exit(159)`，write 本应 < 64B，远小于 pipe 默认 64KB |
| 未来 BPF filter 增加导致 `total_insns` 溢出 u8 jt 字段 | 中（在 255 项以内安全） | jump offset 截断，BPF 行为错误 | 当前 13+4=17 项，jt 字段 u8 可承载 ±255 项；新增超过前需重构 BPF（Out of Scope） |
| SIGKILL 路径下 marker 写不出去 | 极低 | fallback | exit_code=137 不在 Seccomp 分支匹配；最终被分为 `ExitReason::Program(137)` |

---

## 11. Out of Scope（YAGNI）

明确**不**在本次工作：

1. **`SyscallCategory` 新增变体**（如 `Network`）—— 13 项 syscall 不涵盖网络策略；网络策略由 Landlock + 命名空间层负责
2. **`SYSCALLS` / `BLACKLIST` 反序列化**（TOML/JSON）—— 配置复杂度溢出，留待用户自定义策略
3. **`syscall_name` 二分查找** —— 13 项 O(n) < 100ns，复杂度溢价不值
4. **用户自定义 blacklist** —— 需要配置文件 + builder 改写，是独立大特性
5. **handler 国际化** —— stderr marker 与英文 message，无 i18n 计划
6. **`SECCOMP_RET_USER_NOTIF`** —— 拿 syscall args 需要 supervisor 进程，工作量翻倍；下个 PR
7. **`LANDLOCK** 富消息改造** —— 本次仅 seccomp，Landlock 分支已足够清晰
8. **macOS Seatbelt profile 同步富消息** —— 平台差异大，独立 PR
9. **HTTP API 字段扩展** —— `Denied.message` 已经是 String，consumer 直接 parse 即可，不需要新字段
10. **错误码分级**（区分用户错 vs 系统错）—— 当前统一走 `Denied`，需要产品决策
11. **BPF filter 动态 length 检查**（超过 255 项）—— 当前 13 项远未触及

---

## 12. Rollout & Follow-up

### 12.1 合并顺序

1. PR-1：seccomp.rs 重写（数据模型 + BPF）+ 单元测试
2. PR-2：linux/mod.rs handler + pre_exec + classify_exit 改写
3. PR-3：seccomp_test + deny_detect_test 改造 + README 更新
4. （可选）PR-4：follow-up issues for Out of Scope #6 等

每个 PR 独立 reviewable，独立 `cargo test` 可全绿。

### 12.2 Follow-up Issues 候选

- `SECCOMP_RET_USER_NOTIF` 支持（拿 syscall args）
- BPF filter 大小自适应（> 255 项时换 BPF 链接）
- 用户级 `SandboxConfig.blacklist` 字段
- Landlock 富消息同步改造
- HTTP API 增加结构化 `syscall_id` 字段
