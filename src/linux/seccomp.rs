//! seccomp BPF filter 构建与安装。
//!
//! 本模块提供两种 seccomp filter 安装方式：
//!
//! - [`build_deny_filter`] + [`install_user_notif_filter`]：为指定的
//!   syscall 号构建 USER_NOTIF filter，拦截时通知父进程（精确诊断）。
//! - [`install_plain_filter`]：prctl 直装外部 BPF（无诊断）。
//!
//! BPF 程序具备架构感知能力：会检查 `seccomp_data.arch` 并拒绝来自
//! 未知架构的 syscall。x86_64 与 aarch64 的 syscall 号不同，因此
//! filter 在运行时通过 `cfg!(target_arch = ...)` 选取正确的号码来构建。
//!
//! # 拦截 → 通知流程（USER_NOTIF 路径）
//!
//! 1. **父进程** 调用 [`build_deny_filter`] 生成 BPF。
//! 2. **子进程**（fork 后 exec 前）调用 [`install_user_notif_filter`]，
//!    传入 BPF filter。该函数通过 `seccomp(2)` 系统调用加载 filter 并
//!    同时返回一个 listener fd（`SECCOMP_FILTER_FLAG_NEW_LISTENER`）。
//! 3. 子进程把这个 listener fd 通过 `sendmsg(SCM_RIGHTS)` 发送给父进程。
//! 4. **父进程** 从 socketpair 收 listener fd，进入 poll/recv/send 循环：
//!    - `ioctl(SECCOMP_IOCTL_NOTIF_RECV)` 阻塞读 `seccomp_notif`
//!    - 把 `seccomp_notif.data.{nr,arch}` 上报为 `(nr, arch)`
//!    - 用 `ioctl(SECCOMP_IOCTL_NOTIF_SEND)` 回复
//!      `seccomp_notif_resp { val: 0, error: libc::EPERM, flags: 0 }`，
//!      让 syscall 在子进程里以 EPERM 返回（不进入 syscall 主体）。
//!
//! # Safety
//!
//! `install_user_notif_filter` 和 `install_plain_filter` 调用
//! `libc::prctl` 与 `libc::syscall`，本身就是 `unsafe`。每个调用点
//! 都附有 `// SAFETY:` 注释解释合理性。

use std::io;
use std::os::unix::io::RawFd;
use std::path::Path;

use anyhow::Context;

// ---------------------------------------------------------------------------
// BPF 指令编码
// ---------------------------------------------------------------------------

/// BPF 指令 class：BPF_LD（load）
const BPF_LD: u16 = 0x00;

/// BPF 指令 class：BPF_JMP（jump）
const BPF_JMP: u16 = 0x05;

/// BPF 指令 class：BPF_RET（return）
const BPF_RET: u16 = 0x06;

/// BPF load 尺寸：32 位字
const BPF_W: u16 = 0x00;

/// BPF load 模式：绝对偏移（与 `BPF_LD | BPF_W` 配合使用）
const BPF_ABS: u16 = 0x20;

/// BPF 跳转条件：当 A == k 时跳转（与 `BPF_JMP` 配合使用）
const BPF_JEQ: u16 = 0x10;

/// BPF 源操作数为常量（与 `BPF_JMP | BPF_JEQ` 配合使用）
const BPF_K: u16 = 0x00;

// ---------------------------------------------------------------------------
// seccomp 返回值（linux/seccomp.h）
// ---------------------------------------------------------------------------

/// 立即杀死调用进程（seccomp action）。用于架构不匹配分支。
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;

/// 把 syscall 拦截事件转发到 listener fd，由父进程响应（user notification）。
///
/// 一旦 filter 返回该 action，子进程会被阻塞在该 syscall 直到父进程通过
/// `SECCOMP_IOCTL_NOTIF_SEND` 给出响应或子进程被信号打断。
/// 该值与 `libc::SECCOMP_RET_USER_NOTIF` 一致；这里再次声明以便不依赖
/// 较新版本 libc 暴露的常量。
const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;

/// 放行 syscall。
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

// ---------------------------------------------------------------------------
// 审计架构常量（linux/audit.h）
// ---------------------------------------------------------------------------

/// x86_64 审计架构标识。
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

/// aarch64 审计架构标识。
const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;

// ---------------------------------------------------------------------------
// prctl 常量（linux/prctl.h）
// ---------------------------------------------------------------------------

/// `prctl` 选项：设置 no_new_privs（man:prctl(2) PR_SET_NO_NEW_PRIVS）。
const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;

// ---------------------------------------------------------------------------
// seccomp syscall 与 flag 常量（linux/seccomp.h）
// ---------------------------------------------------------------------------

/// `seccomp(2)` 子命令：加载 BPF filter 并（可选）创建 listener fd。
///
/// 与 `libc::SECCOMP_SET_MODE_FILTER` 等价；这里重复定义以便
/// `install_user_notif_filter` 直接使用字面常量。
const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;

/// `seccomp(SECCOMP_SET_MODE_FILTER, ...)` flag：在加载 filter 的同时
/// 返回一个新创建的 listener fd（用于 user notification）。
///
/// 与 `libc::SECCOMP_FILTER_FLAG_NEW_LISTENER` 等价。
const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_ulong = 1 << 3;

// ---------------------------------------------------------------------------
// seccomp_notif ioctl 号（linux/seccomp.h）
// ---------------------------------------------------------------------------

/// SECCOMP_IOCTL_NOTIF_RECV —— 阻塞读取一个待处理的 syscall 拦截通知。
///
/// 由 `_IOWR('!', 0, struct seccomp_notif)` 编码（`SECCOMP_IOC_MAGIC = '!'`）。
/// 在 x86_64 上展开为 `0xC0502100`（dir=IOWR, size=80, type='!', nr=0）。
/// libc 不直接暴露这个值，需要按内核头逐项算出来。
pub const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = 0xC050_2100;

/// SECCOMP_IOCTL_NOTIF_SEND —— 向 listener 提交对拦截 syscall 的响应。
///
/// 由 `_IOWR('!', 1, struct seccomp_notif_resp)` 编码；在 x86_64 上
/// 展开为 `0xC0182101`（dir=IOWR, size=24, type='!', nr=1）。
pub const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = 0xC018_2101;

// ---------------------------------------------------------------------------
// BPF 结构体定义
// ---------------------------------------------------------------------------

/// 单条 BPF 指令（亦称 `sock_filter`）。
///
/// 布局与内核 `include/uapi/linux/filter.h` 中的 `struct sock_filter` 一致。
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct sock_filter {
    /// BPF 操作码（如 `BPF_LD | BPF_W | BPF_ABS`）。
    pub code: u16,
    /// 比较为真时的跳转偏移（要跳过的指令数）。
    pub jt: u8,
    /// 比较为假时的跳转偏移。
    pub jf: u8,
    /// 通用操作数（取决于操作码）。
    pub k: u32,
}

/// BPF 程序头（亦称 `sock_fprog`）。
///
/// 布局与内核 `include/uapi/linux/filter.h` 中的 `sock_fprog` 一致。
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct sock_fprog {
    /// filter 中的指令数。
    pub len: u16,
    /// 指向首条指令的指针。
    pub filter: *const sock_filter,
}

// SAFETY：`sock_fprog` 仅在 fork 之后的 `pre_exec` 闭包内使用。
// fork 之后子进程独占访问，指针所指的是不可变的 BPF 指令数据，
// 在 `prctl(PR_SET_SECCOMP, ...)` 期间只读。不存在数据竞争。
unsafe impl Send for sock_fprog {}
unsafe impl Sync for sock_fprog {}

// ---------------------------------------------------------------------------
// seccomp ABI 结构体（linux/seccomp.h）— user notification 接口
// ---------------------------------------------------------------------------

/// 单个 syscall 参数 + 通用元数据（`struct seccomp_data`）。
///
/// 布局与内核 `struct seccomp_data` 完全一致：
/// `nr` 是 `__s32`，但 BPF 加载指令按 `__u32` 处理；这里保持 `i32`
/// 仅用于在 Rust 端解析。
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct seccomp_data {
    /// syscall 号（与 `arch` 联合决定调用约定）。
    pub nr: i32,
    /// 架构标识（`AUDIT_ARCH_*`）。
    pub arch: u32,
    /// syscall 进入点的指令指针（64 位）。
    pub instruction_pointer: u64,
    /// 6 个 syscall 参数，全部按 64 位保存。
    pub args: [u64; 6],
}

/// 一条 user notification 消息（`struct seccomp_notif`）。
///
/// 内核在每次 filter 返回 `SECCOMP_RET_USER_NOTIF` 时向 listener fd
/// 投递一个该结构体。
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct seccomp_notif {
    /// 通知唯一标识，listener 在响应时必须回传。
    pub id: u64,
    /// 触发拦截的子进程 pid。
    pub pid: u32,
    /// 保留字段（当前为 0）。
    pub flags: u32,
    /// 触发拦截的 syscall 的完整描述。
    pub data: seccomp_data,
}

/// listener 对一条通知的响应（`struct seccomp_notif_resp`）。
///
/// `val` 与 `error` 二选一：若 `flags` 含 `SECCOMP_USER_NOTIF_FLAG_CONTINUE`
/// 则让 syscall 继续执行（`val`/`error` 被忽略）；否则以 `error` 作为
/// errno 返回，进程不会真正进入 syscall。
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct seccomp_notif_resp {
    /// 响应哪条通知（回传 `seccomp_notif.id`）。
    pub id: u64,
    /// 当 `flags` 不含 CONTINUE 时，作为 syscall 返回值。
    /// 在本实现中我们用 `error` 字段直接返回 errno，val 忽略。
    pub val: i64,
    /// 当 `flags` 不含 CONTINUE 时，作为 errno 返回（0 表示成功）。
    pub error: i32,
    /// 响应标志；0 = 强制按 `error` 杀死 syscall。
    pub flags: u32,
}

// ---------------------------------------------------------------------------
// Granularity 3 数据模型：Syscall / SyscallCategory / SYSCALLS / BLACKLIST
// ---------------------------------------------------------------------------

/// 单个 syscall 的元数据：两架构号均缓存，编译期 cfg 选取。
///
/// 来源：
/// - x86_64: `arch/x86/entry/syscalls/syscall_64.tbl`
/// - aarch64: `arch/arm64/tools/syscall.tbl`
#[derive(Debug, Clone, Copy)]
pub struct Syscall {
    /// syscall 名（小写、来自 `<sys/syscall.h>` 或 man page）。
    pub name: &'static str,
    /// x86_64 上的 syscall 号。
    pub nr_x86_64: u32,
    /// aarch64 上的 syscall 号。
    pub nr_aarch64: u32,
}

impl Syscall {
    /// 当前编译目标的 syscall 号。cfg 控制在编译期决策，无运行时分支。
    pub fn nr(&self) -> u32 {
        if cfg!(target_arch = "x86_64") {
            self.nr_x86_64
        } else if cfg!(target_arch = "aarch64") {
            self.nr_aarch64
        } else {
            unreachable!("seccomp: unsupported target architecture")
        }
    }
}

/// 已知 syscall 的诊断查表。保留用于 `syscall_name()` 等诊断函数。
pub static SYSCALLS: &[Syscall] = &[
    Syscall {
        name: "mount",
        nr_x86_64: 165,
        nr_aarch64: 40,
    },
    Syscall {
        name: "umount2",
        nr_x86_64: 166,
        nr_aarch64: 39,
    },
    Syscall {
        name: "pivot_root",
        nr_x86_64: 155,
        nr_aarch64: 41,
    },
    Syscall {
        name: "chroot",
        nr_x86_64: 161,
        nr_aarch64: 51,
    },
    Syscall {
        name: "ptrace",
        nr_x86_64: 101,
        nr_aarch64: 117,
    },
    Syscall {
        name: "kexec_load",
        nr_x86_64: 246,
        nr_aarch64: 104,
    },
    Syscall {
        name: "kexec_file_load",
        nr_x86_64: 320,
        nr_aarch64: 294,
    },
    Syscall {
        name: "reboot",
        nr_x86_64: 169,
        nr_aarch64: 142,
    },
    Syscall {
        name: "init_module",
        nr_x86_64: 175,
        nr_aarch64: 105,
    },
    Syscall {
        name: "finit_module",
        nr_x86_64: 313,
        nr_aarch64: 106,
    },
    Syscall {
        name: "delete_module",
        nr_x86_64: 176,
        nr_aarch64: 107,
    },
    Syscall {
        name: "unshare",
        nr_x86_64: 97,
        nr_aarch64: 97,
    },
    Syscall {
        name: "bpf",
        nr_x86_64: 357,
        nr_aarch64: 280,
    },
];

// ---------------------------------------------------------------------------
// 查询 API
// ---------------------------------------------------------------------------

/// 通过 syscall 号查名。线性扫 SYSCALLS 表，O(n) 足够。
pub fn syscall_name(nr: u32) -> Option<&'static str> {
    SYSCALLS.iter().find(|s| s.nr() == nr).map(|s| s.name)
}

// ---------------------------------------------------------------------------
// 公开 API
// ---------------------------------------------------------------------------

/// 检查当前系统是否支持 seccomp。
///
/// 当 seccomp filter 接口启用时返回 `true`（需要 Linux 3.5+ 且
/// `CONFIG_SECCOMP=y`）。
///
/// 探测依据是文件
/// `/proc/sys/kernel/seccomp/actions_avail` 的存在，它在任何
/// 较新的、编译了 seccomp 的 Linux 系统上都存在。
pub fn is_available() -> bool {
    Path::new("/proc/sys/kernel/seccomp/actions_avail").exists()
}

/// 返回当前编译目标的审计架构常量。
pub fn current_arch() -> u32 {
    if cfg!(target_arch = "x86_64") {
        AUDIT_ARCH_X86_64
    } else if cfg!(target_arch = "aarch64") {
        AUDIT_ARCH_AARCH64
    } else {
        unreachable!("seccomp: unsupported target architecture")
    }
}

/// 为给定的 syscall 号构建 `SECCOMP_RET_USER_NOTIF` filter。
///
/// 生成的 BPF 程序（n = `nrs.len()`，共 n + 6 条指令）：
///
/// ```text
///    0: LD  [4]                     -- 加载 arch
///    1: JEQ AUDIT_ARCH_{XXX}, +1, 0 -- 架构匹配跳过 KILL
///    2: RET KILL_PROCESS            -- 架构不匹配则杀进程
///    3: LD  [0]                     -- 加载 syscall nr
///  4..3+n: JEQ <nr>, die, 0        -- 检查 n 个 syscall
///  3+n+1: RET ALLOW                -- 未命中 → 放行
///  3+n+2: die_insn                 -- RET USER_NOTIF（命中 → 通知父进程）
/// ```
pub fn build_deny_filter(nrs: &[u32]) -> Vec<sock_filter> {
    let target_arch = current_arch();
    let n = nrs.len();
    let total_insns = n + 6;
    let die_insn = total_insns - 1;

    let mut filter = Vec::with_capacity(total_insns);

    // insn 0: LD arch (seccomp_data offset 4)
    filter.push(sock_filter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: 4,
    });

    // insn 1: JEQ arch → skip RET KILL
    filter.push(sock_filter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 1,
        jf: 0,
        k: target_arch,
    });

    // insn 2: RET KILL_PROCESS (arch mismatch)
    filter.push(sock_filter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_KILL_PROCESS,
    });

    // insn 3: LD nr (seccomp_data offset 0)
    filter.push(sock_filter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: 0,
    });

    // insn 4..3+n: JEQ checks for each syscall nr
    for (i, nr) in nrs.iter().enumerate() {
        let insn_idx = 4 + i;
        let jt = (die_insn - insn_idx - 1) as u8;
        filter.push(sock_filter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt,
            jf: 0,
            k: *nr,
        });
    }

    // insn 3+n+1: RET ALLOW (no match → permit)
    filter.push(sock_filter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    });

    // insn die_insn: RET USER_NOTIF (match → notify parent)
    filter.push(sock_filter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_USER_NOTIF,
    });

    assert_eq!(
        filter.len(),
        total_insns,
        "seccomp BPF filter must have exactly {} instructions, got {}",
        total_insns,
        filter.len()
    );

    filter
}

/// 通过 prctl 直装 BPF filter（无 `NEW_LISTENER`）。
///
/// 用于安装外部 BPF filter。子进程在 pre_exec 内调用。
/// 不返回 listener fd，因为外部 BPF 不需要 USER_NOTIF 通知。
pub fn install_plain_filter(filter: &[sock_filter]) -> anyhow::Result<()> {
    let prog = sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };
    // SAFETY：filter 由调用方构造，格式合法；prog 生命周期覆盖 syscall。
    // man:seccomp(2) SECCOMP_SET_MODE_FILTER
    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER as libc::c_int,
            0u64, // flags = 0，无 NEW_LISTENER
            &prog as *const sock_fprog,
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error())
            .context("seccomp(SECCOMP_SET_MODE_FILTER, plain) failed");
    }
    Ok(())
}

/// 在调用线程安装带 `SECCOMP_FILTER_FLAG_NEW_LISTENER` 的 BPF filter，
/// 并返回新创建的 listener fd。
///
/// 由 `pre_exec` 闭包调用。流程：
///
/// 1. `prctl(PR_SET_NO_NEW_PRIVS, 1, ...)` — user notification 的前置条件。
/// 2. `seccomp(SECCOMP_SET_MODE_FILTER, flags, &fprog)` — 加载 BPF 并
///    让内核返回 listener fd（通过 flags 中的 `NEW_LISTENER` 位）。
///
/// # 参数
///
/// - `filter`：经 [`build_blacklist_filter`] 生成的 BPF filter。
///
/// # 返回
///
/// 成功时返回内核新建的 listener fd（>=0）。调用方负责把它通过
/// `sendmsg(SCM_RIGHTS)` 发送给父进程。
///
/// # 错误
///
/// `prctl` 或 `seccomp` 失败时返回错误。常见原因：
/// - 内核不支持 user notification（< 5.0）：`seccomp` 返回 `EACCES` /
///   `EINVAL`。
/// - 进程未设 `PR_SET_NO_NEW_PRIVS` 又无 `CAP_SYS_ADMIN`：本函数会先设
///   no_new_privs，所以不会发生。
///
/// # Safety
///
/// 调用 `libc::prctl` 与 `libc::syscall(SYS_seccomp, ...)`，都是 unsafe
/// 系统调用包装。filter 必须由 [`build_blacklist_filter`] 产生（其格式
/// 内核已校验过）。函数本身不会移动内存，所有权完全转入内核。
pub fn install_user_notif_filter(filter: &[sock_filter]) -> anyhow::Result<RawFd> {
    // -----------------------------------------------------------------------
    // 步骤 1：prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    //
    // 阻止进程（及其子进程）通过 setuid 二进制、capabilities 等获得
    // 任何新特权。它是 `seccomp(SECCOMP_SET_MODE_FILTER)` 的前置条件
    // （当进程没有 CAP_SYS_ADMIN 时）。
    //
    // SAFETY：参数都是普通整数；内核会校验并在失败时返回错误码。
    // -----------------------------------------------------------------------
    // man:prctl(2) PR_SET_NO_NEW_PRIVS
    let ret = unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        return Err(io::Error::last_os_error()).context("prctl(PR_SET_NO_NEW_PRIVS) failed");
    }

    // -----------------------------------------------------------------------
    // 步骤 2：seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog)
    //
    // 加载 BPF 程序。flags 中置位 NEW_LISTENER 后，内核会同时返回一个新
    // 创建的 listener fd（用于 user notification）。
    //
    // SAFETY：
    // - `prog` 是局部变量，其生命周期覆盖整个调用，因此指针始终有效。
    // - `filter` 是切片，其底层存储至少与 `sock_fprog` 引用等长。
    //   BPF 程序会被内核拷入内核内存，因此调用返回后切片即可释放。
    // - filter 由 `build_blacklist_filter()` 产生，结构上合法
    //   （长度满足内核限制，跳转偏移都在范围内）。
    // -----------------------------------------------------------------------
    // man:seccomp(2) SECCOMP_SET_MODE_FILTER
    let prog = sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };

    // 把 flags 与 `u32` 操作数都转成 `c_ulong`/`c_uint` 以匹配
    // `SYS_seccomp` 的可变参数签名。
    let listener_fd = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER as libc::c_int,
            SECCOMP_FILTER_FLAG_NEW_LISTENER as libc::c_ulong,
            &prog as *const sock_fprog,
        )
    };

    // seccomp(2) 在出错时返回 -1；成功时直接返回 listener fd（>=0）。
    if listener_fd < 0 {
        return Err(io::Error::last_os_error())
            .context("seccomp(SECCOMP_SET_MODE_FILTER, NEW_LISTENER) failed");
    }

    Ok(listener_fd as RawFd)
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// 空 nr 列表 → 正好 6 条指令（arch check + nr load + ALLOW + USER_NOTIF）。
    #[test]
    fn build_deny_filter_empty() {
        let filter = build_deny_filter(&[]);
        assert_eq!(filter.len(), 6);
    }

    /// n 个 nr → n + 6 条指令。
    #[test]
    fn build_deny_filter_length() {
        let filter = build_deny_filter(&[165, 97, 357]);
        assert_eq!(filter.len(), 3 + 6);
    }

    /// 第一条指令必须加载架构字段（offset 4）。
    #[test]
    fn first_insn_loads_arch() {
        let filter = build_deny_filter(&[165]);
        let insn = &filter[0];
        assert_eq!(insn.code, BPF_LD | BPF_W | BPF_ABS);
        assert_eq!(insn.k, 4, "must load from seccomp_data.arch (offset 4)");
    }

    /// 第三条指令必须是架构不匹配的自杀指令。
    #[test]
    fn third_insn_is_arch_kill() {
        let filter = build_deny_filter(&[165]);
        let insn = &filter[2];
        assert_eq!(insn.code, BPF_RET | BPF_K);
        assert_eq!(insn.k, SECCOMP_RET_KILL_PROCESS);
    }

    /// 架构检查（指令 1）必须命中时跳到 LD nr（指令 3），
    /// 跳过指令 2 的 RET KILL。
    #[test]
    fn arch_check_jump_target() {
        let filter = build_deny_filter(&[165]);
        let insn = &filter[1];
        assert_eq!(insn.code, BPF_JMP | BPF_JEQ | BPF_K);
        assert_eq!(insn.jt, 1, "arch match should skip the RET KILL");
        assert_eq!(insn.jf, 0, "arch mismatch should fall into RET KILL");
    }

    /// 最后一条指令必须是 RET USER_NOTIF。
    #[test]
    fn last_insn_is_user_notif() {
        let filter = build_deny_filter(&[165]);
        let insn = filter.last().unwrap();
        assert_eq!(insn.code, BPF_RET | BPF_K);
        assert_eq!(insn.k, SECCOMP_RET_USER_NOTIF);
    }

    /// 倒数第二条指令必须是 RET ALLOW。
    #[test]
    fn second_last_insn_is_allow() {
        let filter = build_deny_filter(&[165]);
        let insn = &filter[filter.len() - 2];
        assert_eq!(insn.code, BPF_RET | BPF_K);
        assert_eq!(insn.k, SECCOMP_RET_ALLOW);
    }

    /// 所有 JEQ 指令的跳转偏移必须指向最后的 RET USER_NOTIF。
    #[test]
    fn deny_jumps_target_die() {
        let nrs = [165, 97, 357];
        let filter = build_deny_filter(&nrs);
        let die_index = filter.len() - 1;

        for (i, insn) in filter[4..4 + nrs.len()].iter().enumerate() {
            let insn_idx = 4 + i;
            let expected_jt = (die_index - insn_idx - 1) as u8;
            assert_eq!(insn.code, BPF_JMP | BPF_JEQ | BPF_K);
            assert_eq!(insn.jt, expected_jt);
            assert_eq!(insn.jf, 0);
        }
    }

    /// `current_arch()` 返回编译目标对应的审计架构常量。
    #[test]
    fn arch_constant_is_valid() {
        let arch = current_arch();
        match std::env::consts::ARCH {
            "x86_64" => assert_eq!(arch, AUDIT_ARCH_X86_64),
            "aarch64" => assert_eq!(arch, AUDIT_ARCH_AARCH64),
            other => panic!("unexpected target arch: {other}"),
        }
    }

    /// unshare syscall 号在两种架构上都必须是 97。
    #[test]
    fn unshare_is_97() {
        let unshare = SYSCALLS
            .iter()
            .find(|s| s.name == "unshare")
            .expect("SYSCALLS must contain unshare");
        assert_eq!(unshare.nr_x86_64, 97);
        assert_eq!(unshare.nr_aarch64, 97);
    }

    /// `SYSCALLS` 表内每个架构号列都不应重复。
    #[test]
    fn no_duplicate_syscall_nrs() {
        let mut x86_nrs: Vec<u32> = SYSCALLS.iter().map(|s| s.nr_x86_64).collect();
        x86_nrs.sort();
        x86_nrs.dedup();
        assert_eq!(x86_nrs.len(), SYSCALLS.len());

        let mut arm_nrs: Vec<u32> = SYSCALLS.iter().map(|s| s.nr_aarch64).collect();
        arm_nrs.sort();
        arm_nrs.dedup();
        assert_eq!(arm_nrs.len(), SYSCALLS.len());
    }

    /// `syscall_name` 应能按当前架构号解析出 syscall 名。
    #[test]
    fn syscall_name_resolves() {
        if cfg!(target_arch = "x86_64") {
            assert_eq!(syscall_name(165), Some("mount"));
            assert_eq!(syscall_name(97), Some("unshare"));
            assert_eq!(syscall_name(357), Some("bpf"));
        } else if cfg!(target_arch = "aarch64") {
            assert_eq!(syscall_name(40), Some("mount"));
            assert_eq!(syscall_name(97), Some("unshare"));
            assert_eq!(syscall_name(280), Some("bpf"));
        }
    }

    /// SECCOMP_IOCTL_NOTIF_RECV 与 SECCOMP_IOCTL_NOTIF_SEND 的编码
    /// 必须与内核 `_IOWR('!', 0/1, ...)` 的展开值一致。
    #[test]
    fn ioctl_numbers_have_expected_direction() {
        assert_eq!(SECCOMP_IOCTL_NOTIF_RECV, 0xC050_2100);
        assert_eq!(SECCOMP_IOCTL_NOTIF_SEND, 0xC018_2101);

        assert_eq!(SECCOMP_IOCTL_NOTIF_RECV & 0xC000_0000, 0xC000_0000);
        assert_eq!(SECCOMP_IOCTL_NOTIF_SEND & 0xC000_0000, 0xC000_0000);
        assert_eq!(
            (SECCOMP_IOCTL_NOTIF_RECV >> 8) & 0xff,
            b'!' as libc::c_ulong
        );
        assert_eq!(
            (SECCOMP_IOCTL_NOTIF_SEND >> 8) & 0xff,
            b'!' as libc::c_ulong
        );
        assert_eq!(SECCOMP_IOCTL_NOTIF_RECV & 0xff, 0);
        assert_eq!(SECCOMP_IOCTL_NOTIF_SEND & 0xff, 1);
        assert_eq!((SECCOMP_IOCTL_NOTIF_RECV >> 16) & 0x3FFF, 80);
        assert_eq!((SECCOMP_IOCTL_NOTIF_SEND >> 16) & 0x3FFF, 24);
    }
}
