//! 针对危险 syscall 的 seccomp BPF 黑名单 filter。
//!
//! 使用 `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)` 加载一段手写的
//! BPF 程序，拦截 13 个会破坏内核的 syscall：
//!
//!   mount, umount2, pivot_root, chroot,
//!   ptrace,
//!   kexec_load, kexec_file_load,
//!   reboot,
//!   init_module, finit_module, delete_module,
//!   unshare,
//!   bpf
//!
//! BPF 程序具备架构感知能力：会检查 `seccomp_data.arch` 并拒绝来自
//! 未知架构的 syscall。x86_64 与 aarch64 的 syscall 号不同，因此
//! filter 在运行时通过 `cfg!(target_arch = ...)` 选取正确的号码来构建。
//!
//! # 架构
//!
//! filter 在检查任何 syscall 号之前先检查 `seccomp_data` 中的架构字段，
//! 因此同一份二进制在 syscall 表未知的架构上会返回 KILL（拒绝）。
//!
//! # Safety
//!
//! `apply_seccomp` 函数调用 `libc::prctl`，这本身就是 `unsafe`。
//! 每个调用点都附有 `// SAFETY:` 注释解释该调用的合理性。

use std::io;
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

/// 立即杀死调用进程（seccomp action）。
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;

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

/// `prctl` 选项：设置 seccomp filter（man:prctl(2) PR_SET_SECCOMP）。
const PR_SET_SECCOMP: libc::c_int = 22;

/// `prctl(PR_SET_SECCOMP, ...)` mode：加载 BPF filter（linux/seccomp.h）。
const SECCOMP_MODE_FILTER: libc::c_int = 2;

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
    code: u16,
    /// 比较为真时的跳转偏移（要跳过的指令数）。
    jt: u8,
    /// 比较为假时的跳转偏移。
    jf: u8,
    /// 通用操作数（取决于操作码）。
    k: u32,
}

/// BPF 程序头（亦称 `sock_fprog`）。
///
/// 布局与内核 `include/uapi/linux/filter.h` 中的 `struct sock_fprog` 一致。
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct sock_fprog {
    /// filter 中的指令数。
    len: u16,
    /// 指向首条指令的指针。
    filter: *const sock_filter,
}

// SAFETY：`sock_fprog` 仅在 fork 之后的 `pre_exec` 闭包内使用。
// fork 之后子进程独占访问，指针所指的是不可变的 BPF 指令数据，
// 在 `prctl(PR_SET_SECCOMP, ...)` 期间只读。不存在数据竞争。
unsafe impl Send for sock_fprog {}
unsafe impl Sync for sock_fprog {}

// ---------------------------------------------------------------------------
// Syscall 号表（按架构）
// ---------------------------------------------------------------------------

/// 返回**编译目标**架构的审计架构常量以及 13 个黑名单 syscall 号。
///
/// 黑名单如下：
///
/// | syscall          | x86_64 nr | aarch64 nr |
/// |------------------|-----------|------------|
/// | mount            | 165       | 40         |
/// | umount2          | 166       | 39         |
/// | pivot_root       | 155       | 41         |
/// | chroot           | 161       | 51         |
/// | ptrace           | 101       | 117        |
/// | kexec_load       | 246       | 104        |
/// | kexec_file_load  | 320       | 294        |
/// | reboot           | 169       | 142        |
/// | init_module      | 175       | 105        |
/// | finit_module     | 313       | 106        |
/// | delete_module    | 176       | 107        |
/// | unshare          | 97        | 97         |
/// | bpf              | 357       | 280        |
fn target_arch_config() -> (u32, [u32; 13]) {
    // 两个分支都会被编译；但只有匹配当前 target 的那个会在运行时
    // 被执行。`cfg!` 宏在编译期对当前 target 求值为 `true`，因此
    // 另一分支会被 dead-code 消除。
    if cfg!(target_arch = "x86_64") {
        (
            AUDIT_ARCH_X86_64,
            [
                // mount, umount2, pivot_root, chroot
                165, 166, 155, 161,
                // ptrace
                101,
                // kexec_load, kexec_file_load
                246, 320,
                // reboot
                169,
                // init_module, finit_module, delete_module
                175, 313, 176,
                // unshare
                97,
                // bpf
                357,
            ],
        )
    } else if cfg!(target_arch = "aarch64") {
        (
            AUDIT_ARCH_AARCH64,
            [
                // mount, umount2, pivot_root, chroot
                40, 39, 41, 51,
                // ptrace
                117,
                // kexec_load, kexec_file_load
                104, 294,
                // reboot
                142,
                // init_module, finit_module, delete_module
                105, 106, 107,
                // unshare
                97,
                // bpf
                280,
            ],
        )
    } else {
        // 该分支不可达，因为二进制只会为受支持的架构编译。
        // 保留它是为了避免只有 `if` 没有 `else` 的编译错误。
        panic!(
            "seccomp: unsupported target architecture: {}",
            std::env::consts::ARCH
        );
    }
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

/// 构建 seccomp BPF 黑名单 filter，返回 `sock_filter` 指令的 Vec。
///
/// 生成的程序（19 条指令）：
///
/// ```text
///    0: LD  [4]                     -- 从 seccomp_data 加载 arch
///    1: JEQ AUDIT_ARCH_{XXX}, +1, 0 -- 命中时跳过 arch-KILL
///    2: RET KILL_PROCESS            -- 架构不受支持则自杀
///    3: LD  [0]                     -- 从 seccomp_data 加载 syscall nr
///  4-16: JEQ <黑名单号>, die, 0     -- 检查 13 个 syscall
///   17: RET ALLOW                   -- 没有命中 -> 放行
///   18: RET KILL_PROCESS            -- 命中 -> 自杀（所有 JEQ jt 的目标）
/// ```
///
/// 每条黑名单 JEQ 的 `jt` 都指向索引 18 的 `RET KILL_PROCESS`，
/// 因此任何被命中的 syscall 都会立即终止进程。
pub fn build_blacklist_filter() -> Vec<sock_filter> {
    let (target_arch, syscall_nrs) = target_arch_config();
    const TOTAL_INSNS: usize = 19;
    const DIE_INSN: usize = 18; // RET KILL_PROCESS 的索引

    let mut filter = Vec::with_capacity(TOTAL_INSNS);

    // --- 指令 0：加载架构（seccomp_data offset 4） -----------------------
    filter.push(sock_filter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: 4, // offsetof(struct seccomp_data, arch)
    });

    // --- 指令 1：检查架构 ------------------------------------------------
    // 若架构匹配我们的目标，则跳过下面的 RET KILL。
    // 否则落进 RET KILL。
    filter.push(sock_filter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 1, // 命中时跳过 1 条指令（指令 2）
        jf: 0, // 不命中时落进指令 2
        k: target_arch,
    });

    // --- 指令 2：不支持的架构则杀进程 -----------------------------------
    filter.push(sock_filter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_KILL_PROCESS,
    });

    // --- 指令 3：加载 syscall 号（seccomp_data offset 0） ----------------
    filter.push(sock_filter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: 0, // offsetof(struct seccomp_data, nr)
    });

    // --- 指令 4-16：黑名单 JEQ 检查（13 项） -----------------------------
    // 对每个黑名单 syscall：若加载到的 nr 等于该 syscall 号，则跳到
    // RET KILL_PROCESS（指令 18）。否则落进下一条检查。
    for (i, nr) in syscall_nrs.iter().enumerate() {
        let insn_idx = 4 + i;
        // `jt` = 跳到 DIE_INSN（18）所需跳过的指令数：
        //         jt = DIE_INSN - insn_idx - 1
        // 指令 4   -> jt = 18 - 4  - 1 = 13
        // 指令 16  -> jt = 18 - 16 - 1 = 1
        let jt = (DIE_INSN - insn_idx - 1) as u8;

        filter.push(sock_filter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt,
            jf: 0,
            k: *nr,
        });
    }

    // --- 指令 17：放行（未命中黑名单） ----------------------------------
    filter.push(sock_filter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    });

    // --- 指令 18：杀进程（命中黑名单） ----------------------------------
    filter.push(sock_filter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_KILL_PROCESS,
    });

    // 一致性校验 —— 确保 filter 长度正确。
    assert_eq!(
        filter.len(),
        TOTAL_INSNS,
        "seccomp BPF filter must have exactly {} instructions, got {}",
        TOTAL_INSNS,
        filter.len()
    );

    filter
}

/// 从 filter 切片构造 `sock_fprog` 结构体，供 `pre_exec` 闭包使用。
///
/// 返回的 `sock_fprog` 借用 filter 数据，其有效期不超过底层 `Vec` 的
/// 生命周期。在 `pre_exec`（fork+exec 上下文）中，父进程的 `Vec` 必须
/// 一直存活到 `spawn()` 返回；子进程获得自己的栈 COW 副本，因此指针
/// 在 prctl 调用期间始终有效。
pub(crate) fn build_sock_fprog(filter: &[sock_filter]) -> sock_fprog {
    sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    }
}

/// 对**调用进程**施加 seccomp BPF filter。
///
/// # 前置条件
///
/// 该函数必须在进程已设置 `PR_SET_NO_NEW_PRIVS` 之后调用
/// （本函数会替你设置）。重复调用会叠加第二个 filter
///（seccomp 支持堆叠）。
///
/// # 错误
///
/// 若 `prctl(PR_SET_NO_NEW_PRIVS)` 或 `prctl(PR_SET_SECCOMP)` 失败
/// 则返回错误。常见失败原因：
///
/// - 内核不支持 seccomp（3.5 之前或 `CONFIG_SECCOMP=n`）。
/// - 进程缺少 `CAP_SYS_ADMIN` **且** `PR_SET_NO_NEW_PRIVS` 还未设置
///   （不过这里会设置，所以只有在外层 filter 已施加时才相关）。
/// - filter 格式错误。
///
/// # Safety
///
/// 该函数调用 `libc::prctl`，它是一个 `unsafe` 的系统调用包装。
/// filter **必须**是良构的 BPF 程序；格式错误的 filter 会让
/// `prctl` 返回 `-1`，本身并不内存不安全，但会让进程无法继续工作。
pub fn apply_seccomp(filter: &[sock_filter]) -> anyhow::Result<()> {
    // -----------------------------------------------------------------------
    // 步骤 1：prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    //
    // 阻止进程（及其子进程）通过 setuid 二进制、capabilities 等获得
    // 任何新特权。它是 `SECCOMP_MODE_FILTER` 的前置条件（当进程没有
    // CAP_SYS_ADMIN 时）。
    //
    // SAFETY：参数都是普通整数；内核会校验并在失败时返回错误码。
    // -----------------------------------------------------------------------
    // man:prctl(2) PR_SET_NO_NEW_PRIVS
    let ret = unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        return Err(io::Error::last_os_error())
            .context("prctl(PR_SET_NO_NEW_PRIVS) failed");
    }

    // -----------------------------------------------------------------------
    // 步骤 2：prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)
    //
    // 将 BPF 程序作为 seccomp filter 加载。一旦该调用成功，
    // 之后每一次 syscall（内核信号投递路径中的除外）都会通过
    // 该 filter 校验。
    //
    // SAFETY：
    // - `prog` 是局部变量，其生命周期覆盖整个调用，因此指针始终有效。
    // - `filter` 是切片，其底层存储至少与 `sock_fprog` 引用等长。
    //   BPF 程序会被 `prctl` 拷入内核内存，因此调用返回后切片即可释放。
    // - filter 由 `build_blacklist_filter()` 产生，结构上合法
    //   （长度满足内核限制，跳转偏移都在范围内）。
    // -----------------------------------------------------------------------
    // man:prctl(2) PR_SET_SECCOMP
    let prog = sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };

    let ret = unsafe { libc::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) };
    if ret != 0 {
        return Err(io::Error::last_os_error())
            .context("prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER) failed");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// BPF filter 必须正好包含 19 条指令：
    ///
    ///   1  (LD arch)
    ///   1  (JEQ arch)
    ///   1  (RET KILL — die_arch)
    ///   1  (LD nr)
    ///  13  (JEQ × 13 黑名单项)
    ///   1  (RET ALLOW)
    ///   1  (RET KILL — die)
    ///   ───
    ///  19
    #[test]
    fn filter_length() {
        let filter = build_blacklist_filter();
        assert_eq!(filter.len(), 19);
    }

    /// 第一条指令必须加载架构字段（offset 4）。
    #[test]
    fn first_insn_loads_arch() {
        let filter = build_blacklist_filter();
        let insn = &filter[0];
        assert_eq!(insn.code, BPF_LD | BPF_W | BPF_ABS, "insn 0: must load word from absolute offset");
        assert_eq!(insn.k, 4, "insn 0: must load from seccomp_data.arch (offset 4)");
    }

    /// 第三条指令必须是架构不匹配的自杀指令。
    #[test]
    fn third_insn_is_arch_kill() {
        let filter = build_blacklist_filter();
        let insn = &filter[2];
        assert_eq!(
            insn.code,
            BPF_RET | BPF_K,
            "insn 2: must be RET"
        );
        assert_eq!(
            insn.k, SECCOMP_RET_KILL_PROCESS,
            "insn 2: must return KILL_PROCESS"
        );
    }

    /// 架构检查（指令 1）必须命中时跳到 LD nr（指令 3），
    /// 跳过指令 2 的 RET KILL。
    #[test]
    fn arch_check_jump_target() {
        let filter = build_blacklist_filter();
        let insn = &filter[1];
        assert_eq!(insn.code, BPF_JMP | BPF_JEQ | BPF_K);
        // jt = 1 意味着跳过 1 条指令（指令 2 = RET KILL），落到指令 3
        assert_eq!(insn.jt, 1, "arch match should skip the RET KILL");
        assert_eq!(insn.jf, 0, "arch mismatch should fall into RET KILL");
    }

    /// 最后一条指令必须是 RET KILL_PROCESS（die 目标）。
    #[test]
    fn last_insn_is_die() {
        let filter = build_blacklist_filter();
        let insn = filter.last().unwrap();
        assert_eq!(insn.code, BPF_RET | BPF_K);
        assert_eq!(insn.k, SECCOMP_RET_KILL_PROCESS);
    }

    /// 倒数第二条指令必须是 RET ALLOW。
    #[test]
    fn second_last_insn_is_allow() {
        let filter = build_blacklist_filter();
        let insn = &filter[filter.len() - 2];
        assert_eq!(insn.code, BPF_RET | BPF_K);
        assert_eq!(insn.k, SECCOMP_RET_ALLOW);
    }

    /// 所有 13 条黑名单 JEQ 指令的跳转偏移必须合法，并指向
    /// 最后的 RET KILL_PROCESS（指令 18）。
    #[test]
    fn blacklist_jumps_target_die() {
        let filter = build_blacklist_filter();
        let die_index = filter.len() - 1; // 18

        // 指令 4 到 16 是黑名单检查。
        for (i, insn) in filter[4..17].iter().enumerate() {
            let insn_idx = 4 + i;
            let expected_jt = (die_index - insn_idx - 1) as u8;

            assert_eq!(
                insn.code,
                BPF_JMP | BPF_JEQ | BPF_K,
                "insn {}: expected JEQ opcode",
                insn_idx
            );
            assert_eq!(
                insn.jt, expected_jt,
                "insn {}: jt should skip to die (die_index={}, insn_idx={}, expected_jt={})",
                insn_idx, die_index, insn_idx, expected_jt
            );
            assert_eq!(
                insn.jf, 0,
                "insn {}: jf should fall through to next check",
                insn_idx
            );
        }
    }

    /// `build_blacklist_filter` 必须为编译目标返回有效的 arch 常量。
    #[test]
    fn arch_constant_is_valid() {
        let (arch, _nrs) = target_arch_config();
        match std::env::consts::ARCH {
            "x86_64" => assert_eq!(arch, AUDIT_ARCH_X86_64),
            "aarch64" => assert_eq!(arch, AUDIT_ARCH_AARCH64),
            other => panic!("unexpected target arch: {other}"),
        }
    }

    /// syscall 号表必须正好有 13 项。
    #[test]
    fn syscall_nrs_count() {
        let (_arch, nrs) = target_arch_config();
        assert_eq!(nrs.len(), 13);
    }

    /// unshare syscall 号在两种架构上都必须是 97。
    #[test]
    fn unshare_is_97() {
        let (_arch, nrs) = target_arch_config();
        // unshare 是第 12 项（index 11）
        assert_eq!(nrs[11], 97, "unshare must be syscall 97 on all architectures");
    }

    /// 表中所有 13 个 syscall 号必须互不相同。
    #[test]
    fn no_duplicate_syscall_nrs() {
        let (_arch, nrs) = target_arch_config();
        let mut sorted = nrs.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 13, "syscall numbers must be unique");
    }
}