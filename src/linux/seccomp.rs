//! Seccomp BPF blacklist filter for dangerous syscalls.
//!
//! Uses `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)` to load a hand-written
//! BPF program that blocks 13 kernel-disruptive syscalls:
//!
//!   mount, umount2, pivot_root, chroot,
//!   ptrace,
//!   kexec_load, kexec_file_load,
//!   reboot,
//!   init_module, finit_module, delete_module,
//!   unshare,
//!   bpf
//!
//! The BPF program is architecture-aware: it checks `seccomp_data.arch` and
//! rejects syscalls from unsupported architectures. Syscall numbers differ
//! between x86_64 and aarch64, so the filter is built at runtime using
//! `cfg!(target_arch = ...)` to select the correct numbers.
//!
//! # Architecture
//!
//! The filter checks the architecture field in `seccomp_data` before checking
//! any syscall numbers, so the same binary will reject (KILL) on architectures
//! whose syscall table is unknown.
//!
//! # Safety
//!
//! The `apply_seccomp` function calls `libc::prctl` which is inherently
//! `unsafe`.  Each call site is annotated with a `// SAFETY:` comment
//! explaining why the call is sound.

use std::io;
use std::path::Path;

use anyhow::Context;

// ---------------------------------------------------------------------------
// BPF instruction encoding
// ---------------------------------------------------------------------------

/// BPF instruction class: BPF_LD (load)
const BPF_LD: u16 = 0x00;

/// BPF instruction class: BPF_JMP (jump)
const BPF_JMP: u16 = 0x05;

/// BPF instruction class: BPF_RET (return)
const BPF_RET: u16 = 0x06;

/// BPF load size: 32-bit word
const BPF_W: u16 = 0x00;

/// BPF load mode: absolute offset (used with `BPF_LD | BPF_W`)
const BPF_ABS: u16 = 0x20;

/// BPF jump condition: jump if A == k (used with `BPF_JMP`)
const BPF_JEQ: u16 = 0x10;

/// BPF source operand is a constant (used with `BPF_JMP | BPF_JEQ`)
const BPF_K: u16 = 0x00;

// ---------------------------------------------------------------------------
// seccomp return values (linux/seccomp.h)
// ---------------------------------------------------------------------------

/// Kill the calling process immediately (seccomp action).
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;

/// Allow the syscall to proceed.
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

// ---------------------------------------------------------------------------
// Audit architecture constants (linux/audit.h)
// ---------------------------------------------------------------------------

/// x86_64 audit architecture identifier.
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

/// aarch64 audit architecture identifier.
const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;

// ---------------------------------------------------------------------------
// prctl constants (linux/prctl.h)
// ---------------------------------------------------------------------------

/// `prctl` option: set no_new_privs (man:prctl(2) PR_SET_NO_NEW_PRIVS).
const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;

/// `prctl` option: set seccomp filter (man:prctl(2) PR_SET_SECCOMP).
const PR_SET_SECCOMP: libc::c_int = 22;

/// `prctl(PR_SET_SECCOMP, ...)` mode: load BPF filter (linux/seccomp.h).
const SECCOMP_MODE_FILTER: libc::c_int = 2;

// ---------------------------------------------------------------------------
// BPF struct definitions
// ---------------------------------------------------------------------------

/// A single BPF instruction (also known as `sock_filter`).
///
/// Layout matches the kernel's `struct sock_filter` in `include/uapi/linux/filter.h`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct sock_filter {
    /// BPF opcode (e.g. `BPF_LD | BPF_W | BPF_ABS`).
    code: u16,
    /// Jump offset if the comparison is true (number of instructions to skip).
    jt: u8,
    /// Jump offset if the comparison is false.
    jf: u8,
    /// Generic operand (depends on opcode).
    k: u32,
}

/// BPF program header (also known as `sock_fprog`).
///
/// Layout matches the kernel's `struct sock_fprog` in `include/uapi/linux/filter.h`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct sock_fprog {
    /// Number of instructions in the filter.
    len: u16,
    /// Pointer to the first instruction.
    filter: *const sock_filter,
}

// SAFETY: `sock_fprog` is only used inside a `pre_exec` closure after
// `fork()`.  The child process has exclusive access post-fork, and the
// pointer refers to immutable BPF instruction data that is read-only
// during `prctl(PR_SET_SECCOMP, ...)`.  No data races are possible.
unsafe impl Send for sock_fprog {}
unsafe impl Sync for sock_fprog {}

// ---------------------------------------------------------------------------
// Syscall number tables (per architecture)
// ---------------------------------------------------------------------------

/// Returns the audit architecture constant and the 13 blacklisted syscall
/// numbers for the **compiled** target architecture.
///
/// The blacklist is:
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
    // Both branches are compiled; only the matching one is ever reached at
    // runtime. The `cfg!` macro evaluates to `true` at compile time for the
    // current target, so the other branch is dead-code eliminated.
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
        // This branch is unreachable because the binary is compiled for a
        // supported architecture.  We keep it to avoid a compile error from
        // `if` without `else`.
        panic!(
            "seccomp: unsupported target architecture: {}",
            std::env::consts::ARCH
        );
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Check whether seccomp is available on the current system.
///
/// Returns `true` if the seccomp filter interface is enabled (requires
/// Linux 3.5+ and `CONFIG_SECCOMP=y`).
///
/// Detection relies on the existence of
/// `/proc/sys/kernel/seccomp/actions_avail`, which is present on any
/// reasonably modern Linux system with seccomp compiled in.
pub fn is_available() -> bool {
    Path::new("/proc/sys/kernel/seccomp/actions_avail").exists()
}

/// Build the seccomp BPF blacklist filter as a vector of `sock_filter`
/// instructions.
///
/// The generated program (19 instructions):
///
/// ```text
///    0: LD  [4]                     -- load arch from seccomp_data
///    1: JEQ AUDIT_ARCH_{XXX}, +1, 0 -- skip arch-KILL on match
///    2: RET KILL_PROCESS            -- die on unsupported arch
///    3: LD  [0]                     -- load syscall nr from seccomp_data
///  4-16: JEQ <blacklist_nr>, die, 0 -- check each of the 13 syscalls
///   17: RET ALLOW                   -- no match -> allow
///   18: RET KILL_PROCESS            -- match -> die (target of all JEQ jt)
/// ```
///
/// The `jt` offset of each blacklist JEQ targets the final `RET KILL_PROCESS`
/// at index 18, so any matched syscall immediately terminates the process.
pub fn build_blacklist_filter() -> Vec<sock_filter> {
    let (target_arch, syscall_nrs) = target_arch_config();
    const TOTAL_INSNS: usize = 19;
    const DIE_INSN: usize = 18; // index of RET KILL_PROCESS

    let mut filter = Vec::with_capacity(TOTAL_INSNS);

    // --- Instruction 0: Load architecture (seccomp_data offset 4) -----------
    filter.push(sock_filter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: 4, // offsetof(struct seccomp_data, arch)
    });

    // --- Instruction 1: Check architecture ----------------------------------
    // If the arch matches our target, skip the RET KILL below.
    // Otherwise, fall through to RET KILL.
    filter.push(sock_filter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 1, // skip 1 insn (insn 2) on match
        jf: 0, // fall through to insn 2 on mismatch
        k: target_arch,
    });

    // --- Instruction 2: Kill on unsupported architecture --------------------
    filter.push(sock_filter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_KILL_PROCESS,
    });

    // --- Instruction 3: Load syscall number (seccomp_data offset 0) ---------
    filter.push(sock_filter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: 0, // offsetof(struct seccomp_data, nr)
    });

    // --- Instructions 4-16: Blacklist JEQ checks (13 entries) ---------------
    // For each blacklisted syscall: if the loaded nr equals this syscall's
    // number, jump to RET KILL_PROCESS (insn 18).  Otherwise fall through to
    // the next check.
    for (i, nr) in syscall_nrs.iter().enumerate() {
        let insn_idx = 4 + i;
        // `jt` = number of instructions to skip to reach DIE_INSN (18):
        //         jt = DIE_INSN - insn_idx - 1
        // For insn 4  -> jt = 18 - 4 - 1 = 13
        // For insn 16 -> jt = 18 - 16 - 1 = 1
        let jt = (DIE_INSN - insn_idx - 1) as u8;

        filter.push(sock_filter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt,
            jf: 0,
            k: *nr,
        });
    }

    // --- Instruction 17: Allow (no blacklist match) -------------------------
    filter.push(sock_filter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    });

    // --- Instruction 18: Kill (blacklist match) -----------------------------
    filter.push(sock_filter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_KILL_PROCESS,
    });

    // Sanity check — make sure we didn't mess up the filter length.
    assert_eq!(
        filter.len(),
        TOTAL_INSNS,
        "seccomp BPF filter must have exactly {} instructions, got {}",
        TOTAL_INSNS,
        filter.len()
    );

    filter
}

/// Build a `sock_fprog` struct from a filter slice for use in `pre_exec` closures.
///
/// The returned `sock_fprog` borrows the filter data and is only valid as long
/// as the backing `Vec` lives.  In `pre_exec` (fork+exec context) the parent's
/// `Vec` must stay alive until `spawn()` returns; the child process gets its own
/// COW copy of the stack, so the pointer remains valid through the prctl call.
pub(crate) fn build_sock_fprog(filter: &[sock_filter]) -> sock_fprog {
    sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    }
}

/// Apply a seccomp BPF filter to the **calling process**.
///
/// # Preconditions
///
/// This function MUST be called **after** the process has set
/// `PR_SET_NO_NEW_PRIVS` (which this function handles for you).  Calling
/// this twice will add a second filter (seccomp supports stacking).
///
/// # Errors
///
/// Returns an error if either `prctl(PR_SET_NO_NEW_PRIVS)` or
/// `prctl(PR_SET_SECCOMP)` fails.  Common failure modes:
///
/// - The kernel does not support seccomp (pre-3.5 or `CONFIG_SECCOMP=n`).
/// - The process lacks `CAP_SYS_ADMIN` **and** `PR_SET_NO_NEW_PRIVS` has
///   not been set yet (though we set it here, so this is only relevant if
///   an outer filter was already applied).
/// - The filter is malformed.
///
/// # Safety
///
/// This function calls `libc::prctl`, which is an `unsafe` system call
/// wrapper.  The filter **must** be a well-formed BPF program; a malformed
/// filter will cause `prctl` to return `-1` and is not memory-unsafe by
/// itself, but can render the process unusable.
pub fn apply_seccomp(filter: &[sock_filter]) -> anyhow::Result<()> {
    // -----------------------------------------------------------------------
    // Step 1: prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    //
    // This prevents the process (and its children) from gaining any new
    // privileges via setuid binaries, capabilities, etc.  It is a
    // prerequisite for `SECCOMP_MODE_FILTER` when the process does not have
    // CAP_SYS_ADMIN.
    //
    // SAFETY: All arguments are plain integers.  The kernel validates them
    // and returns an error code on failure.
    // -----------------------------------------------------------------------
    // man:prctl(2) PR_SET_NO_NEW_PRIVS
    let ret = unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        return Err(io::Error::last_os_error())
            .context("prctl(PR_SET_NO_NEW_PRIVS) failed");
    }

    // -----------------------------------------------------------------------
    // Step 2: prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)
    //
    // Load the BPF program as a seccomp filter.  Once this call succeeds,
    // every subsequent syscall (except those made by the kernel's signal
    // delivery path) is checked against the filter.
    //
    // SAFETY:
    // - `prog` is a local variable whose lifetime covers the call, so the
    //   pointer remains valid.
    // - `filter` is a slice whose backing storage lives at least as long as
    //   the `sock_fprog` reference.  The BPF program is copied into kernel
    //   memory by `prctl`, so the slice can be dropped after this call
    //   returns.
    // - The filter was produced by `build_blacklist_filter()` and is
    //   structurally valid (length matches the kernel's limits, jump
    //   offsets stay within bounds).
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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The BPF filter must have exactly 19 instructions:
    ///
    ///   1  (LD arch)
    ///   1  (JEQ arch)
    ///   1  (RET KILL — die_arch)
    ///   1  (LD nr)
    ///  13  (JEQ × 13 blacklist entries)
    ///   1  (RET ALLOW)
    ///   1  (RET KILL — die)
    ///   ───
    ///  19
    #[test]
    fn filter_length() {
        let filter = build_blacklist_filter();
        assert_eq!(filter.len(), 19);
    }

    /// The first instruction must load the architecture field (offset 4).
    #[test]
    fn first_insn_loads_arch() {
        let filter = build_blacklist_filter();
        let insn = &filter[0];
        assert_eq!(insn.code, BPF_LD | BPF_W | BPF_ABS, "insn 0: must load word from absolute offset");
        assert_eq!(insn.k, 4, "insn 0: must load from seccomp_data.arch (offset 4)");
    }

    /// The third instruction must be the architecture mismatch kill.
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

    /// The architecture check (insn 1) must jump to LD nr (insn 3) on match,
    /// skipping the RET KILL at insn 2.
    #[test]
    fn arch_check_jump_target() {
        let filter = build_blacklist_filter();
        let insn = &filter[1];
        assert_eq!(insn.code, BPF_JMP | BPF_JEQ | BPF_K);
        // jt = 1 means skip 1 instruction (insn 2 = RET KILL) to land on insn 3
        assert_eq!(insn.jt, 1, "arch match should skip the RET KILL");
        assert_eq!(insn.jf, 0, "arch mismatch should fall into RET KILL");
    }

    /// The last instruction must be RET KILL_PROCESS (the die target).
    #[test]
    fn last_insn_is_die() {
        let filter = build_blacklist_filter();
        let insn = filter.last().unwrap();
        assert_eq!(insn.code, BPF_RET | BPF_K);
        assert_eq!(insn.k, SECCOMP_RET_KILL_PROCESS);
    }

    /// The second-to-last instruction must be RET ALLOW.
    #[test]
    fn second_last_insn_is_allow() {
        let filter = build_blacklist_filter();
        let insn = &filter[filter.len() - 2];
        assert_eq!(insn.code, BPF_RET | BPF_K);
        assert_eq!(insn.k, SECCOMP_RET_ALLOW);
    }

    /// All 13 blacklist JEQ instructions must have valid jump offsets that
    /// point to the final RET KILL_PROCESS (insn 18).
    #[test]
    fn blacklist_jumps_target_die() {
        let filter = build_blacklist_filter();
        let die_index = filter.len() - 1; // 18

        // Instructions 4 through 16 are the blacklist checks.
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

    /// `build_blacklist_filter` must return a valid arch constant for the
    /// compiled target.
    #[test]
    fn arch_constant_is_valid() {
        let (arch, _nrs) = target_arch_config();
        match std::env::consts::ARCH {
            "x86_64" => assert_eq!(arch, AUDIT_ARCH_X86_64),
            "aarch64" => assert_eq!(arch, AUDIT_ARCH_AARCH64),
            other => panic!("unexpected target arch: {other}"),
        }
    }

    /// Syscall number tables must have exactly 13 entries.
    #[test]
    fn syscall_nrs_count() {
        let (_arch, nrs) = target_arch_config();
        assert_eq!(nrs.len(), 13);
    }

    /// The unshare syscall number must be 97 on both architectures.
    #[test]
    fn unshare_is_97() {
        let (_arch, nrs) = target_arch_config();
        // unshare is the 12th entry (index 11)
        assert_eq!(nrs[11], 97, "unshare must be syscall 97 on all architectures");
    }

    /// All 13 syscall numbers in the table must be distinct.
    #[test]
    fn no_duplicate_syscall_nrs() {
        let (_arch, nrs) = target_arch_config();
        let mut sorted = nrs.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 13, "syscall numbers must be unique");
    }
}
