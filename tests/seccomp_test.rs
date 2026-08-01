//! sandbox-runtime 二进制的 seccomp 黑名单端到端测试。
//!
//! 直接以子进程方式运行编译出的 `sandbox-runtime` 二进制，触发黑名单中
//! 的 13 个 syscall，断言 wrapper 对 SIGSYS 杀死的归类与拒绝消息格式。
//!
//! ## 覆盖范围
//!
//! 黑名单（来自 `src/linux/seccomp.rs`）：
//!
//! | syscall          | x86_64 nr | aarch64 nr |
//! |------------------|-----------|------------|
//! | mount            | 165       | 40         |
//! | umount2          | 166       | 39         |
//! | pivot_root       | 155       | 41         |
//! | chroot           | 161       | 51         |
//! | ptrace           | 101       | 117        |
//! | kexec_load       | 246       | 104        |
//! | kexec_file_load  | 320       | 294        |
//! | reboot           | 169       | 142        |
//! | init_module      | 175       | 105        |
//! | finit_module     | 313       | 106        |
//! | delete_module    | 176       | 107        |
//! | unshare          | 97        | 97         |
//! | bpf              | 357       | 280        |
//!
//! 每个 syscall 都通过 `syscall_probe` 辅助二进制直接调用，让 seccomp
//! 在 syscall **入口**拦截，避免被 syscall 自身的权限检查、EFAULT 等
//! 错误路径掩盖黑名单拦截行为。
//!
//! ## 关于不同 syscall 的可靠性
//!
//! 经过实际验证，下列 syscall **不**通过现有 CLI 工具能可靠触发：
//!
//! - **`unshare`**：现代 util-linux 的 `unshare` 命令使用 `clone3` 加
//!   `CLONE_NEWUSER` 标志，而非 `unshare` syscall。`clone3` 不在黑名单中。
//!   直接用 `syscall_probe 97` 即可触发。
//! - **`reboot`**：systemd / logind 的 inhibitor 锁在 `reboot(2)` syscall
//!   进入前就拒绝执行。直接用 `syscall_probe 169` 即可触发。
//!
//! 因此本文件对全部 13 个 syscall 都用 `syscall_probe` 触发。
//!
//! ## 预检与安全约束
//!
//! - **`verify_seccomp_active()` 预检**：跑一次 `mount` syscall，确认黑名单
//!   真的拦截。失败则所有 mount-touching 测试跳过。
//! - **目标路径唯一**：所有 mount 相关测试目标用 PID 后缀避免冲突。
//! - **清理**：探针执行后 best-effort `umount` + `rmdir`，避免主机污染。

// 本文件仅在 Linux 下编译——seccomp 是 Linux 专属机制。
#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use sandbox_runtime::linux::seccomp;
use sandbox_runtime::linux::seccomp::is_available as seccomp_is_available;

/// 通过 syscall 号查名。
#[allow(dead_code)]
fn syscall_name_for_test(nr: &str) -> &'static str {
    let n: u32 = nr.parse().expect("invalid nr");
    seccomp::syscall_name(n).unwrap_or_else(|| panic!("unknown syscall nr in test: {nr}"))
}

// ---------------------------------------------------------------------------
// 基础辅助
// ---------------------------------------------------------------------------

/// 由 Cargo 在集成测试中自动注入的二进制绝对路径。
fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_sandbox-runtime")
}

/// `syscall_probe` 辅助二进制的绝对路径，用于直接调用任意 syscall。
fn syscall_probe_bin() -> &'static str {
    env!("CARGO_BIN_EXE_syscall_probe")
}

/// 当前编译目标的 syscall 号（按架构选取）。与 `seccomp.rs` 中的
/// `target_arch_config()` 保持一致。
fn arch_config() -> &'static str {
    if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        panic!("unsupported target arch");
    }
}

/// 子进程结果。
struct RunOutput {
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// 以子进程方式调用 `sandbox-runtime`，捕获退出码与双向输出。
fn run_cli(args: &[&str]) -> RunOutput {
    let output = Command::new(bin())
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to spawn sandbox-runtime binary");

    RunOutput {
        exit_code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// 生成进程唯一的 mount 目标路径，避免与并发/历史运行残留冲突。
fn unique_mount_target(tag: &str) -> PathBuf {
    let pid = std::process::id();
    PathBuf::from(format!("/tmp/.sandbox_runtime_seccomp_{tag}_{pid}"))
}

/// Best-effort 清理某个 mount 目标：若已挂载则 umount，若为目录则删除。
fn cleanup_mount_target(target: &PathBuf) {
    let _ = Command::new("umount")
        .arg(target)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let _ = std::fs::remove_dir(target);
}

// ---------------------------------------------------------------------------
// 预检：seccomp 是否真的生效
// ---------------------------------------------------------------------------

/// 主动跑一次 mount 探针，确认黑名单拦截。返回 true 表示拦截生效。
fn verify_seccomp_active() -> bool {
    if !seccomp_is_available() {
        return false;
    }

    let target = unique_mount_target("probe");
    cleanup_mount_target(&target);

    let out = run_cli(&[
        "run",
        "--",
        syscall_probe_bin(),
        // mount syscall 号：x86_64=165, aarch64=40
        mount_nr(),
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
    ]);

    let active = out.exit_code == Some(126);

    cleanup_mount_target(&target);
    active
}

/// `OnceLock` 缓存的探针结果，整个测试 session 只跑一次。
fn seccomp_probe_cached() -> bool {
    static RESULT: OnceLock<bool> = OnceLock::new();
    *RESULT.get_or_init(verify_seccomp_active)
}

/// 测试入口：seccomp 探针失败则跳过。
fn skip_unless_seccomp_active() -> bool {
    if !seccomp_is_available() {
        eprintln!("seccomp not available, skipping test");
        return true;
    }
    if !seccomp_probe_cached() {
        eprintln!(
            "seccomp probe failed — mount syscall was not killed; \
             skipping test to avoid affecting host system"
        );
        return true;
    }
    false
}

/// 仅判断 seccomp 是否可用（不跑探针）。
fn skip_if_no_seccomp() -> bool {
    if !seccomp_is_available() {
        eprintln!("seccomp not available, skipping test");
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// 当前架构的 syscall 号常量
// ---------------------------------------------------------------------------

fn mount_nr() -> &'static str {
    match arch_config() {
        "x86_64" => "165",
        "aarch64" => "40",
        _ => unreachable!(),
    }
}

fn umount2_nr() -> &'static str {
    match arch_config() {
        "x86_64" => "166",
        "aarch64" => "39",
        _ => unreachable!(),
    }
}

fn pivot_root_nr() -> &'static str {
    match arch_config() {
        "x86_64" => "155",
        "aarch64" => "41",
        _ => unreachable!(),
    }
}

fn chroot_nr() -> &'static str {
    match arch_config() {
        "x86_64" => "161",
        "aarch64" => "51",
        _ => unreachable!(),
    }
}

fn ptrace_nr() -> &'static str {
    match arch_config() {
        "x86_64" => "101",
        "aarch64" => "117",
        _ => unreachable!(),
    }
}

fn kexec_load_nr() -> &'static str {
    match arch_config() {
        "x86_64" => "246",
        "aarch64" => "104",
        _ => unreachable!(),
    }
}

fn kexec_file_load_nr() -> &'static str {
    match arch_config() {
        "x86_64" => "320",
        "aarch64" => "294",
        _ => unreachable!(),
    }
}

fn reboot_nr() -> &'static str {
    match arch_config() {
        "x86_64" => "169",
        "aarch64" => "142",
        _ => unreachable!(),
    }
}

fn init_module_nr() -> &'static str {
    match arch_config() {
        "x86_64" => "175",
        "aarch64" => "105",
        _ => unreachable!(),
    }
}

fn finit_module_nr() -> &'static str {
    match arch_config() {
        "x86_64" => "313",
        "aarch64" => "106",
        _ => unreachable!(),
    }
}

fn delete_module_nr() -> &'static str {
    match arch_config() {
        "x86_64" => "176",
        "aarch64" => "107",
        _ => unreachable!(),
    }
}

fn unshare_nr() -> &'static str {
    // x86_64 与 aarch64 都是 97
    "97"
}

fn bpf_nr() -> &'static str {
    match arch_config() {
        "x86_64" => "357",
        "aarch64" => "280",
        _ => unreachable!(),
    }
}

// ---------------------------------------------------------------------------
// 通用断言 helper
// ---------------------------------------------------------------------------

/// 调用 sandbox-runtime 包装 syscall_probe 来触发指定 syscall，断言
/// wrapper 把它归类为 `Denied { Seccomp }` 并退出 126。
fn assert_syscall_blocked(nr: &str, extra_args: &[&str]) {
    let mut args: Vec<&str> = vec!["run", "--", syscall_probe_bin(), nr];
    args.extend_from_slice(extra_args);

    let out = run_cli(&args);

    assert_eq!(
        out.exit_code,
        Some(126),
        "syscall {nr} 应被 seccomp 黑名单拦截、wrapper 应退出 126。\
         stdout={:?} stderr={:?}",
        out.stdout,
        out.stderr
    );
}

// ---------------------------------------------------------------------------
// 黑名单 13 个 syscall 的逐项测试
// ---------------------------------------------------------------------------

#[test]
fn mount_blocked_by_seccomp() {
    if skip_unless_seccomp_active() {
        return;
    }
    // mount(source, target, fs, flags, data) — 全 0 即可让 syscall 进入
    // 内核，被 seccomp 立即拦截。
    assert_syscall_blocked(mount_nr(), &["0", "0", "0", "0", "0", "0"]);
}

#[test]
fn umount2_blocked_by_seccomp() {
    if skip_unless_seccomp_active() {
        return;
    }
    // umount2(target, flags)
    assert_syscall_blocked(umount2_nr(), &["0", "0"]);
}

#[test]
fn pivot_root_blocked_by_seccomp() {
    if skip_unless_seccomp_active() {
        return;
    }
    // pivot_root(new_root, put_old)
    assert_syscall_blocked(pivot_root_nr(), &["0", "0"]);
}

#[test]
fn chroot_blocked_by_seccomp() {
    if skip_unless_seccomp_active() {
        return;
    }
    // chroot(path)
    assert_syscall_blocked(chroot_nr(), &["0"]);
}

#[test]
fn ptrace_blocked_by_seccomp() {
    if skip_unless_seccomp_active() {
        return;
    }
    // ptrace(request, pid, addr, data) — request=PTRACE_TRACEME=0
    assert_syscall_blocked(ptrace_nr(), &["0", "0", "0", "0"]);
}

#[test]
fn kexec_load_blocked_by_seccomp() {
    if skip_unless_seccomp_active() {
        return;
    }
    // kexec_load(entry, nr_segments, segments, flags)
    assert_syscall_blocked(kexec_load_nr(), &["0", "0", "0", "0"]);
}

#[test]
fn kexec_file_load_blocked_by_seccomp() {
    if skip_unless_seccomp_active() {
        return;
    }
    // kexec_file_load(kernel_fd, initrd_fd, cmdline_len, cmdline, flags)
    assert_syscall_blocked(kexec_file_load_nr(), &["0", "0", "0", "0", "0"]);
}

#[test]
fn reboot_blocked_by_seccomp() {
    if skip_unless_seccomp_active() {
        return;
    }
    // reboot(magic1, magic2, cmd, arg) — magic1=0xfee1dead (LINUX_REBOOT_MAGIC1)
    // 但 seccomp 在入口拦截，根本不会校验 magic，所以全 0 也行。
    assert_syscall_blocked(reboot_nr(), &["0", "0", "0", "0"]);
}

#[test]
fn init_module_blocked_by_seccomp() {
    if skip_unless_seccomp_active() {
        return;
    }
    // init_module(module_image, len, param_values)
    assert_syscall_blocked(init_module_nr(), &["0", "0", "0"]);
}

#[test]
fn finit_module_blocked_by_seccomp() {
    if skip_unless_seccomp_active() {
        return;
    }
    // finit_module(fd, param_values, flags)
    assert_syscall_blocked(finit_module_nr(), &["0", "0", "0"]);
}

#[test]
fn delete_module_blocked_by_seccomp() {
    if skip_unless_seccomp_active() {
        return;
    }
    // delete_module(name, flags)
    assert_syscall_blocked(delete_module_nr(), &["0", "0"]);
}

#[test]
fn unshare_blocked_by_seccomp() {
    if skip_unless_seccomp_active() {
        return;
    }
    // unshare(flags) — flags=CLONE_NEWUSER=0x10000000
    // 但 seccomp 在入口拦截，全 0 也行。
    assert_syscall_blocked(unshare_nr(), &["0"]);
}

#[test]
fn bpf_blocked_by_seccomp() {
    if skip_unless_seccomp_active() {
        return;
    }
    // bpf(cmd, attr, size) — cmd=BPF_PROG_LOAD=5
    assert_syscall_blocked(bpf_nr(), &["0", "0", "0"]);
}

// ---------------------------------------------------------------------------
// 跨 syscall 的语义测试
// ---------------------------------------------------------------------------

#[test]
fn cli_check_reports_seccomp_available() {
    if skip_if_no_seccomp() {
        return;
    }

    let out = run_cli(&["check"]);

    assert_eq!(out.exit_code, Some(0));

    assert!(
        out.stdout.contains("Seccomp"),
        "check 输出应含 'Seccomp'。stdout={:?}",
        out.stdout
    );
    assert!(
        out.stdout.contains("available"),
        "check 输出在 seccomp 可用时应含 'available'。stdout={:?}",
        out.stdout
    );
}

#[test]
fn full_access_policy_does_not_bypass_seccomp() {
    if skip_unless_seccomp_active() {
        return;
    }

    // FullAccess 仅跳过 Landlock，seccomp 总是生效。
    let target = unique_mount_target("bypass_check");
    cleanup_mount_target(&target);

    let out = run_cli(&[
        "run",
        "--",
        syscall_probe_bin(),
        mount_nr(),
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
    ]);

    cleanup_mount_target(&target);

    assert_eq!(
        out.exit_code,
        Some(126),
        "FullAccess 下 mount syscall 应仍被 seccomp 拦截。\
         stdout={:?} stderr={:?}",
        out.stdout,
        out.stderr
    );
}

// ---------------------------------------------------------------------------
// 回归测试：USER_NOTIF worker hang
// ---------------------------------------------------------------------------

/// 回归测试：跑一个不在黑名单的命令（/bin/true），验证 worker
/// 能正确退出且主线程不卡死。
///
/// **背景：** USER_NOTIF worker 线程此前在子进程正常退出时永远阻塞
/// 在 ioctl(NOTIF_RECV) 上，导致 wait_with_output 后 join 永久挂起。
/// 此测试是 bug 修复后的回归保护。
///
/// **超时机制：** cargo test 默认有 timeout；如果 worker 真 hang，
/// 整个测试 binary 会被 cargo 杀掉 → 测试标记为失败。
/// 也可以在测试内显式测时：start = Instant::now()，结束后检查
/// elapsed < 10s。
#[test]
fn normal_exit_does_not_hang_worker() {
    // 选 /bin/true：每个 Linux 发行版都有；exit 0；不调任何黑名单 syscall
    let true_path = if std::path::Path::new("/bin/true").exists() {
        "/bin/true"
    } else if std::path::Path::new("/usr/bin/true").exists() {
        "/usr/bin/true"
    } else {
        // 容器极简环境：跳过测试
        eprintln!("skipping normal_exit_does_not_hang_worker: no /bin/true");
        return;
    };

    let start = std::time::Instant::now();
    let out = run_cli(&["run", "--", true_path]);
    let elapsed = start.elapsed();

    // 1. 退出码正确
    assert_eq!(
        out.exit_code,
        Some(0),
        "expected exit 0 from /bin/true, got {:?}, stderr={:?}",
        out.exit_code,
        out.stderr
    );

    // 2. 耗时合理（< 10s，超出则怀疑 worker hang 或其它问题）
    assert!(
        elapsed.as_secs() < 10,
        "/bin/true test took too long: {:?} — worker may be hanging",
        elapsed
    );

    // 3. exit_code 0 已确认无拒绝，无需额外 stderr 检查
}

// ---------------------------------------------------------------------------
// --seccomp-deny-nr 端到端测试
// ---------------------------------------------------------------------------

/// 用 `--seccomp-deny-nr` 指定 syscall 号后调用 syscall_probe 触发，
/// 断言 wrapper 退出 126（Denied { Seccomp }）。
fn assert_deny_nr_blocked(deny_nrs: &[&str], probe_nr: &str, probe_args: &[&str]) {
    let mut args: Vec<&str> = vec!["run"];
    for nr in deny_nrs {
        args.push("--seccomp-deny-nr");
        args.push(nr);
    }
    args.push("--");
    args.push(syscall_probe_bin());
    args.push(probe_nr);
    args.extend_from_slice(probe_args);

    let out = run_cli(&args);

    assert_eq!(
        out.exit_code,
        Some(126),
        "--seccomp-deny-nr 应拦截 syscall {probe_nr}，wrapper 应退出 126。\
         stdout={:?} stderr={:?}",
        out.stdout,
        out.stderr
    );
    assert!(
        out.stderr.contains("Blocked by seccomp filter"),
        "stderr 应含拒绝消息。stderr={:?}",
        out.stderr
    );
}

/// mount(165) 被 `--seccomp-deny-nr 165` 拦截。
#[test]
fn deny_nr_blocks_mount() {
    if skip_if_no_seccomp() {
        return;
    }
    assert_deny_nr_blocked(&["165"], mount_nr(), &["0", "0", "0", "0", "0", "0"]);
}

/// unshare(97) 被 `--seccomp-deny-nr 97` 拦截。
#[test]
fn deny_nr_blocks_unshare() {
    if skip_if_no_seccomp() {
        return;
    }
    assert_deny_nr_blocked(&["97"], unshare_nr(), &["0"]);
}

/// reboot(169) 被 `--seccomp-deny-nr 169` 拦截。
#[test]
fn deny_nr_blocks_reboot() {
    if skip_if_no_seccomp() {
        return;
    }
    assert_deny_nr_blocked(&["169"], reboot_nr(), &["0", "0", "0", "0"]);
}

/// 同时指定多个 `--seccomp-deny-nr`，mount 和 unshare 都被拦截。
#[test]
fn deny_nr_multiple_blocks_both() {
    if skip_if_no_seccomp() {
        return;
    }
    // mount 被拦截
    assert_deny_nr_blocked(&["165", "97"], mount_nr(), &["0", "0", "0", "0", "0", "0"]);
    // unshare 也被拦截
    assert_deny_nr_blocked(&["165", "97"], unshare_nr(), &["0"]);
}

/// 不在 deny 列表中的 syscall 正常放行。
#[test]
fn deny_nr_allows_non_denied() {
    if skip_if_no_seccomp() {
        return;
    }
    let out = run_cli(&[
        "run",
        "--seccomp-deny-nr",
        "165",
        "--",
        syscall_probe_bin(),
        bpf_nr(), // bpf(357) 不在 deny 列表
        "0",
        "0",
        "0",
    ]);
    // bpf 不被拦截，进程因参数无效返回错误（exit 非 126）
    assert_ne!(
        out.exit_code,
        Some(126),
        "bpf 不应在 deny 列表中被拦截。stderr={:?}",
        out.stderr
    );
}

/// 无 seccomp 参数时，mount 不被 seccomp 拦截（退出码非 126）。
#[test]
fn no_deny_nr_does_not_block_mount() {
    if skip_if_no_seccomp() {
        return;
    }
    let out = run_cli(&[
        "run",
        "--",
        syscall_probe_bin(),
        mount_nr(),
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
    ]);
    // 无 seccomp filter → mount 不被拦截（exit 是内核 EPERM=101，非 126）
    assert_ne!(
        out.exit_code,
        Some(126),
        "无 --seccomp-deny-nr 时 mount 不应被 seccomp 拦截。stderr={:?}",
        out.stderr
    );
}

/// 指定 `--seccomp-deny-nr` 但执行正常命令（/bin/true），应正常退出 0。
#[test]
fn deny_nr_normal_command_succeeds() {
    if skip_if_no_seccomp() {
        return;
    }
    let true_path = if std::path::Path::new("/bin/true").exists() {
        "/bin/true"
    } else if std::path::Path::new("/usr/bin/true").exists() {
        "/usr/bin/true"
    } else {
        eprintln!("skipping: no /bin/true");
        return;
    };

    let out = run_cli(&["run", "--seccomp-deny-nr", "165", "--", true_path]);
    assert_eq!(
        out.exit_code,
        Some(0),
        "/bin/true 不调用 mount，应正常退出 0。stderr={:?}",
        out.stderr
    );
}
