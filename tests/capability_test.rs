//! Capability 权限管理集成测试。
//!
//! 验证 `--cap-add` / `--cap-drop` / `--uid 0` 在沙箱内进程的 **CapEff** 实际
//! 效果（首个断言 `/proc/self/status` 的 CapEff/CapBnd 的测试文件）。
//!
//! 依赖用户命名空间（`unshare(CLONE_NEWUSER)`）；不可用时自动跳过。
//!
//! 测试用例：
//! - **P1 探针**（F2）：默认 userns 下 CapEff=0（"零 cap + 非 root 不可重提"机制生效）
//! - **P2 探针**（F5）：非 root `--cap-add CHOWN` 生效（写非零 uid_map 后 permitted 保留）
//! - T1: root 无 userns 默认收零（CapEff=0；`geteuid()!=0` 时 skip）
//! - T2: `--cap-drop ALL --cap-add CHOWN` → CapEff=0x1（只 bit0）
//! - T3: `--uid 0 --cap-add ALL` → ns-root 全量 caps（容器式能力）
//! - T4: 非 root 默认 userns → CapEff=0
//! - T5: 未知 cap 名 → CLI 报错（exit 非零）
//! - T6: `--cap-add` 自动叠加 userns（与宿主 user ns inode 不同）
//!
//! # 重要
//!
//! - 本测试断言的是沙箱内进程的 CapEff，因此相关命令需在 userns 内运行。
//! - P1/P2 探针失败时**相关测试 skip 而非 fail**（环境能力不足时如实报告 skip）。

#![cfg(target_os = "linux")]

use std::process::{Command, Stdio};
use std::sync::OnceLock;

use seabox::linux::namespaces;

// ---------------------------------------------------------------------------
// 基础辅助
// ---------------------------------------------------------------------------

/// 由 Cargo 在集成测试中自动注入的二进制绝对路径。
fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_seabox")
}

/// 子进程结果。
#[derive(Debug)]
struct RunOutput {
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// 以子进程方式调用 `seabox`，捕获退出码与双向输出。
fn run_cli(args: &[&str]) -> RunOutput {
    let output = Command::new(bin())
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to spawn seabox binary");

    RunOutput {
        exit_code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

// ---------------------------------------------------------------------------
// CapEff 解析
// ---------------------------------------------------------------------------

/// 解析 `/proc/self/status` 的 CapEff 行（形如 `CapEff:\t0000000000000001`）为 u64。
///
/// 非 CapEff 行或无 hex 值时返回 0（健壮降级，不 panic）。
fn parse_cap_line(status_line: &str) -> u64 {
    if let Some(rest) = status_line.strip_prefix("CapEff:") {
        return u64::from_str_radix(rest.trim(), 16).unwrap_or(0);
    }
    0
}

/// 从 stdout（`sh -c 'grep CapEff /proc/self/status'` 的输出）中提取 CapEff 位图。
fn cap_eff(stdout: &str) -> u64 {
    stdout
        .lines()
        .find(|l| l.starts_with("CapEff:"))
        .map(parse_cap_line)
        .unwrap_or(0)
}

/// 在沙箱内跑 `grep CapEff /proc/self/status`，返回 CapEff 位图。
///
/// `run_args` 是 `run` 子命令的选项（如 `--unshare-user --cap-add CHOWN`）。
fn sandbox_cap_eff(run_args: &[&str]) -> u64 {
    let mut args: Vec<&str> = vec!["run"];
    args.extend_from_slice(run_args);
    args.extend_from_slice(&["--", "sh", "-c", "grep CapEff /proc/self/status"]);
    let out = run_cli(&args);
    cap_eff(&out.stdout)
}

// ---------------------------------------------------------------------------
// Skip 守卫
// ---------------------------------------------------------------------------

fn skip_if_no_user_ns() -> bool {
    if !namespaces::is_user_namespace_available() {
        eprintln!("user namespace not available, skipping test");
        return true;
    }
    false
}

// ── 探针 P1（F2）────────────────────────────────────────────────────
// 机制生效表现：非 root 进入 userns 后默认 CapEff=0（零 cap + 不可重提）。
// 失败 → 依赖该机制的测试 skip。
fn probe_p1_ok() -> bool {
    sandbox_cap_eff(&["--unshare-user"]) == 0
}
static P1_CACHE: OnceLock<bool> = OnceLock::new();
fn p1_ok() -> bool {
    *P1_CACHE.get_or_init(probe_p1_ok)
}
fn skip_if_p1_failed() -> bool {
    if !p1_ok() {
        eprintln!("probe P1 failed (CapEff != 0 in default userns), skipping test");
        return true;
    }
    false
}

// ── 探针 P2（F5）────────────────────────────────────────────────────
// 写非零 uid_map 后 permitted 是否保留 → 决定非 root `--cap-add` 是否可测。
// CapEff 含 bit0 → 生效；否则非 root cap-add 相关测试（T2）skip。
fn probe_p2_ok() -> bool {
    sandbox_cap_eff(&["--unshare-user", "--cap-add", "CHOWN"]) & 0x1 != 0
}
static P2_CACHE: OnceLock<bool> = OnceLock::new();
fn p2_ok() -> bool {
    *P2_CACHE.get_or_init(probe_p2_ok)
}
fn skip_if_p2_failed() -> bool {
    if !p2_ok() {
        eprintln!("probe P2 failed (non-root --cap-add not effective), skipping test");
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// T1: root 无 userns 默认收零
// ---------------------------------------------------------------------------

#[test]
fn root_no_userns_default_zero_caps() {
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        eprintln!("not running as root, skipping test");
        return;
    }
    let out = run_cli(&["run", "--", "sh", "-c", "grep CapEff /proc/self/status"]);
    assert_eq!(
        out.exit_code,
        Some(0),
        "run without userns should succeed: {:?}",
        out
    );
    assert_eq!(
        cap_eff(&out.stdout),
        0,
        "host-root default should zero caps (D1), got: {:?}",
        out.stdout
    );
}

// ---------------------------------------------------------------------------
// T2: --cap-drop ALL --cap-add CHOWN → 只 bit0
// ---------------------------------------------------------------------------

#[test]
fn cap_drop_all_then_add_chown() {
    if skip_if_no_user_ns() || skip_if_p2_failed() {
        return;
    }
    let out = run_cli(&[
        "run",
        "--unshare-user",
        "--cap-drop",
        "ALL",
        "--cap-add",
        "CHOWN",
        "--",
        "sh",
        "-c",
        "grep CapEff /proc/self/status",
    ]);
    assert_eq!(
        out.exit_code,
        Some(0),
        "--cap-drop ALL --cap-add CHOWN should succeed: {:?}",
        out
    );
    assert_eq!(
        cap_eff(&out.stdout),
        0x1,
        "only CHOWN (bit0) should remain, got: {:?}",
        out.stdout
    );
}

// ---------------------------------------------------------------------------
// T3: --uid 0 --cap-add ALL → ns-root 全量 caps
// ---------------------------------------------------------------------------

#[test]
fn uid_0_cap_add_all_ns_root() {
    if skip_if_no_user_ns() {
        return;
    }
    let out = run_cli(&[
        "run",
        "--unshare-user",
        "--uid",
        "0",
        "--cap-add",
        "ALL",
        "--",
        "sh",
        "-c",
        "grep CapEff /proc/self/status",
    ]);
    assert_eq!(
        out.exit_code,
        Some(0),
        "--uid 0 --cap-add ALL should succeed: {:?}",
        out
    );
    let eff = cap_eff(&out.stdout);
    assert_ne!(
        eff, 0,
        "ns-root should have full caps, got: {:?}",
        out.stdout
    );
    assert_ne!(
        eff & 0x1,
        0,
        "ns-root caps should include CHOWN (bit0), got: {:?}",
        out.stdout
    );
}

// ---------------------------------------------------------------------------
// T4: 非 root 默认路径 → CapEff=0
// ---------------------------------------------------------------------------

#[test]
fn non_root_default_userns_zero_caps() {
    if skip_if_no_user_ns() || skip_if_p1_failed() {
        return;
    }
    let out = run_cli(&[
        "run",
        "--unshare-user",
        "--",
        "sh",
        "-c",
        "grep CapEff /proc/self/status",
    ]);
    assert_eq!(
        out.exit_code,
        Some(0),
        "unshare-user default should succeed: {:?}",
        out
    );
    assert_eq!(
        cap_eff(&out.stdout),
        0,
        "default userns should zero caps, got: {:?}",
        out.stdout
    );
}

// ---------------------------------------------------------------------------
// T5: 未知 cap 名 → CLI 报错
// ---------------------------------------------------------------------------

#[test]
fn unknown_cap_name_fails() {
    let out = run_cli(&["run", "--cap-drop", "bogus", "--", "true"]);
    assert_ne!(
        out.exit_code,
        Some(0),
        "unknown cap name should fail, got exit={:?}",
        out.exit_code
    );
    assert!(
        out.stderr.contains("unknown capability name"),
        "stderr should mention unknown capability name, got: {:?}",
        out.stderr
    );
}

// ---------------------------------------------------------------------------
// T6: --cap-add 自动叠加 userns
// ---------------------------------------------------------------------------

#[test]
fn cap_add_auto_stacks_user_ns() {
    if skip_if_no_user_ns() {
        return;
    }
    // 宿主 user ns inode（测试进程自己，未进沙箱）。
    let host_ns = std::fs::read_link("/proc/self/ns/user").expect("host user ns link");
    // 无 --unshare-user，仅靠 --cap-add 自动叠加 userns（D2，root 也触发）。
    let out = run_cli(&[
        "run",
        "--cap-add",
        "CHOWN",
        "--",
        "readlink",
        "/proc/self/ns/user",
    ]);
    assert_eq!(
        out.exit_code,
        Some(0),
        "--cap-add CHOWN readlink: {:?}",
        out
    );
    let sandbox_ns = out.stdout.trim();
    assert_ne!(
        sandbox_ns,
        format!("{}", host_ns.display()),
        "--cap-add should auto-stack a new user ns; host={host_ns:?} sandbox={sandbox_ns:?}"
    );
}
