//! 命名空间隔离端到端测试。
//!
//! 这些测试验证 seabox 的命名空间隔离功能：user/net/pid/uts/ipc/cgroup
//! 命名空间的创建、UID/GID 映射、hostname 设置、chdir、clearenv 等。
//!
//! 需要 Linux，缺少 namespace 支持时自动跳过。
//!
//! 测试用例：
//! - N1:  --unshare-user 基本功能
//! - N2:  --unshare-user --uid 1000
//! - N3:  --unshare-net 网络隔离
//! - N4:  --unshare-uts --hostname
//! - N5:  --unshare-all 基本功能
//! - N6:  --chdir 覆盖工作目录
//! - N7:  --clearenv 清空环境变量
//! - N8:  --unshare-pid 基本功能
//! - N9:  --unshare-uts 不含 hostname
//! - N10: --uid 需要 --unshare-user
//! - N11: --hostname 需要 --unshare-uts
//! - N12: --unshare-user-try 静默回退
//! - N13: check 输出包含命名空间状态
//! - N14: --unshare-user --uid 0 --gid 0
//! - N15: --unshare-pid 退出码转发
//! - N16: --env 设置环境变量
//! - N17: --clearenv + --env 组合
//! - N18: --unsetenv 删除环境变量
//! - N19: --env 后者覆盖前者
//! - N20: --env 不含 = 报错
//! - N21: --unsetenv 不存在的变量是 no-op

#![cfg(target_os = "linux")]

use std::process::{Command, Stdio};

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
// Skip 守卫
// ---------------------------------------------------------------------------

fn skip_if_no_user_ns() -> bool {
    if !namespaces::is_user_namespace_available() {
        eprintln!("user namespace not available, skipping test");
        return true;
    }
    false
}

fn skip_if_no_net_ns() -> bool {
    if !namespaces::is_net_namespace_available() {
        eprintln!("net namespace not available, skipping test");
        return true;
    }
    false
}

#[allow(dead_code)]
fn skip_if_no_pid_ns() -> bool {
    if !namespaces::is_pid_namespace_available() {
        eprintln!("pid namespace not available, skipping test");
        return true;
    }
    false
}

fn skip_if_no_uts_ns() -> bool {
    if !namespaces::is_uts_namespace_available() {
        eprintln!("uts namespace not available, skipping test");
        return true;
    }
    false
}

#[allow(dead_code)]
fn skip_if_no_ipc_ns() -> bool {
    if !namespaces::is_ipc_namespace_available() {
        eprintln!("ipc namespace not available, skipping test");
        return true;
    }
    false
}

#[allow(dead_code)]
fn skip_if_no_cgroup_ns() -> bool {
    if !namespaces::is_cgroup_namespace_available() {
        eprintln!("cgroup namespace not available, skipping test");
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// N1: --unshare-user 基本功能
// ---------------------------------------------------------------------------

#[test]
fn unshare_user_basic() {
    if skip_if_no_user_ns() {
        return;
    }
    let out = run_cli(&["run", "--unshare-user", "--", "id", "-u"]);
    assert_eq!(
        out.exit_code,
        Some(0),
        "unshare-user should succeed: {:?}",
        out
    );
    assert!(!out.stdout.trim().is_empty(), "id -u should output a uid");
}

// ---------------------------------------------------------------------------
// N2: --unshare-user --uid 1000
// ---------------------------------------------------------------------------

#[test]
fn unshare_user_uid_1000() {
    if skip_if_no_user_ns() {
        return;
    }
    let out = run_cli(&["run", "--unshare-user", "--uid", "1000", "--", "id", "-u"]);
    assert_eq!(out.exit_code, Some(0), "unshare-user --uid 1000: {:?}", out);
    assert_eq!(out.stdout.trim(), "1000", "uid should be 1000");
}

// ---------------------------------------------------------------------------
// N3: --unshare-net 网络隔离
// ---------------------------------------------------------------------------

#[test]
fn unshare_net_isolates() {
    if skip_if_no_net_ns() {
        return;
    }
    let out = run_cli(&["run", "--unshare-net", "--", "ls", "/sys/class/net"]);
    assert_eq!(out.exit_code, Some(0), "unshare-net ls: {:?}", out);
    // netns 中只有 lo
    assert_eq!(out.stdout.trim(), "lo", "only lo should exist in new netns");
}

// ---------------------------------------------------------------------------
// N4: --unshare-uts --hostname
// ---------------------------------------------------------------------------

#[test]
fn unshare_uts_hostname() {
    if skip_if_no_uts_ns() {
        return;
    }
    let out = run_cli(&[
        "run",
        "--unshare-uts",
        "--hostname",
        "sandbox-test",
        "--",
        "hostname",
    ]);
    assert_eq!(out.exit_code, Some(0), "unshare-uts hostname: {:?}", out);
    assert_eq!(
        out.stdout.trim(),
        "sandbox-test",
        "hostname should be sandbox-test"
    );
}

// ---------------------------------------------------------------------------
// N5: --unshare-all 基本功能
// ---------------------------------------------------------------------------

#[test]
fn unshare_all_basic() {
    if skip_if_no_user_ns() {
        return;
    }
    let out = run_cli(&["run", "--unshare-all", "--", "id", "-u"]);
    assert_eq!(
        out.exit_code,
        Some(0),
        "unshare-all should succeed: {:?}",
        out
    );
}

// ---------------------------------------------------------------------------
// N6: --chdir 覆盖工作目录
// ---------------------------------------------------------------------------

#[test]
fn chdir_override() {
    let out = run_cli(&["run", "--chdir", "/tmp", "--", "pwd"]);
    assert_eq!(out.exit_code, Some(0), "chdir to /tmp: {:?}", out);
    assert_eq!(out.stdout.trim(), "/tmp", "pwd should be /tmp");
}

// ---------------------------------------------------------------------------
// N7: --clearenv 清空环境变量
// ---------------------------------------------------------------------------

#[test]
fn clearenv_works() {
    let out = run_cli(&["run", "--clearenv", "--", "sh", "-c", "echo \"HOME=$HOME\""]);
    assert_eq!(out.exit_code, Some(0), "clearenv: {:?}", out);
    // $HOME 应该为空（环境变量已清空）
    assert_eq!(
        out.stdout.trim(),
        "HOME=",
        "HOME should be empty after clearenv"
    );
}

// ---------------------------------------------------------------------------
// N8: --unshare-pid 基本功能（验证业务进程 PID=2，reaper 是 PID 1）
// ---------------------------------------------------------------------------

#[test]
fn unshare_pid_isolates() {
    // PID ns 在非 root 下需要 user ns。如果 PID ns 探针失败但 user ns 可
    // 用，仍然可以跑（CLI 会自动隐含 --unshare-user）。
    let pid_ok = namespaces::is_pid_namespace_available();
    let user_ok = namespaces::is_user_namespace_available();
    if !pid_ok && !user_ok {
        eprintln!("neither PID ns nor user ns available, skipping test");
        return;
    }
    let out = run_cli(&["run", "--unshare-pid", "--", "sh", "-c", "echo $$"]);
    assert_eq!(
        out.exit_code,
        Some(0),
        "unshare-pid with echo $$ should succeed: {:?}",
        out
    );
    assert_eq!(
        out.stdout.trim(),
        "2",
        "in PID namespace, business process PID should be 2 (reaper is PID 1), got: {:?}",
        out.stdout
    );
}

// ---------------------------------------------------------------------------
// N9: --unshare-uts 不含 hostname
// ---------------------------------------------------------------------------

#[test]
fn unshare_uts_without_hostname() {
    if skip_if_no_uts_ns() {
        return;
    }
    let out = run_cli(&["run", "--unshare-uts", "--", "hostname"]);
    assert_eq!(
        out.exit_code,
        Some(0),
        "unshare-uts without hostname: {:?}",
        out
    );
    // 应该不崩溃，正常输出一个 hostname（可能是 "(none)" 或其他）
}

// ---------------------------------------------------------------------------
// N10: --uid 需要 --unshare-user
// ---------------------------------------------------------------------------

#[test]
fn uid_requires_unshare_user() {
    let out = run_cli(&["run", "--uid", "1000", "--", "true"]);
    assert_ne!(
        out.exit_code,
        Some(0),
        "--uid without --unshare-user should fail"
    );
    assert!(
        out.stderr.contains("--uid requires --unshare-user")
            || out.stderr.contains("requires --unshare-user"),
        "stderr should mention the requirement: {:?}",
        out.stderr
    );
}

// ---------------------------------------------------------------------------
// N11: --hostname 需要 --unshare-uts
// ---------------------------------------------------------------------------

#[test]
fn hostname_requires_unshare_uts() {
    let out = run_cli(&["run", "--hostname", "test", "--", "true"]);
    assert_ne!(
        out.exit_code,
        Some(0),
        "--hostname without --unshare-uts should fail"
    );
    assert!(
        out.stderr.contains("--hostname requires --unshare-uts")
            || out.stderr.contains("requires --unshare-uts"),
        "stderr should mention the requirement: {:?}",
        out.stderr
    );
}

// ---------------------------------------------------------------------------
// N12: --unshare-user-try 静默回退
// ---------------------------------------------------------------------------

#[test]
fn unshare_user_try_graceful() {
    // 即使在 user ns 不可用时也应该成功
    let out = run_cli(&["run", "--unshare-user-try", "--", "true"]);
    assert_eq!(
        out.exit_code,
        Some(0),
        "unshare-user-try should always succeed: {:?}",
        out
    );
}

// ---------------------------------------------------------------------------
// N13: check 输出包含命名空间状态
// ---------------------------------------------------------------------------

#[test]
fn check_reports_namespaces() {
    let out = run_cli(&["check"]);
    assert_eq!(out.exit_code, Some(0), "check should succeed: {:?}", out);
    assert!(
        out.stdout.contains("User namespace"),
        "check should show user ns: {:?}",
        out.stdout
    );
    assert!(
        out.stdout.contains("Network namespace"),
        "check should show net ns"
    );
    assert!(
        out.stdout.contains("PID namespace"),
        "check should show pid ns"
    );
    assert!(
        out.stdout.contains("IPC namespace"),
        "check should show ipc ns"
    );
    assert!(
        out.stdout.contains("UTS namespace"),
        "check should show uts ns"
    );
    assert!(
        out.stdout.contains("Cgroup namespace"),
        "check should show cgroup ns"
    );
}

// ---------------------------------------------------------------------------
// N14: --unshare-user --uid 0 --gid 0
// ---------------------------------------------------------------------------

#[test]
fn unshare_user_uid_0_gid_0() {
    if skip_if_no_user_ns() {
        return;
    }
    let out = run_cli(&[
        "run",
        "--unshare-user",
        "--uid",
        "0",
        "--gid",
        "0",
        "--",
        "sh",
        "-c",
        "id -u; id -g",
    ]);
    assert_eq!(
        out.exit_code,
        Some(0),
        "unshare-user --uid 0 --gid 0: {:?}",
        out
    );
    let lines: Vec<&str> = out.stdout.trim().lines().collect();
    assert_eq!(lines[0].trim(), "0", "uid should be 0");
    assert_eq!(lines[1].trim(), "0", "gid should be 0");
}

// ---------------------------------------------------------------------------
// N15: --unshare-pid 退出码转发
// ---------------------------------------------------------------------------

#[test]
fn unshare_pid_exit_code_forwarding() {
    let pid_ok = namespaces::is_pid_namespace_available();
    let user_ok = namespaces::is_user_namespace_available();
    if !pid_ok && !user_ok {
        eprintln!("neither PID ns nor user ns available, skipping test");
        return;
    }
    let out = run_cli(&["run", "--unshare-pid", "--", "sh", "-c", "exit 42"]);
    assert_eq!(
        out.exit_code,
        Some(42),
        "exit code 42 should be forwarded through reaper chain, got: {:?}",
        out
    );
}

// ---------------------------------------------------------------------------
// N16: --env 设置环境变量
// ---------------------------------------------------------------------------

#[test]
fn env_flag_sets_variable() {
    let out = run_cli(&[
        "run",
        "--env",
        "SANDBOX_TEST=hello",
        "--",
        "sh",
        "-c",
        "echo $SANDBOX_TEST",
    ]);
    assert_eq!(out.exit_code, Some(0), "--env: {:?}", out);
    assert_eq!(out.stdout.trim(), "hello", "SANDBOX_TEST should be 'hello'");
}

// ---------------------------------------------------------------------------
// N17: --clearenv + --env 组合（只保留 --env 设置的变量）
// ---------------------------------------------------------------------------

#[test]
fn clearenv_with_env_combines() {
    let out = run_cli(&[
        "run",
        "--clearenv",
        "--env",
        "SANDBOX_TEST=world",
        "--",
        "sh",
        "-c",
        "echo \"[$SANDBOX_TEST] [$HOME]\"",
    ]);
    assert_eq!(out.exit_code, Some(0), "clearenv+env: {:?}", out);
    assert_eq!(
        out.stdout.trim(),
        "[world] []",
        "SANDBOX_TEST should be 'world' and HOME should be empty"
    );
}

// ---------------------------------------------------------------------------
// N18: --unsetenv 删除环境变量
// ---------------------------------------------------------------------------

#[test]
fn unsetenv_removes_variable() {
    // 注意：sh（dash）有编译期内置 fallback PATH，所以不能用 `echo $PATH` 验证。
    // 直接跑 `env` 确认变量已被删除。
    let out = run_cli(&["run", "--unsetenv", "PATH", "--", "env"]);
    assert_eq!(out.exit_code, Some(0), "--unsetenv PATH: {:?}", out);
    assert!(
        !out.stdout.lines().any(|l| l.starts_with("PATH=")),
        "PATH should not appear in `env` output after --unsetenv"
    );
}

// ---------------------------------------------------------------------------
// N19: --env 后者覆盖前者
// ---------------------------------------------------------------------------

#[test]
fn env_latter_overrides_former() {
    let out = run_cli(&[
        "run",
        "--env",
        "OVERRIDE=first",
        "--env",
        "OVERRIDE=second",
        "--",
        "sh",
        "-c",
        "echo $OVERRIDE",
    ]);
    assert_eq!(out.exit_code, Some(0), "--env override: {:?}", out);
    assert_eq!(
        out.stdout.trim(),
        "second",
        "later --env should override earlier one"
    );
}

// ---------------------------------------------------------------------------
// N20: --env 不含 = 报错
// ---------------------------------------------------------------------------

#[test]
fn env_missing_equals_fails() {
    let out = run_cli(&["run", "--env", "BADKEY", "--", "sh", "-c", "echo hi"]);
    assert!(
        out.exit_code != Some(0),
        "--env BADKEY should fail, got exit_code={:?}",
        out.exit_code
    );
    assert!(
        out.stderr.contains("KEY=VALUE"),
        "stderr should contain helpful error message, got: {:?}",
        out.stderr
    );
}

// ---------------------------------------------------------------------------
// N21: --unsetenv 不存在的变量是 no-op
// ---------------------------------------------------------------------------

#[test]
fn unsetenv_nonexistent_is_noop() {
    let out = run_cli(&[
        "run",
        "--unsetenv",
        "THIS_VAR_DOES_NOT_EXIST_12345",
        "--",
        "sh",
        "-c",
        "echo ok",
    ]);
    assert_eq!(
        out.exit_code,
        Some(0),
        "unsetenv nonexistent var should be no-op, got: {:?}",
        out
    );
    assert_eq!(out.stdout.trim(), "ok");
}
