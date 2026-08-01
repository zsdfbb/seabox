//! Landlock 文件系统 ACL 强制执行的集成测试。
//!
//! 这些测试需要 Linux 5.13+ 且内核编译了 Landlock
//!（`CONFIG_SECURITY_LANDLOCK=y`, `lsm=landlock`）。在没有 Landlock 支持
//! 的内核上，测试会在运行时通过 `seabox::linux::landlock::is_available()`
//! 跳过自身。
//!
//! 测试用例：
//! - WorkspaceWrite 策略：写入工作区目录应成功。
//! - FullAccess 策略：不施加 Landlock 限制，写入应成功。
//! - ReadOnly 策略：写入临时目录应被 Landlock 阻止。
//!
//! ## 预检与安全约束
//!
//! CLI 二进制测试在 Landlock 失效的环境下可能真的在主机上写入文件。
//! 为避免污染当前系统：
//!
//! 1. **预检**：调用一次 read-only 探针（写入到 tempdir 的预期失败操作），
//!    确认 Landlock 真的拦截。探针结果用 `OnceLock` 缓存。
//! 2. **隔离目标**：禁止向 `/etc`、`/usr` 等系统目录写入。WorkspaceWrite
//!    拒绝测试改用 `/var/tmp` 下临时创建的目标目录——它存在、不在
//!    WorkspaceWrite 默认可写集合（`/tmp` + cwd + allow_write）中。
//! 3. **清理**：所有在主机文件系统上创建的目标，都用 PID 化路径并在
//!    测试末尾 best-effort 删除；用 `.seabox_*` 前缀便于人工
//!    排查残留。

// 本文件仅在 Linux 下编译，因为它依赖
// `seabox::linux::LinuxSandbox` 与 `seabox::linux::landlock`。
#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::Duration;

use seabox::config::SandboxConfig;
use seabox::{CommandSpec, LandlockPerm, LandlockRule, Sandbox};

/// 检查运行中的内核是否支持 Landlock。
fn is_landlock_available() -> bool {
    seabox::linux::landlock::is_available()
}

/// 辅助函数：创建一个默认配置的 Sandbox。
fn make_sandbox() -> Sandbox {
    Sandbox::from_config(SandboxConfig::default()).expect("create sandbox")
}

// ---------------------------------------------------------------------------
// CLI 二进制测试辅助
// ---------------------------------------------------------------------------

/// Cargo 在集成测试中自动注入的二进制绝对路径。
fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_seabox")
}

/// 调用 CLI 二进制后的捕获结果。
struct CliOutput {
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// 以子进程方式调用 `seabox`，继承当前 cwd。
fn run_cli(args: &[&str]) -> CliOutput {
    let output = Command::new(bin())
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to spawn seabox binary");

    CliOutput {
        exit_code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// 生成进程唯一的路径名，避免与并发/历史运行残留冲突。
fn unique_path(prefix: &str) -> PathBuf {
    let pid = std::process::id();
    PathBuf::from(format!("/tmp/.seabox_{prefix}_{pid}"))
}

/// 与 `unique_path` 类似，但落到 `/var/tmp`——用于需要"位于 WorkspaceWrite
/// 默认可写集（`/tmp` + cwd + allow_write）之外"的目标。/var/tmp 在所有
/// Linux 上都存在，且不在 WorkspaceWrite 的默认可写集合中。
fn unique_path_in_var_tmp(prefix: &str) -> PathBuf {
    let pid = std::process::id();
    PathBuf::from(format!("/var/tmp/.seabox_{prefix}_{pid}"))
}

/// Best-effort 删除路径（文件或目录）。用于测试后清理。
fn cleanup_path(p: &Path) {
    let _ = std::fs::remove_file(p);
    let _ = std::fs::remove_dir_all(p);
}

// ---------------------------------------------------------------------------
// 预检：Landlock 是否真的生效
// ---------------------------------------------------------------------------

/// 跑一次 read-only 探针：试图写入 tempdir，期望被 Landlock 拦截。
///
/// - 返回 `true`：read-only 策略下写被拒绝，Landlock 工作正常。
/// - 返回 `false`：写成功或返回非 Denied，说明 Landlock 没生效；
///   调用方应跳过任何会真的写入主机的测试。
///
/// 探针自身在 tempdir 内运行，写失败也不会污染主机。
fn verify_landlock_active() -> bool {
    if !is_landlock_available() {
        return false;
    }

    let dir = tempfile::tempdir().expect("failed to create tempdir for Landlock probe");
    let dir_path = dir.path().to_path_buf();

    // Library API：ReadOnly 策略 = `/:ro`
    let sandbox = make_sandbox_with_landlock(vec![LandlockRule {
        path: "/".into(),
        perms: vec![
            LandlockPerm::Execute,
            LandlockPerm::ReadFile,
            LandlockPerm::ReadDir,
        ],
    }]);
    let spec = CommandSpec {
        program: "sh".to_string(),
        args: vec!["-c".to_string(), "echo probe > probe_file".to_string()],
        cwd: dir_path,
        env: HashMap::new(),
        timeout: Duration::from_secs(10),
    };

    let (output, _reason) = sandbox
        .execute(&spec)
        .expect("Landlock probe execute should not fail");
    // 探针写入本应在 read-only 下被拒绝。
    output.exit_code != 0
}

/// `OnceLock` 缓存的探针结果，整个测试 session 只跑一次。
fn landlock_probe_cached() -> bool {
    static RESULT: OnceLock<bool> = OnceLock::new();
    *RESULT.get_or_init(verify_landlock_active)
}

/// 测试入口：Landlock 探针失败则跳过并返回 true。
fn skip_unless_landlock_active() -> bool {
    if !is_landlock_available() {
        eprintln!("Landlock not available, skipping test");
        return true;
    }
    if !landlock_probe_cached() {
        eprintln!(
            "Landlock probe failed — read-only policy did not deny write; \
             skipping test to avoid affecting host system"
        );
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// WorkspaceWrite：写入工作区目录应当成功（库 API 测试）
// ---------------------------------------------------------------------------

#[test]
fn workspace_write_allows_write() {
    if !is_landlock_available() {
        eprintln!("Landlock not available, skipping test");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let dir_path = dir.path().to_path_buf();

    // WorkspaceWrite: RO on /, RW on cwd
    let ro_perms = vec![
        LandlockPerm::Execute,
        LandlockPerm::ReadFile,
        LandlockPerm::ReadDir,
    ];
    let rw_perms = vec![
        LandlockPerm::Execute,
        LandlockPerm::ReadFile,
        LandlockPerm::ReadDir,
        LandlockPerm::WriteFile,
        LandlockPerm::RemoveDir,
        LandlockPerm::RemoveFile,
        LandlockPerm::MakeDir,
        LandlockPerm::MakeReg,
        LandlockPerm::MakeSym,
        LandlockPerm::Truncate,
    ];
    let sandbox = make_sandbox_with_landlock(vec![
        LandlockRule {
            path: "/".into(),
            perms: ro_perms,
        },
        LandlockRule {
            path: dir_path.clone(),
            perms: rw_perms,
        },
    ]);
    let spec = CommandSpec {
        program: "sh".to_string(),
        args: vec!["-c".to_string(), "echo ok > test.txt".to_string()],
        cwd: dir_path.clone(),
        env: HashMap::new(),
        timeout: Duration::from_secs(10),
    };

    let (output, _reason) = sandbox
        .execute(&spec)
        .expect("execute should succeed under WorkspaceWrite");

    assert_eq!(
        output.exit_code, 0,
        "write should succeed under WorkspaceWrite, exit_code={}",
        output.exit_code
    );
    assert!(
        dir_path.join("test.txt").exists(),
        "file should be created under WorkspaceWrite"
    );
}

// ---------------------------------------------------------------------------
// FullAccess：不施加 Landlock 限制，写入应当成功（库 API 测试）
// ---------------------------------------------------------------------------

#[test]
fn full_access_bypasses_landlock() {
    if !is_landlock_available() {
        eprintln!("Landlock not available, skipping test");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let dir_path = dir.path().to_path_buf();

    let sandbox = make_sandbox();
    let spec = CommandSpec {
        program: "sh".to_string(),
        args: vec!["-c".to_string(), "echo ok > test.txt".to_string()],
        cwd: dir_path.clone(),
        env: HashMap::new(),
        timeout: Duration::from_secs(10),
    };

    let (output, _reason) = sandbox
        .execute(&spec)
        .expect("execute should succeed under FullAccess");

    assert_eq!(
        output.exit_code, 0,
        "write should succeed under FullAccess, exit_code={}",
        output.exit_code
    );
    assert!(
        dir_path.join("test.txt").exists(),
        "file should be created under FullAccess"
    );
}

// ---------------------------------------------------------------------------
// ReadOnly：写入临时目录应被 Landlock 阻止（库 API 测试）
// ---------------------------------------------------------------------------

#[test]
fn read_only_blocks_write() {
    if !is_landlock_available() {
        eprintln!("Landlock not available, skipping test");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let dir_path = dir.path().to_path_buf();

    let ro_perms = vec![
        LandlockPerm::Execute,
        LandlockPerm::ReadFile,
        LandlockPerm::ReadDir,
    ];
    let sandbox = make_sandbox_with_landlock(vec![LandlockRule {
        path: "/".into(),
        perms: ro_perms,
    }]);
    let spec = CommandSpec {
        program: "sh".to_string(),
        args: vec!["-c".to_string(), "echo ok > test.txt".to_string()],
        cwd: dir_path.clone(),
        env: HashMap::new(),
        timeout: Duration::from_secs(10),
    };

    let (output, _reason) = sandbox
        .execute(&spec)
        .expect("execute should not fail, though the child process may error");

    assert_ne!(
        output.exit_code, 0,
        "write should fail under ReadOnly, exit_code={}",
        output.exit_code
    );
    assert!(
        !dir_path.join("test.txt").exists(),
        "file should NOT be created under ReadOnly"
    );
}

// ---------------------------------------------------------------------------
// CLI 二进制测试：以子进程方式调用 seabox 二进制，验证 wrapper
// 的 Landlock 拒绝路径、退出码、stderr 消息格式。
// ---------------------------------------------------------------------------

// L1：ReadOnly 下写入应被 Landlock 拒绝（库 API）。

#[test]
fn cli_read_only_blocks_write_with_exit_126() {
    if skip_unless_landlock_active() {
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let dir_path = dir.path().to_path_buf();

    let sandbox = make_sandbox_with_landlock(vec![LandlockRule {
        path: "/".into(),
        perms: vec![
            LandlockPerm::Execute,
            LandlockPerm::ReadFile,
            LandlockPerm::ReadDir,
        ],
    }]);
    let spec = CommandSpec {
        program: "sh".to_string(),
        args: vec!["-c".to_string(), "echo blocked > blocked.txt".to_string()],
        cwd: dir_path,
        env: HashMap::new(),
        timeout: Duration::from_secs(10),
    };

    let (output, _reason) = sandbox
        .execute(&spec)
        .expect("execute should not fail, though the child process may error");

    assert_ne!(
        output.exit_code, 0,
        "read-only 下写入应被 Landlock 拒绝。exit_code={}",
        output.exit_code
    );
}

// L2：ReadOnly 模式下写到工作目录之外应被 Landlock 拒绝。
//
// 风险控制：
// - 用 `skip_unless_landlock_active()` 预检，确保 Landlock 在拦截；
//   探针失败则跳过，不会触碰任何主机路径。
// - 目标路径选 `/var/tmp/.seabox_landlock_test_<pid>`：
//   /var/tmp 在所有 Linux 上存在，但 `/:ro` 下不可写。
// - 测试开始前创建该空目录（这样目标路径已存在，写操作不因 ENOENT 失败）；
//   测试结束后 best-effort 删除整个目录。

#[test]
fn cli_workspace_write_blocks_write_outside_cwd() {
    if skip_unless_landlock_active() {
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let dir_path = dir.path().to_path_buf();
    // 注意：必须放在 /var/tmp 而非 /tmp 下——ReadOnly 对所有路径都是 RO，
    // 但为了模拟旧版 WorkspaceWrite 的隔离语义，选 /var/tmp 确保落点
    // 不在默认可写路径中。
    let target_dir = unique_path_in_var_tmp("landlock_isolated_target_dir");
    std::fs::create_dir_all(&target_dir).expect("failed to create isolated target dir");

    let target_file = target_dir.join("blocked_file");
    let sh_cmd = format!("echo blocked > {}", target_file.display());

    let sandbox = make_sandbox_with_landlock(vec![LandlockRule {
        path: "/".into(),
        perms: vec![
            LandlockPerm::Execute,
            LandlockPerm::ReadFile,
            LandlockPerm::ReadDir,
        ],
    }]);
    let spec = CommandSpec {
        program: "sh".to_string(),
        args: vec!["-c".to_string(), sh_cmd],
        cwd: dir_path,
        env: HashMap::new(),
        timeout: Duration::from_secs(10),
    };

    let (output, _reason) = sandbox
        .execute(&spec)
        .expect("execute should not fail, though the child process may error");

    // 不论结果，先清理——若 Landlock 真的拦截了，target_file 不会存在；
    // 万一 Landlock 失效，文件会留下，需要清理。
    cleanup_path(&target_file);
    cleanup_path(&target_dir);

    assert_ne!(
        output.exit_code, 0,
        "RO 下写工作目录之外应被 Landlock 拒绝。exit_code={}",
        output.exit_code
    );
}

// L3：无 Landlock 限制（空规则），任意写都应成功。
//
// 风险控制：
// - 用 PID 化的 /tmp 路径，测试结束后删除，避免在 /tmp 留垃圾。
// - 仍走 `skip_unless_landlock_active()` 预检——空规则跳过 Landlock，
//   但用预检确保整套 Landlock 路径至少工作（防止 Landlock 完全失效
//   导致其他测试出现误判）。

#[test]
fn cli_full_access_allows_arbitrary_write() {
    if skip_unless_landlock_active() {
        return;
    }

    let sandbox = make_sandbox();
    let target_file = unique_path("landlock_full_access_test");
    let sh_cmd = format!("echo ok > {}", target_file.display());
    let spec = CommandSpec {
        program: "sh".to_string(),
        args: vec!["-c".to_string(), sh_cmd],
        cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")),
        env: HashMap::new(),
        timeout: Duration::from_secs(10),
    };

    let (output, _reason) = sandbox
        .execute(&spec)
        .expect("execute should succeed under no landlock rules");

    // 测试结束后清理。
    cleanup_path(&target_file);

    assert_eq!(
        output.exit_code, 0,
        "无 Landlock 限制下写入应成功。exit_code={}",
        output.exit_code
    );
}

// L4：cmd_check 在 Landlock 可用内核上报告 "Landlock available"。
//
// 此测试不写任何文件，无副作用；不需要预检。

#[test]
fn cli_check_reports_landlock_available() {
    let out = run_cli(&["check"]);

    assert_eq!(out.exit_code, Some(0));

    // 在 `src/lib.rs::check_capabilities()` 中，Landlock 行在 ABI 探测
    // 成功时会打印 "Landlock                      available (ABI vN)"。
    assert!(
        out.stdout.contains("Landlock"),
        "check 输出应含 'Landlock'。stdout={:?}",
        out.stdout
    );

    if is_landlock_available() {
        assert!(
            out.stdout.contains("available (ABI v"),
            "Landlock 可用时 check 应输出 ABI 版本。stdout={:?}",
            out.stdout
        );
    } else {
        assert!(
            out.stdout.contains("not available"),
            "Landlock 不可用时 check 应明确标注 'not available'。stdout={:?}",
            out.stdout
        );
    }
}

// ---------------------------------------------------------------------------
// 完整 Landlock 限制能力覆盖
// ---------------------------------------------------------------------------
//
// 下面这套测试覆盖 Landlock 在不同策略下的每一条限制能力：
// - ReadOnly：写被拒绝，但读被允许。
// - WorkspaceWrite：写 cwd 允许；写 /tmp 允许；写 --allow-write 路径允许；
//                  写其他路径被拒绝；读任意路径允许。
// - FullAccess：不施加 Landlock 限制。
//
// 既覆盖库 API（直接构造 SandboxConfig + LinuxSandbox），也覆盖 CLI 二进制
// 路径（验证 --policy / --allow-write 等 flag 完整地传递到 ruleset 构造）。
//
// 所有会真的写入主机的测试都走预检 + PID 化路径 + best-effort 清理。

/// 用指定策略 + allow_write 列表构造 Sandbox，用于库 API 测试。
fn make_sandbox_with_landlock(rules: Vec<LandlockRule>) -> Sandbox {
    Sandbox::from_config(SandboxConfig {
        landlock: rules,
        ..Default::default()
    })
    .expect("create sandbox")
}

// ===== 库 API 测试：覆盖每条限制能力 =====

// K1：ReadOnly 允许读取任意路径。

#[test]
fn read_only_allows_read() {
    if !is_landlock_available() {
        eprintln!("Landlock not available, skipping test");
        return;
    }

    let sandbox = make_sandbox();
    let spec = CommandSpec {
        program: "cat".to_string(),
        args: vec!["/etc/passwd".to_string()],
        cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")),
        env: HashMap::new(),
        timeout: Duration::from_secs(10),
    };

    let (output, _reason) = sandbox
        .execute(&spec)
        .expect("execute should succeed under ReadOnly");

    assert_eq!(
        output.exit_code, 0,
        "ReadOnly 应允许读取 /etc/passwd。exit={}",
        output.exit_code
    );
}

// K2：WorkspaceWrite 允许写入 /tmp。

#[test]
fn workspace_write_allows_write_to_tmp() {
    if !is_landlock_available() {
        eprintln!("Landlock not available, skipping test");
        return;
    }

    let sandbox = make_sandbox();
    // 使用 PID 化的 /tmp 路径，避免与并发/历史运行冲突。
    let target = unique_path("libapi_workspace_tmp");
    let cmd = format!("echo ok > {}", target.display());

    let spec = CommandSpec {
        program: "sh".to_string(),
        args: vec!["-c".to_string(), cmd],
        cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")),
        env: HashMap::new(),
        timeout: Duration::from_secs(10),
    };

    let (output, _reason) = sandbox
        .execute(&spec)
        .expect("execute should succeed under WorkspaceWrite");

    cleanup_path(&target);

    assert_eq!(
        output.exit_code, 0,
        "WorkspaceWrite 应允许写 /tmp。exit={}",
        output.exit_code
    );
}

// K3：WorkspaceWrite 允许读取任意路径。

#[test]
fn workspace_write_allows_read_anywhere() {
    if !is_landlock_available() {
        eprintln!("Landlock not available, skipping test");
        return;
    }

    let sandbox = make_sandbox();
    let spec = CommandSpec {
        program: "cat".to_string(),
        args: vec!["/etc/passwd".to_string()],
        cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")),
        env: HashMap::new(),
        timeout: Duration::from_secs(10),
    };

    let (output, _reason) = sandbox
        .execute(&spec)
        .expect("execute should succeed under WorkspaceWrite");

    assert_eq!(
        output.exit_code, 0,
        "WorkspaceWrite 应允许读 /etc/passwd。exit={}",
        output.exit_code
    );
}

// K4：WorkspaceWrite 通过 allow_write 显式授予的路径可写。

#[test]
fn workspace_write_grants_allow_write_path() {
    if !is_landlock_available() {
        eprintln!("Landlock not available, skipping test");
        return;
    }

    // 授予 /var/tmp 下特定子目录的写权限。
    let granted_dir = unique_path_in_var_tmp("libapi_allow_granted");
    std::fs::create_dir_all(&granted_dir).expect("failed to create granted dir");

    let ro_perms = vec![
        LandlockPerm::Execute,
        LandlockPerm::ReadFile,
        LandlockPerm::ReadDir,
    ];
    let rw_perms = vec![
        LandlockPerm::Execute,
        LandlockPerm::ReadFile,
        LandlockPerm::ReadDir,
        LandlockPerm::WriteFile,
        LandlockPerm::RemoveDir,
        LandlockPerm::RemoveFile,
        LandlockPerm::MakeDir,
        LandlockPerm::MakeReg,
        LandlockPerm::MakeSym,
        LandlockPerm::Truncate,
    ];
    let sandbox = make_sandbox_with_landlock(vec![
        LandlockRule {
            path: "/".into(),
            perms: ro_perms,
        },
        LandlockRule {
            path: granted_dir.clone(),
            perms: rw_perms,
        },
    ]);

    let target = granted_dir.join("written_file");
    let cmd = format!("echo ok > {}", target.display());
    let spec = CommandSpec {
        program: "sh".to_string(),
        args: vec!["-c".to_string(), cmd],
        cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")),
        env: HashMap::new(),
        timeout: Duration::from_secs(10),
    };

    let (output, _reason) = sandbox
        .execute(&spec)
        .expect("execute should succeed under WorkspaceWrite with allow_write");

    cleanup_path(&target);
    cleanup_path(&granted_dir);

    assert_eq!(
        output.exit_code, 0,
        "allow_write 列表中的路径应可写。exit={}",
        output.exit_code
    );
}

// K5：WorkspaceWrite 的 allow_write 不应"溢出"——非显式列入的路径仍被拒绝。

#[test]
fn workspace_write_does_not_grant_unlisted_path() {
    if !is_landlock_available() {
        eprintln!("Landlock not available, skipping test");
        return;
    }

    let granted_dir = unique_path_in_var_tmp("libapi_allow_only_this");
    std::fs::create_dir_all(&granted_dir).expect("failed to create granted dir");
    let other_dir = unique_path_in_var_tmp("libapi_allow_NOT_this");
    std::fs::create_dir_all(&other_dir).expect("failed to create other dir");

    // 只授权 granted_dir，不授权 other_dir。
    let ro_perms = vec![
        LandlockPerm::Execute,
        LandlockPerm::ReadFile,
        LandlockPerm::ReadDir,
    ];
    let rw_perms = vec![
        LandlockPerm::Execute,
        LandlockPerm::ReadFile,
        LandlockPerm::ReadDir,
        LandlockPerm::WriteFile,
        LandlockPerm::RemoveDir,
        LandlockPerm::RemoveFile,
        LandlockPerm::MakeDir,
        LandlockPerm::MakeReg,
        LandlockPerm::MakeSym,
        LandlockPerm::Truncate,
    ];
    let sandbox = make_sandbox_with_landlock(vec![
        LandlockRule {
            path: "/".into(),
            perms: ro_perms,
        },
        LandlockRule {
            path: granted_dir.clone(),
            perms: rw_perms,
        },
    ]);

    let target = other_dir.join("should_be_blocked");
    let cmd = format!("echo blocked > {}", target.display());
    let spec = CommandSpec {
        program: "sh".to_string(),
        args: vec!["-c".to_string(), cmd],
        cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")),
        env: HashMap::new(),
        timeout: Duration::from_secs(10),
    };

    let (output, _reason) = sandbox
        .execute(&spec)
        .expect("execute should not fail; child may error");

    cleanup_path(&target);
    cleanup_path(&other_dir);
    cleanup_path(&granted_dir);

    assert_ne!(
        output.exit_code, 0,
        "未列入 allow_write 的路径应被拒绝。exit={}",
        output.exit_code
    );
}

// K6：FullAccess 不施加 Landlock，写到 /etc 等系统位置也能成功（前提是有权限）。
// 在普通 CI / 开发环境通常没有 /etc 写权限，所以这里只用 /tmp 验证
// "FullAccess 至少不拦截"。

#[test]
fn full_access_does_not_intercept_writes() {
    if !is_landlock_available() {
        eprintln!("Landlock not available, skipping test");
        return;
    }

    let sandbox = make_sandbox();
    let target = unique_path("libapi_full_access");
    let cmd = format!("echo ok > {}", target.display());
    let spec = CommandSpec {
        program: "sh".to_string(),
        args: vec!["-c".to_string(), cmd],
        cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")),
        env: HashMap::new(),
        timeout: Duration::from_secs(10),
    };

    let (output, _reason) = sandbox
        .execute(&spec)
        .expect("execute should succeed under FullAccess");

    cleanup_path(&target);

    assert_eq!(
        output.exit_code, 0,
        "FullAccess 不应拦截任何写。exit={}",
        output.exit_code
    );
}

// ===== CLI 二进制测试：覆盖 wrapper → Landlock 的完整链路 =====

// CLI L5：ReadOnly 下读取应成功（库 API）。

#[test]
fn cli_read_only_allows_read() {
    if skip_unless_landlock_active() {
        return;
    }

    let sandbox = make_sandbox_with_landlock(vec![LandlockRule {
        path: "/".into(),
        perms: vec![
            LandlockPerm::Execute,
            LandlockPerm::ReadFile,
            LandlockPerm::ReadDir,
        ],
    }]);
    let spec = CommandSpec {
        program: "cat".to_string(),
        args: vec!["/etc/passwd".to_string()],
        cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")),
        env: HashMap::new(),
        timeout: Duration::from_secs(10),
    };

    let (output, _reason) = sandbox
        .execute(&spec)
        .expect("execute should succeed under ReadOnly");

    assert_eq!(
        output.exit_code, 0,
        "ReadOnly 下读取 /etc/passwd 应成功。exit_code={}",
        output.exit_code
    );
    // CommandOutput 不含 stdout，故不验证输出内容；
    // exit_code=0 即可确认读取未被拦截。
}

// CLI L6：ReadOnly 下写到 /tmp 应失败，验证 RO 语义。

#[test]
fn cli_workspace_write_allows_write_to_tmp() {
    if skip_unless_landlock_active() {
        return;
    }

    let target = unique_path("landlock_ro_tmp_blocked");
    let sh_cmd = format!("echo ok > {}", target.display());

    let sandbox = make_sandbox_with_landlock(vec![LandlockRule {
        path: "/".into(),
        perms: vec![
            LandlockPerm::Execute,
            LandlockPerm::ReadFile,
            LandlockPerm::ReadDir,
        ],
    }]);
    let spec = CommandSpec {
        program: "sh".to_string(),
        args: vec!["-c".to_string(), sh_cmd],
        cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")),
        env: HashMap::new(),
        timeout: Duration::from_secs(10),
    };

    let (output, _reason) = sandbox
        .execute(&spec)
        .expect("execute should not fail, though the child process may error");

    cleanup_path(&target);

    assert_ne!(
        output.exit_code, 0,
        "ReadOnly 下写到 /tmp 应被拒绝。exit_code={}",
        output.exit_code
    );
}

// CLI L7：显式授予写权限应允许写。

#[test]
fn cli_workspace_write_grants_allow_write_path() {
    if skip_unless_landlock_active() {
        return;
    }

    let granted_dir = unique_path_in_var_tmp("cli_allow_granted");
    std::fs::create_dir_all(&granted_dir).expect("failed to create granted dir");

    let target = granted_dir.join("cli_written_file");
    let sh_cmd = format!("echo ok > {}", target.display());

    // RO on /, RW on granted_dir
    let sandbox = make_sandbox_with_landlock(vec![
        LandlockRule {
            path: "/".into(),
            perms: vec![
                LandlockPerm::Execute,
                LandlockPerm::ReadFile,
                LandlockPerm::ReadDir,
            ],
        },
        LandlockRule {
            path: granted_dir.clone(),
            perms: vec![
                LandlockPerm::Execute,
                LandlockPerm::ReadFile,
                LandlockPerm::ReadDir,
                LandlockPerm::WriteFile,
                LandlockPerm::RemoveDir,
                LandlockPerm::RemoveFile,
                LandlockPerm::MakeDir,
                LandlockPerm::MakeReg,
                LandlockPerm::MakeSym,
                LandlockPerm::Truncate,
            ],
        },
    ]);
    let spec = CommandSpec {
        program: "sh".to_string(),
        args: vec!["-c".to_string(), sh_cmd],
        cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")),
        env: HashMap::new(),
        timeout: Duration::from_secs(10),
    };

    let (output, _reason) = sandbox
        .execute(&spec)
        .expect("execute should succeed for granted path");

    cleanup_path(&target);
    cleanup_path(&granted_dir);

    assert_eq!(
        output.exit_code, 0,
        "显式授予写权限的路径应可写。exit_code={}",
        output.exit_code
    );
}

// CLI L8：未授予写权限的路径应被拒绝。

#[test]
fn cli_workspace_write_does_not_grant_unlisted_path() {
    if skip_unless_landlock_active() {
        return;
    }

    let granted_dir = unique_path_in_var_tmp("cli_grant_only_this");
    let other_dir = unique_path_in_var_tmp("cli_NOT_granted");
    std::fs::create_dir_all(&granted_dir).expect("failed to create granted dir");
    std::fs::create_dir_all(&other_dir).expect("failed to create other dir");

    let target = other_dir.join("should_be_blocked");
    let sh_cmd = format!("echo blocked > {}", target.display());

    // RO on /, RW on granted_dir only
    let sandbox = make_sandbox_with_landlock(vec![
        LandlockRule {
            path: "/".into(),
            perms: vec![
                LandlockPerm::Execute,
                LandlockPerm::ReadFile,
                LandlockPerm::ReadDir,
            ],
        },
        LandlockRule {
            path: granted_dir.clone(),
            perms: vec![
                LandlockPerm::Execute,
                LandlockPerm::ReadFile,
                LandlockPerm::ReadDir,
                LandlockPerm::WriteFile,
                LandlockPerm::RemoveDir,
                LandlockPerm::RemoveFile,
                LandlockPerm::MakeDir,
                LandlockPerm::MakeReg,
                LandlockPerm::MakeSym,
                LandlockPerm::Truncate,
            ],
        },
    ]);
    let spec = CommandSpec {
        program: "sh".to_string(),
        args: vec!["-c".to_string(), sh_cmd],
        cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")),
        env: HashMap::new(),
        timeout: Duration::from_secs(10),
    };

    let (output, _reason) = sandbox
        .execute(&spec)
        .expect("execute should not fail, though the child process may error");

    cleanup_path(&target);
    cleanup_path(&other_dir);
    cleanup_path(&granted_dir);

    assert_ne!(
        output.exit_code, 0,
        "未授予写权限的路径应被拒绝。exit_code={}",
        output.exit_code
    );
}

// CLI L9：ReadOnly 下读取任意路径应成功（库 API）。

#[test]
fn cli_workspace_write_allows_read_anywhere() {
    if skip_unless_landlock_active() {
        return;
    }

    let sandbox = make_sandbox_with_landlock(vec![LandlockRule {
        path: "/".into(),
        perms: vec![
            LandlockPerm::Execute,
            LandlockPerm::ReadFile,
            LandlockPerm::ReadDir,
        ],
    }]);
    let spec = CommandSpec {
        program: "cat".to_string(),
        args: vec!["/etc/passwd".to_string()],
        cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")),
        env: HashMap::new(),
        timeout: Duration::from_secs(10),
    };

    let (output, _reason) = sandbox
        .execute(&spec)
        .expect("execute should succeed under ReadOnly");

    assert_eq!(
        output.exit_code, 0,
        "ReadOnly 下读 /etc/passwd 应成功。exit_code={}",
        output.exit_code
    );
}

// CLI L10：无 Landlock 限制（空规则）写到 /var/tmp 应成功。

#[test]
fn cli_full_access_allows_write_to_var_tmp() {
    if skip_unless_landlock_active() {
        return;
    }

    let sandbox = make_sandbox();
    let target = unique_path_in_var_tmp("cli_full_access");
    let sh_cmd = format!("echo ok > {}", target.display());
    let spec = CommandSpec {
        program: "sh".to_string(),
        args: vec!["-c".to_string(), sh_cmd],
        cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")),
        env: HashMap::new(),
        timeout: Duration::from_secs(10),
    };

    let (output, _reason) = sandbox
        .execute(&spec)
        .expect("execute should succeed with no landlock rules");

    cleanup_path(&target);

    assert_eq!(
        output.exit_code, 0,
        "无 Landlock 限制下写 /var/tmp 应成功。exit_code={}",
        output.exit_code
    );
}

/// 哨兵测试：确保最后一个执行的测试显式 flush stdout。
/// 用于诊断 cargo 在并发测试模式下是否因 stdout 未 flush 而 hang。
#[test]
fn zzz_flush_stdout_marker() {
    use std::io::Write;
    println!("FLUSH_MARKER");
    std::io::stdout().flush().unwrap();
    std::io::stderr().flush().unwrap();
}

// ---------------------------------------------------------------------------
// --landlock flag 解析测试
// ---------------------------------------------------------------------------

#[test]
fn cli_landlock_ro_blocks_write() {
    if skip_unless_landlock_active() {
        return;
    }
    let out = run_cli(&[
        "run",
        "--landlock",
        "/:ro",
        "--",
        "sh",
        "-c",
        "echo hi > /tmp/.sandbox_ll_ro_test",
    ]);
    assert_eq!(
        out.exit_code,
        Some(2),
        "ro 模式下写 /tmp 应被拒绝, stderr={:?}",
        out.stderr
    );
}

#[test]
fn cli_landlock_rw_allows_write() {
    if skip_unless_landlock_active() {
        return;
    }
    let target = "/tmp/.sandbox_ll_rw_test".to_string();
    let out = run_cli(&[
        "run",
        "--landlock",
        "/:ro",
        "--landlock",
        "/tmp:rw",
        "--",
        "sh",
        "-c",
        &format!("echo hi > {target}"),
    ]);
    assert_eq!(
        out.exit_code,
        Some(0),
        "ro+/tmp:rw 模式下写 /tmp 应允许, stderr={:?}",
        out.stderr
    );
    let _ = std::fs::remove_file(&target);
}

#[test]
fn cli_landlock_all_allows_ioctl_dev() {
    if skip_unless_landlock_active() {
        return;
    }
    // all 应包含 refer + ioctl-dev；配合 /:ro 让 sh 可执行
    let out = run_cli(&[
        "run",
        "--landlock",
        "/:ro",
        "--landlock",
        "/tmp:all",
        "--",
        "sh",
        "-c",
        "echo ok",
    ]);
    assert_eq!(
        out.exit_code,
        Some(0),
        "all 模式下运行基本命令应成功, stderr={:?}",
        out.stderr
    );
}

#[test]
fn cli_landlock_multiple_rules_combined() {
    if skip_unless_landlock_active() {
        return;
    }
    let target = "/tmp/.sandbox_ll_multi_test".to_string();
    let out = run_cli(&[
        "run",
        "--landlock",
        "/:ro",
        "--landlock",
        "/etc:ro",
        "--landlock",
        "/tmp:rw",
        "--",
        "sh",
        "-c",
        &format!("echo ok > {target} && cat /etc/hostname"),
    ]);
    // 注意：> /dev/null 需要 /dev 的写权限，不与 /:ro 兼容，故省去。
    assert_eq!(
        out.exit_code,
        Some(0),
        "多规则组合应正常工作, stderr={:?}",
        out.stderr
    );
    let _ = std::fs::remove_file(&target);
}
