//! Mount namespace 集成测试。
//!
//! 验证：
//! - M1: `--tmpfs /target` 后目标可写，初始为空
//! - M2: `--bind /src /dst` 后可见 src 内容
//! - M3: `--ro-bind /src /dst` 后写入被拒绝
//! - M4: 仅 `--unshare-mnt` 无 mount ops，进程正常运行
//! - M5: 多个 mount 操作全部生效
//! - M6: `--bind` + `--landlock` 组合正常
//! - M7: mount ops 非空时自动启用 mount ns
//! - M8: bind 不存在路径 → exit 非零
//!
//! # 重要
//!
//! 所有 mount 操作需要 `--unshare-user`，因为非 root 下 mount ns 需要
//! user ns 提供 CAP_SYS_ADMIN。

#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

use sandbox_runtime::linux::mount;
use sandbox_runtime::linux::namespaces;

// ---------------------------------------------------------------------------
// 计数器：生成集成测试内的唯一路径
// ---------------------------------------------------------------------------

/// 为每次测试生成一个唯一序号（同一测试文件内，各 test 函数共用同一个进程，
/// 因此用 PID 不够唯一；用原子计数器确保无冲突）。
static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

fn unique_id() -> u32 {
    TEST_COUNTER.fetch_add(1, Ordering::SeqCst)
}

/// 在 `/tmp` 下创建一个唯一的临时目录并返回路径。
///
/// 调用方负责清理（`remove_dir_all`）。
fn create_temp_dir(label: &str) -> PathBuf {
    let id = unique_id();
    let path = PathBuf::from(format!("/tmp/sandbox-mount-{label}-{id}"));
    std::fs::create_dir_all(&path).expect("create temp dir");
    path
}

// ---------------------------------------------------------------------------
// 基础辅助
// ---------------------------------------------------------------------------

/// 由 Cargo 在集成测试中自动注入的二进制绝对路径。
fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_sandbox-runtime")
}

/// 子进程结果。
#[derive(Debug)]
struct RunOutput {
    exit_code: Option<i32>,
    stdout: String,
    #[allow(dead_code)]
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

fn skip_if_no_mnt_ns() -> bool {
    if !mount::is_mount_namespace_available() {
        eprintln!("mount namespace not available, skipping test");
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// M1: --tmpfs /target 后目标可写，初始为空
// ---------------------------------------------------------------------------

#[test]
fn mount_tmpfs_works() {
    if skip_if_no_user_ns() || skip_if_no_mnt_ns() {
        return;
    }

    let tmpdir = create_temp_dir("tmpfs");
    let tmpdir_str = tmpdir.to_str().expect("valid utf-8 path");

    // 先确认 tmpfs 初始为空
    let out = run_cli(&[
        "run",
        "--unshare-user",
        "--unshare-mnt",
        "--tmpfs",
        tmpdir_str,
        "--",
        "ls",
        tmpdir_str,
    ]);
    assert_eq!(
        out.exit_code,
        Some(0),
        "tmpfs ls should succeed: {:?}",
        out
    );
    assert!(
        out.stdout.trim().is_empty(),
        "tmpfs should be initially empty, got: {:?}",
        out.stdout
    );

    // 再确认 tmpfs 可写
    let out = run_cli(&[
        "run",
        "--unshare-user",
        "--unshare-mnt",
        "--tmpfs",
        tmpdir_str,
        "--",
        "sh",
        "-c",
        &format!("touch {tmpdir_str}/hello && ls {tmpdir_str}"),
    ]);
    assert_eq!(
        out.exit_code,
        Some(0),
        "tmpfs write should succeed: {:?}",
        out
    );
    assert_eq!(
        out.stdout.trim(),
        "hello",
        "tmpfs should contain 'hello' after touch"
    );

    // 清理
    let _ = std::fs::remove_dir_all(&tmpdir);
}

// ---------------------------------------------------------------------------
// M2: --bind /src /dst 后可见 src 内容
// ---------------------------------------------------------------------------

#[test]
fn mount_bind_visible() {
    if skip_if_no_user_ns() || skip_if_no_mnt_ns() {
        return;
    }

    let src = create_temp_dir("bind-src");
    let dst = create_temp_dir("bind-dst");

    // 在 src 中创建一个测试文件
    std::fs::write(src.join("data.txt"), "bind content").expect("write test file");

    let src_str = src.to_str().expect("utf-8 src");
    let dst_str = dst.to_str().expect("utf-8 dst");

    let out = run_cli(&[
        "run",
        "--unshare-user",
        "--unshare-mnt",
        "--bind",
        src_str,
        dst_str,
        "--",
        "cat",
        &format!("{dst_str}/data.txt"),
    ]);
    assert_eq!(
        out.exit_code,
        Some(0),
        "bind mount should succeed: {:?}",
        out
    );
    assert_eq!(
        out.stdout.trim(),
        "bind content",
        "bind target should show source file content"
    );

    // 清理
    let _ = std::fs::remove_dir_all(&src);
    let _ = std::fs::remove_dir_all(&dst);
}

// ---------------------------------------------------------------------------
// M3: --ro-bind /src /dst 后写入被拒绝
// ---------------------------------------------------------------------------

#[test]
fn mount_ro_bind_readonly() {
    if skip_if_no_user_ns() || skip_if_no_mnt_ns() {
        return;
    }

    let src = create_temp_dir("ro-src");
    let dst = create_temp_dir("ro-dst");

    // 在 src 中创建一个测试文件
    std::fs::write(src.join("readme.txt"), "read-only content").expect("write test file");

    let src_str = src.to_str().expect("utf-8 src");
    let dst_str = dst.to_str().expect("utf-8 dst");

    // 验证读取成功（ro-bind 允许读取）
    let out = run_cli(&[
        "run",
        "--unshare-user",
        "--unshare-mnt",
        "--ro-bind",
        src_str,
        dst_str,
        "--",
        "cat",
        &format!("{dst_str}/readme.txt"),
    ]);
    assert_eq!(
        out.exit_code,
        Some(0),
        "ro-bind read should succeed: {:?}",
        out
    );
    assert_eq!(
        out.stdout.trim(),
        "read-only content",
        "ro-bind target should show source file content"
    );

    // 验证写入被拒绝（ro-bind 禁止写入）
    let out = run_cli(&[
        "run",
        "--unshare-user",
        "--unshare-mnt",
        "--ro-bind",
        src_str,
        dst_str,
        "--",
        "touch",
        &format!("{dst_str}/newfile"),
    ]);
    assert!(
        out.exit_code != Some(0),
        "ro-bind write should be denied, got exit={:?}: {:?}",
        out.exit_code,
        out
    );

    // 清理
    let _ = std::fs::remove_dir_all(&src);
    let _ = std::fs::remove_dir_all(&dst);
}

// ---------------------------------------------------------------------------
// M4: 仅 --unshare-mnt 无 mount ops，进程正常运行
// ---------------------------------------------------------------------------

#[test]
fn unshare_mnt_only() {
    if skip_if_no_user_ns() || skip_if_no_mnt_ns() {
        return;
    }

    let out = run_cli(&["run", "--unshare-user", "--unshare-mnt", "--", "true"]);
    assert_eq!(
        out.exit_code,
        Some(0),
        "unshare-mnt alone should succeed: {:?}",
        out
    );
}

// ---------------------------------------------------------------------------
// M5: 多个 mount 操作全部生效
// ---------------------------------------------------------------------------

#[test]
fn mount_multiple_ops() {
    if skip_if_no_user_ns() || skip_if_no_mnt_ns() {
        return;
    }

    let src1 = create_temp_dir("multi-src1");
    let dst1 = create_temp_dir("multi-dst1");
    let tmpdir = create_temp_dir("multi-tmpfs");

    std::fs::write(src1.join("a.txt"), "file-a").expect("write file a");
    let src1_str = src1.to_str().expect("utf-8");
    let dst1_str = dst1.to_str().expect("utf-8");
    let tmpdir_str = tmpdir.to_str().expect("utf-8");

    // 同时使用 --bind 和 --tmpfs，验证两者均生效
    let out = run_cli(&[
        "run",
        "--unshare-user",
        "--unshare-mnt",
        "--bind",
        src1_str,
        dst1_str,
        "--tmpfs",
        tmpdir_str,
        "--",
        "sh",
        "-c",
        &format!(
            "cat {dst1_str}/a.txt && touch {tmpdir_str}/tmpfile && ls {tmpdir_str}"
        ),
    ]);
    assert_eq!(
        out.exit_code,
        Some(0),
        "multiple mount ops should succeed: {:?}",
        out
    );

    let lines: Vec<&str> = out.stdout.lines().map(|l| l.trim()).collect();
    assert!(
        lines.contains(&"file-a"),
        "bind mount should expose src file: {:?}",
        lines
    );
    assert!(
        lines.contains(&"tmpfile"),
        "tmpfs should be writable: {:?}",
        lines
    );

    // 清理
    let _ = std::fs::remove_dir_all(&src1);
    let _ = std::fs::remove_dir_all(&dst1);
    let _ = std::fs::remove_dir_all(&tmpdir);
}

// ---------------------------------------------------------------------------
// M6: --bind + --landlock 组合正常
// ---------------------------------------------------------------------------

#[test]
fn mount_with_landlock() {
    if skip_if_no_user_ns() || skip_if_no_mnt_ns() {
        return;
    }

    let src = create_temp_dir("ll-src");
    let dst = create_temp_dir("ll-dst");

    std::fs::write(src.join("tool"), "binary").expect("write test file");
    let src_str = src.to_str().expect("utf-8");
    let dst_str = dst.to_str().expect("utf-8");

    // --bind 提供文件可见性，--landlock /:ro 限制根目录为只读。
    // 但由于 bind mount 发生在 landlock 限制之前，且 landlock 规则
    // 作用于 mount namespace 内的 vfs 挂载点，bind mount 创建的新
    // 挂载点也受 landlock 保护。
    //
    // 这里只验证组合不崩溃 + bind mount 仍有效：
    let out = run_cli(&[
        "run",
        "--unshare-user",
        "--unshare-mnt",
        "--landlock",
        "/:ro",
        "--bind",
        src_str,
        dst_str,
        "--",
        "cat",
        &format!("{dst_str}/tool"),
    ]);
    assert_eq!(
        out.exit_code,
        Some(0),
        "bind + landlock should coexist: {:?}",
        out
    );
    assert_eq!(
        out.stdout.trim(),
        "binary",
        "bind target should show source file under landlock"
    );

    // 清理
    let _ = std::fs::remove_dir_all(&src);
    let _ = std::fs::remove_dir_all(&dst);
}

// ---------------------------------------------------------------------------
// M7: mount ops 非空时自动启用 mount ns
// ---------------------------------------------------------------------------

#[test]
fn mount_auto_ns() {
    if skip_if_no_user_ns() || skip_if_no_mnt_ns() {
        return;
    }

    let src = create_temp_dir("auto-src");
    let dst = create_temp_dir("auto-dst");

    std::fs::write(src.join("auto.txt"), "auto-ns").expect("write test file");
    let src_str = src.to_str().expect("utf-8");
    let dst_str = dst.to_str().expect("utf-8");

    // 不传 --unshare-mnt，仅靠 --bind 自动启用 mount ns
    let out = run_cli(&[
        "run",
        "--unshare-user",
        "--bind",
        src_str,
        dst_str,
        "--",
        "cat",
        &format!("{dst_str}/auto.txt"),
    ]);
    assert_eq!(
        out.exit_code,
        Some(0),
        "auto ns from --bind should work: {:?}",
        out
    );
    assert_eq!(
        out.stdout.trim(),
        "auto-ns",
        "auto ns bind should expose source content"
    );

    // 清理
    let _ = std::fs::remove_dir_all(&src);
    let _ = std::fs::remove_dir_all(&dst);
}

// ---------------------------------------------------------------------------
// M8: bind 不存在路径 → exit 非零
// ---------------------------------------------------------------------------

#[test]
fn mount_failure_exit() {
    if skip_if_no_user_ns() || skip_if_no_mnt_ns() {
        return;
    }

    let dst = create_temp_dir("fail-dst");
    let dst_str = dst.to_str().expect("utf-8");

    // bind 不存在的源路径 → mount(2) 失败 → 子进程 exit(1)
    let out = run_cli(&[
        "run",
        "--unshare-user",
        "--unshare-mnt",
        "--bind",
        "/tmp/sandbox-nonexistent-source-this-does-not-exist",
        dst_str,
        "--",
        "true",
    ]);
    assert!(
        out.exit_code != Some(0),
        "bind nonexistent source should fail, got exit={:?}",
        out.exit_code
    );

    // 清理
    let _ = std::fs::remove_dir_all(&dst);
}
