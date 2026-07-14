//! Integration tests for Landlock filesystem ACL enforcement.
//!
//! These tests require Linux 5.13+ with Landlock compiled in
//! (`CONFIG_SECURITY_LANDLOCK=y`, `lsm=landlock`). On kernels without
//! Landlock support the tests skip themselves at runtime via
//! `sandbox_runtime::linux::landlock::is_available()`.
//!
//! Test cases:
//! - WorkspaceWrite policy: write to workspace dir succeeds.
//! - FullAccess policy: no Landlock restrictions, write succeeds.
//! - ReadOnly policy: write to temp dir is blocked by Landlock.

// This file only compiles on Linux because it depends on
// `sandbox_runtime::linux::LinuxSandbox` and `sandbox_runtime::linux::landlock`.
#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::time::Duration;

use sandbox_runtime::config::SandboxConfig;
use sandbox_runtime::linux::LinuxSandbox;
use sandbox_runtime::{CommandSpec, FsPolicy, Sandbox};

/// Check whether Landlock is available on the running kernel.
fn is_landlock_available() -> bool {
    sandbox_runtime::linux::landlock::is_available()
}

/// Helper: create a default-configured LinuxSandbox.
fn make_sandbox() -> LinuxSandbox {
    LinuxSandbox {
        config: SandboxConfig::default(),
    }
}

// ---------------------------------------------------------------------------
// WorkspaceWrite: write to workspace dir should succeed
// ---------------------------------------------------------------------------

#[test]
fn workspace_write_allows_write() {
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
        sandbox_policy: FsPolicy::WorkspaceWrite,
    };

    let output = sandbox
        .execute(&spec)
        .expect("execute should succeed under WorkspaceWrite");

    assert_eq!(
        output.exit_code, 0,
        "write should succeed under WorkspaceWrite, exit_code={}, stderr={}",
        output.exit_code, output.stderr
    );
    assert!(
        dir_path.join("test.txt").exists(),
        "file should be created under WorkspaceWrite"
    );
}

// ---------------------------------------------------------------------------
// FullAccess: no Landlock restrictions, write should succeed
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
        sandbox_policy: FsPolicy::FullAccess,
    };

    let output = sandbox
        .execute(&spec)
        .expect("execute should succeed under FullAccess");

    assert_eq!(
        output.exit_code, 0,
        "write should succeed under FullAccess, exit_code={}, stderr={}",
        output.exit_code, output.stderr
    );
    assert!(
        dir_path.join("test.txt").exists(),
        "file should be created under FullAccess"
    );
}

// ---------------------------------------------------------------------------
// ReadOnly: write to temp dir should be blocked by Landlock
// ---------------------------------------------------------------------------

#[test]
fn read_only_blocks_write() {
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
        sandbox_policy: FsPolicy::ReadOnly,
    };

    let output = sandbox
        .execute(&spec)
        .expect("execute should not fail, though the child process may error");

    assert_ne!(
        output.exit_code, 0,
        "write should fail under ReadOnly, exit_code={}, stderr={}",
        output.exit_code, output.stderr
    );
    assert!(
        !dir_path.join("test.txt").exists(),
        "file should NOT be created under ReadOnly"
    );
}
