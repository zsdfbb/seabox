//! LinuxSandbox::classify_exit() 的集成测试。
//!
//! 覆盖所有边界情况：退出码 0、SIGSYS 信号（31, 159）、
//! stderr 中的 Landlock 拒绝模式、seccomp 拒绝模式以及普通程序退出。

// 本文件仅在 Linux 下编译，因为它依赖
// `sandbox_runtime::linux::LinuxSandbox`。
#![cfg(target_os = "linux")]

use sandbox_runtime::config::SandboxConfig;
use sandbox_runtime::linux::LinuxSandbox;
use sandbox_runtime::{DenyMechanism, ExitReason, Sandbox};

/// 辅助函数：创建一个默认配置的 LinuxSandbox 用于 classify_exit 测试。
fn make_sandbox() -> LinuxSandbox {
    LinuxSandbox {
        config: SandboxConfig::default(),
    }
}

// ---------------------------------------------------------------------------
// exit_code = 0 → Ok（与 stderr 内容无关）
// ---------------------------------------------------------------------------

#[test]
fn exit_zero_ok() {
    let sandbox = make_sandbox();
    let result = sandbox.classify_exit(0, "some error text");
    assert_eq!(result, ExitReason::Ok);
}

// ---------------------------------------------------------------------------
// SIGSYS 退出码 → Denied(Seccomp)
// ---------------------------------------------------------------------------

#[test]
fn exit_31_seccomp_direct() {
    let sandbox = make_sandbox();
    let result = sandbox.classify_exit(31, "");
    assert_eq!(
        result,
        ExitReason::Denied {
            mechanism: DenyMechanism::Seccomp,
            message: "Blocked by seccomp filter (SIGSYS)".into(),
        }
    );
}

#[test]
fn exit_159_seccomp_shell() {
    let sandbox = make_sandbox();
    let result = sandbox.classify_exit(159, "");
    assert_eq!(
        result,
        ExitReason::Denied {
            mechanism: DenyMechanism::Seccomp,
            message: "Blocked by seccomp filter (SIGSYS)".into(),
        }
    );
}

// ---------------------------------------------------------------------------
// stderr 中的 Landlock 拒绝模式（exit_code = 1）
// ---------------------------------------------------------------------------

#[test]
fn stderr_operation_not_permitted() {
    let sandbox = make_sandbox();
    let result = sandbox.classify_exit(1, "Operation not permitted");
    assert!(result.is_denied());
    assert_eq!(
        result,
        ExitReason::Denied {
            mechanism: DenyMechanism::Landlock,
            message: "Landlock blocked access: Operation not permitted".into(),
        }
    );
}

#[test]
fn stderr_permission_denied() {
    let sandbox = make_sandbox();
    let result = sandbox.classify_exit(1, "Permission denied");
    assert!(result.is_denied());
    assert_eq!(
        result,
        ExitReason::Denied {
            mechanism: DenyMechanism::Landlock,
            message: "Landlock blocked access: Permission denied".into(),
        }
    );
}

// ---------------------------------------------------------------------------
// stderr 中的 seccomp 拒绝模式（exit_code = 1）
// ---------------------------------------------------------------------------

#[test]
fn stderr_bad_system_call() {
    let sandbox = make_sandbox();
    let result = sandbox.classify_exit(1, "Bad system call (core dumped)");
    assert_eq!(
        result,
        ExitReason::Denied {
            mechanism: DenyMechanism::Seccomp,
            message: "Seccomp blocked syscall: Bad system call (core dumped)".into(),
        }
    );
}

#[test]
fn stderr_sigsys() {
    let sandbox = make_sandbox();
    let result = sandbox.classify_exit(1, "SIGSYS from seccomp");
    assert_eq!(
        result,
        ExitReason::Denied {
            mechanism: DenyMechanism::Seccomp,
            message: "Seccomp blocked syscall: SIGSYS from seccomp".into(),
        }
    );
}

#[test]
fn stderr_seccomp() {
    let sandbox = make_sandbox();
    let result = sandbox.classify_exit(1, "seccomp filter killed process");
    assert_eq!(
        result,
        ExitReason::Denied {
            mechanism: DenyMechanism::Seccomp,
            message: "Seccomp blocked syscall: seccomp filter killed process".into(),
        }
    );
}

// ---------------------------------------------------------------------------
// 没有匹配 → Program(exit_code)
// ---------------------------------------------------------------------------

#[test]
fn exit_1_no_match_program() {
    let sandbox = make_sandbox();
    let result = sandbox.classify_exit(1, "some unrelated error message");
    assert_eq!(result, ExitReason::Program(1));
}

#[test]
fn exit_139_sigsegv() {
    let sandbox = make_sandbox();
    let result = sandbox.classify_exit(139, "");
    assert_eq!(result, ExitReason::Program(139));
}