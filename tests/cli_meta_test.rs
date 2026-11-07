//! 与后端无关的 CLI 表面测试（`--version` / `--help` / 子命令清单）。
//!
//! **刻意不设 `#![cfg(target_os = ...)]`**：这些是 CLI 元信息，两个平台行为应一致，
//! 因此也应当在两个平台的 CI 上都跑。需要后端语义的测试见 `tests/macos_test.rs`
//! （macOS 库 API）与 `tests/macos_cli_e2e_test.rs`（macOS CLI 端到端）。

use std::process::Command;

/// Cargo 注入的 CLI 二进制绝对路径。
fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_seabox")
}

/// `--version` / `-V` 输出含 crate 版本号。
///
/// 这条防的是「clap 的 `#[command(version)]` 被误删」：删掉之后 `--version`
/// 会变成 `error: unexpected argument '--version' found`，而其余全部测试仍然全绿。
/// 发布 crate 时尤其致命——用户第一件事就是 `seabox --version`。
#[test]
fn version_flag_matches_crate_version() {
    let expected = env!("CARGO_PKG_VERSION");

    for flag in ["--version", "-V"] {
        let out = Command::new(bin())
            .arg(flag)
            .output()
            .expect("spawn seabox binary");

        assert!(
            out.status.success(),
            "`{flag}` 应正常退出，实际状态: {:?}",
            out.status
        );

        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains(expected),
            "`{flag}` 输出应含 crate 版本 {expected:?}，实际: {stdout:?}"
        );
    }
}

/// `--help` 正常退出并列出 `run` 与 `check` 子命令。
#[test]
fn help_lists_subcommands() {
    let out = Command::new(bin()).arg("--help").output().expect("spawn");

    assert!(out.status.success(), "`--help` 应正常退出");
    let stdout = String::from_utf8_lossy(&out.stdout);
    for sub in ["run", "check"] {
        assert!(
            stdout.contains(sub),
            "`--help` 应列出子命令 {sub:?}，实际: {stdout:?}"
        );
    }
}

/// 无子命令时非零退出且给出用法（避免静默成功）。
#[test]
fn no_subcommand_is_an_error() {
    let out = Command::new(bin()).output().expect("spawn seabox binary");

    assert!(
        !out.status.success(),
        "无子命令应当非零退出，而不是静默成功"
    );
}
