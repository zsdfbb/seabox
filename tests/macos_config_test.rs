//! macOS 配置面的 CLI 映射与双向硬错误（合同 N9 / N10 / H1-H3）。
//!
//! # 数字来源
//!
//! 设计稿与执行计划里写「13 个 `--mac-*` flag」，实际落地是 **12 个**
//! （`--mac-workspace` 是后期补的字段，早期文档的计数没同步）。
//! 本文件的 12 个 flag 清单直接取自 `src/cli.rs::Cli::Run` 的实际字段，
//! 并用 [`mac_flag_count_is_twelve`] 反向核对数量：将来若新增/删除 flag，
//! 计数断言会立刻失败，提醒同步 [`MAC_FLAG_ARGS`]。
//!
//! # 三层验证（与平台的对应关系）
//!
//! - **组 1（全平台）**：clap 层 12 个 flag 未被 `#[cfg]` 门控、且真的进了
//!   `ArgMatches`（`ValueSource::CommandLine` = 值来自命令行，而非默认值）；
//!   取值解析的硬错误路径；以及 `MacOsConfig` 上 12 个同名 `with_mac_*`
//!   的存在性——后者是编译期验证，方法被删就编不过。
//! - **组 2（`#[cfg(target_os = "macos")]`）**：走 [`seabox::cli::config_from_flag_args`]
//!   ——与二进制完全同一条 `preprocess → clap → parse_run` 管线——逐 flag
//!   断言落到 `MacOsConfig` 的具体字段（N9 主体）；外加 H1 与 N10 扩展。
//! - **组 3（`#[cfg(target_os = "linux")]`）**：H2 / H3，12 个 flag 逐一必须 bail。
//!
//! # 为什么 Linux 上不做「flag → `MacOsConfig` 字段」的断言
//!
//! `parse_run` 的平台互斥检查在 Linux 上会直接 bail（这正是 H2），
//! 所以字段级断言在 Linux 上物理不可达。Linux 侧的映射保证改由
//! 「12 个 flag 全部触发 `--mac-* options are macOS-only`」间接覆盖：
//! 该 bail 的前置条件是 `macos.is_configured() == true`——某个 flag 若没被
//! 映射进 `MacOsConfig`，它在 Linux 上就不会 bail，测试随即失败。
//!
//! 本文件不写工程目录、不 spawn 沙箱子进程（组 1 的解析错误用例与组 2/3
//! 只会在 `parse_run` 阶段退出，永远不会到达执行侧）。

use std::path::PathBuf;

use clap::parser::ValueSource;
use clap::CommandFactory;

use seabox::cli::Cli;
use seabox::config::SandboxConfig;
use seabox::macos::config::{MacNetConfig, MacOsConfig, MacPreset, MacReadMode, NetAccess};

/// 12 个 `--mac-*` flag 各自的最小参数组合（N9 清单）。
///
/// 顺序即 `src/cli.rs::Cli::Run` 中字段的声明顺序，便于人工比对。
/// 路径一律落在 `/tmp` 下且**不需要存在**：本轮所有测试都不到达
/// `resolve()` 的 `canonicalize`（见 `src/macos/sbpl.rs` 的 `norm()` 文档）。
const MAC_FLAG_ARGS: [(&str, &[&str]); 12] = [
    ("--mac-preset", &["--mac-preset", "read-only"]),
    ("--mac-write", &["--mac-write", "/tmp/seabox-mac-write"]),
    (
        "--mac-deny-write",
        &["--mac-deny-write", "/tmp/seabox-mac-deny-write"],
    ),
    (
        "--mac-workspace",
        &["--mac-workspace", "/tmp/seabox-mac-workspace"],
    ),
    ("--mac-read", &["--mac-read", "/tmp/seabox-mac-read"]),
    ("--mac-read-all", &["--mac-read-all"]),
    (
        "--mac-deny-read",
        &["--mac-deny-read", "/tmp/seabox-mac-deny-read"],
    ),
    ("--mac-no-credential-deny", &["--mac-no-credential-deny"]),
    ("--mac-no-git-write", &["--mac-no-git-write"]),
    ("--mac-no-tmp-writable", &["--mac-no-tmp-writable"]),
    ("--mac-net", &["--mac-net", "443,80"]),
    ("--mac-net-inbound", &["--mac-net-inbound"]),
];

/// `seabox` 二进制路径（`[[bin]] required-features = ["cli"]`，默认特性下存在）。
fn seabox() -> &'static str {
    env!("CARGO_BIN_EXE_seabox")
}

/// 用 clap 解析一段 `run` 参数，返回 `run` 子命令的 `ArgMatches`。
///
/// 只跑 clap 层，不跑 `parse_run`——因此全平台可用（不受平台互斥 bail 影响）。
fn run_matches(args: &[&str]) -> clap::ArgMatches {
    let mut argv: Vec<&str> = vec!["seabox", "run"];
    argv.extend_from_slice(args);
    argv.extend_from_slice(&["--", "true"]);
    let matches = Cli::command()
        .try_get_matches_from(argv)
        .unwrap_or_else(|e| panic!("clap 解析 {args:?} 失败: {e}"));
    matches
        .subcommand_matches("run")
        .expect("应匹配到 run 子命令")
        .clone()
}

/// 跑 `seabox run <args>`，返回 (是否成功, stderr)。
fn run_expect_err(args: &[&str]) -> (bool, String) {
    let out = std::process::Command::new(seabox())
        .arg("run")
        .args(args)
        .output()
        .expect("failed to spawn seabox");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

// ---------------------------------------------------------------------------
// 组 1：全平台（不依赖平台）
// ---------------------------------------------------------------------------

/// N9 前半段：12 个 `--mac-*` flag 都**未被 `#[cfg]` 门控**，且真的进了
/// `ArgMatches`（`ValueSource::CommandLine` = 值来自命令行，而非默认值）。
///
/// 若某字段被 cfg 掉，clap 会报 `unexpected argument '--mac-read'`，
/// 用户拿不到「请改用 `--landlock`」的建议文案——H1/H2/H3 全线失效。
#[test]
fn all_twelve_mac_flags_are_parsed_by_clap() {
    for (flag, args) in MAC_FLAG_ARGS {
        // clap derive 把 `--mac-read-all` 映射为长名 `mac-read-all`、id `mac_read_all`。
        let id = flag.trim_start_matches("--").replace('-', "_");
        let matches = run_matches(args);
        assert_eq!(
            matches.value_source(&id),
            Some(ValueSource::CommandLine),
            "{flag} 未被 clap 识别为命令行参数（可能被 #[cfg] 门控掉了）"
        );
    }
}

/// N9 清单自校验：`run` 子命令上恰好有 12 个 `mac_*` 参数。
///
/// 设计稿写「13 个」，实际 12 个。本断言是计数回归守卫：
/// 新增 flag 时必须同步 [`MAC_FLAG_ARGS`] 与 `src/macos/config.rs` 的 `with_*`。
#[test]
fn mac_flag_count_is_twelve() {
    let run = Cli::command()
        .find_subcommand("run")
        .expect("应有 run 子命令")
        .clone();
    let mut names: Vec<String> = run
        .get_arguments()
        .map(|a| a.get_id().as_str().to_string())
        .filter(|id| id.starts_with("mac_"))
        .collect();
    names.sort();
    assert_eq!(
        names.len(),
        12,
        "run 子命令的 --mac-* 参数应为 12 个，实际: {names:?}"
    );
}

/// N9：`--mac-preset` 的取值集合与 `MacPreset` 三个变体一致，未知值硬错误。
#[test]
fn mac_preset_rejects_unknown_value() {
    let (ok, stderr) = run_expect_err(&["--mac-preset", "bogus", "--", "echo", "hi"]);
    assert!(!ok, "--mac-preset bogus 应当失败，stderr: {stderr}");
    assert!(
        stderr.contains("unknown --mac-preset"),
        "stderr 应含 `unknown --mac-preset`，实际: {stderr}"
    );
}

/// N9：`--mac-net` 端口列表里出现非数字项 ⇒ 报出具体非法值。
#[test]
fn mac_net_rejects_non_numeric_port() {
    let (ok, stderr) = run_expect_err(&["--mac-net", "443,abc", "--", "echo", "hi"]);
    assert!(!ok, "--mac-net 443,abc 应当失败，stderr: {stderr}");
    assert!(
        stderr.contains("invalid port \"abc\""),
        "stderr 应含 `invalid port \"abc\"`，实际: {stderr}"
    );
}

/// N9：`--mac-net ,` 全部项为空 ⇒ 空端口列表硬错误。
///
/// 不能静默退化成「禁网」通过：那样用户以为放通了端口，实际全禁。
#[test]
fn mac_net_rejects_empty_port_list() {
    let (ok, stderr) = run_expect_err(&["--mac-net", ",", "--", "echo", "hi"]);
    assert!(!ok, "--mac-net , 应当失败，stderr: {stderr}");
    assert!(
        stderr.contains("empty port list"),
        "stderr 应含 `empty port list`，实际: {stderr}"
    );
}

/// N9 后半段（AGENTS.md「CLI + Crate API 对应」）：12 个 flag 都有同名
/// `with_mac_*` 语义化方法，且字段语义正确。
///
/// 方法不存在则本测试**编译失败**——这是最强的存在性验证。
#[test]
fn builder_methods_cover_all_twelve_flags() {
    let cfg = MacOsConfig::default()
        .with_mac_preset(MacPreset::WorkspaceWrite)
        .with_mac_write("/w")
        .with_mac_deny_write("/dw")
        .with_mac_workspace("/ws")
        .with_mac_read("/r")
        // 后设 read_all ⇒ 覆盖前一行（「显式覆盖更早的 --mac-read」语义）
        .with_mac_read_all()
        .with_mac_deny_read("/dr")
        .with_mac_no_credential_deny()
        .with_mac_no_git_write()
        .with_mac_no_tmp_writable()
        .with_mac_net(NetAccess::Ports(vec![443]))
        .with_mac_net_inbound(true);

    assert_eq!(cfg.preset, Some(MacPreset::WorkspaceWrite));
    assert_eq!(cfg.write, vec![PathBuf::from("/w")]);
    assert_eq!(cfg.deny_write, vec![PathBuf::from("/dw")]);
    assert_eq!(cfg.workspace, Some(PathBuf::from("/ws")));
    assert_eq!(
        cfg.read,
        Some(MacReadMode::All),
        "read_all 应覆盖先前的 Only"
    );
    assert_eq!(cfg.deny_read, vec![PathBuf::from("/dr")]);
    // 三个 `--mac-no-*` 是「反向」语义：内部存的是正向开关。
    assert_eq!(cfg.no_credential_deny, Some(true));
    assert_eq!(cfg.allow_git_write, Some(false));
    assert_eq!(cfg.tmp_writable, Some(false));
    assert_eq!(
        cfg.net,
        Some(MacNetConfig {
            outbound: NetAccess::Ports(vec![443]),
            inbound_loopback: true,
        })
    );
}

/// 底层完整签名方法（`Option` 版）也存在，且 `None` 表达「跟随预设」而非 false。
///
/// `bool` 无法区分「未设置」与「显式 false」，而「ReadOnly 预设 + 显式关 TMP 可写」
/// 正是预设机制的核心用法，故底层必须用 `Option<bool>`。
#[test]
fn underlying_builder_methods_accept_none() {
    let cfg = MacOsConfig::default()
        .with_mac_tmp_writable(None)
        .with_mac_git_write(None)
        .with_mac_credential_deny(None)
        .with_mac_read_mode(None);

    assert_eq!(cfg.tmp_writable, None);
    assert_eq!(cfg.allow_git_write, None);
    assert_eq!(cfg.no_credential_deny, None);
    assert_eq!(cfg.read, None);
    assert!(!cfg.is_configured(), "全未设置 ⇒ 不施加沙箱");

    // 显式 Some 才改变状态
    let on = MacOsConfig::default()
        .with_mac_tmp_writable(Some(true))
        .with_mac_git_write(Some(true))
        .with_mac_credential_deny(Some(true))
        .with_mac_read_mode(Some(MacReadMode::Only(vec![PathBuf::from("/r")])));
    assert_eq!(on.tmp_writable, Some(true));
    assert_eq!(on.allow_git_write, Some(true));
    assert_eq!(
        on.no_credential_deny,
        Some(false),
        "credential_deny=true ⇒ no_credential_deny=false"
    );
    assert_eq!(on.read, Some(MacReadMode::Only(vec![PathBuf::from("/r")])));
    assert!(on.is_configured());
}

/// `SandboxConfig::with_mac_*` 委托族（链式风格在 macOS 侧保持对称）。
#[test]
fn sandbox_config_delegates_with_mac_methods() {
    let cfg = SandboxConfig::default()
        .with_mac_preset(MacPreset::ReadOnly)
        .with_mac_write("/w")
        .with_mac_deny_write("/dw")
        .with_mac_read("/r")
        .with_mac_deny_read("/dr")
        .with_mac_net(NetAccess::Loopback)
        .with_mac_git_write(Some(false))
        .with_mac_tmp_writable(Some(false))
        .with_mac_credential_deny(Some(false));

    assert_eq!(cfg.macos.preset, Some(MacPreset::ReadOnly));
    assert_eq!(cfg.macos.write, vec![PathBuf::from("/w")]);
    assert_eq!(cfg.macos.deny_write, vec![PathBuf::from("/dw")]);
    assert_eq!(
        cfg.macos.read,
        Some(MacReadMode::Only(vec![PathBuf::from("/r")]))
    );
    assert_eq!(cfg.macos.deny_read, vec![PathBuf::from("/dr")]);
    assert_eq!(
        cfg.macos.net,
        Some(MacNetConfig {
            outbound: NetAccess::Loopback,
            inbound_loopback: false,
        })
    );
    assert_eq!(cfg.macos.allow_git_write, Some(false));
    assert_eq!(cfg.macos.tmp_writable, Some(false));
    assert_eq!(cfg.macos.no_credential_deny, Some(true));
    assert!(cfg.macos.is_configured());
}

// ---------------------------------------------------------------------------
// 组 2：macOS 专用（N9 主体 + H1 + N10 扩展）
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod macos_only {
    use super::MAC_FLAG_ARGS;
    use seabox::cli::config_from_flag_args;
    use seabox::macos::config::{MacNetConfig, MacOsConfig, MacPreset, MacReadMode, NetAccess};
    use std::path::PathBuf;

    /// 走与二进制同一条管线解析一段 flag，返回 `MacOsConfig`。
    fn mac_cfg(args: &[&str]) -> MacOsConfig {
        let config = config_from_flag_args(args)
            .unwrap_or_else(|e| panic!("{args:?} 在 macOS 上应能解析，实际报错: {e}"));
        assert!(
            config.macos.is_configured(),
            "{args:?} 应使 MacOsConfig::is_configured() 为真（否则沙箱不施加）"
        );
        config.macos
    }

    // ── N9 主体：12 个 flag 逐一映射 ──

    /// N9：每个 `--mac-*` flag 落到 `MacOsConfig` 的**对应**字段。
    ///
    /// 用 `config_from_flag_args`（`preprocess → clap → parse_run`，与二进制同一条
    /// 管线）而不是 `Cli::try_parse_from`：后者看不到 `parse_run` 里的字段映射。
    #[test]
    fn n9_each_mac_flag_maps_to_mac_os_config() {
        type Check = Box<dyn Fn(&MacOsConfig) -> bool>;
        let cases: Vec<(&str, &[&str], Check)> = vec![
            (
                "--mac-preset",
                &["--mac-preset", "read-only"],
                Box::new(|c| c.preset == Some(MacPreset::ReadOnly)),
            ),
            (
                "--mac-write",
                &["--mac-write", "/tmp/seabox-mac-write"],
                Box::new(|c| c.write == vec![PathBuf::from("/tmp/seabox-mac-write")]),
            ),
            (
                "--mac-deny-write",
                &["--mac-deny-write", "/tmp/seabox-mac-deny-write"],
                Box::new(|c| c.deny_write == vec![PathBuf::from("/tmp/seabox-mac-deny-write")]),
            ),
            (
                "--mac-workspace",
                &["--mac-workspace", "/tmp/seabox-mac-workspace"],
                Box::new(|c| c.workspace == Some(PathBuf::from("/tmp/seabox-mac-workspace"))),
            ),
            (
                "--mac-read",
                &["--mac-read", "/tmp/seabox-mac-read"],
                Box::new(|c| {
                    c.read
                        == Some(MacReadMode::Only(vec![PathBuf::from(
                            "/tmp/seabox-mac-read",
                        )]))
                }),
            ),
            (
                "--mac-read-all",
                &["--mac-read-all"],
                Box::new(|c| c.read == Some(MacReadMode::All)),
            ),
            (
                "--mac-deny-read",
                &["--mac-deny-read", "/tmp/seabox-mac-deny-read"],
                Box::new(|c| c.deny_read == vec![PathBuf::from("/tmp/seabox-mac-deny-read")]),
            ),
            (
                "--mac-no-credential-deny",
                &["--mac-no-credential-deny"],
                Box::new(|c| c.no_credential_deny == Some(true)),
            ),
            (
                "--mac-no-git-write",
                &["--mac-no-git-write"],
                Box::new(|c| c.allow_git_write == Some(false)),
            ),
            (
                "--mac-no-tmp-writable",
                &["--mac-no-tmp-writable"],
                Box::new(|c| c.tmp_writable == Some(false)),
            ),
            (
                "--mac-net",
                &["--mac-net", "443,80"],
                Box::new(|c| {
                    c.net
                        == Some(MacNetConfig {
                            outbound: NetAccess::Ports(vec![443, 80]),
                            inbound_loopback: false,
                        })
                }),
            ),
            (
                "--mac-net-inbound",
                &["--mac-net-inbound"],
                Box::new(|c| {
                    c.net
                        == Some(MacNetConfig {
                            outbound: NetAccess::Deny,
                            inbound_loopback: true,
                        })
                }),
            ),
        ];

        // 清单自校验：必须与全平台清单逐项对齐（防漏测/多测）
        let covered: Vec<&str> = cases.iter().map(|(flag, _, _)| *flag).collect();
        let expected: Vec<&str> = MAC_FLAG_ARGS.iter().map(|(flag, _)| *flag).collect();
        assert_eq!(covered, expected, "N9 清单必须逐 flag 覆盖实际 12 个 flag");

        for (flag, args, check) in cases {
            let macos = mac_cfg(args);
            assert!(check(&macos), "{flag} 未映射到预期字段，实际: {macos:?}");
        }
    }

    /// N9 补充：`--mac-net` 的四种 SPEC 全部落到 `NetAccess`（含 `deny` 的 A2 陷阱）。
    ///
    /// `--mac-net deny` 的值恰好等于 `NetAccess::default()`，因此 `is_configured()`
    /// 只能靠 `net.is_some()` 判断；`mac_cfg()` 已内含该断言。
    #[test]
    fn n9_mac_net_specs_all_map() {
        for (spec, expect) in [
            ("deny", NetAccess::Deny),
            ("loopback", NetAccess::Loopback),
            ("all", NetAccess::All),
            ("80,443", NetAccess::Ports(vec![80, 443])),
        ] {
            let macos = mac_cfg(&["--mac-net", spec]);
            assert_eq!(
                macos.net,
                Some(MacNetConfig {
                    outbound: expect,
                    inbound_loopback: false,
                }),
                "--mac-net {spec} 映射错误"
            );
        }
    }

    /// N9 补充：可重复的 flag 按命令行顺序累积（`Vec` 字段）。
    #[test]
    fn n9_repeated_flags_accumulate_in_order() {
        let macos = mac_cfg(&[
            "--mac-write",
            "/tmp/sb-a",
            "--mac-write",
            "/tmp/sb-b",
            "--mac-read",
            "/tmp/sb-r1",
            "--mac-read",
            "/tmp/sb-r2",
            "--mac-deny-read",
            "/tmp/sb-d1",
            "--mac-deny-write",
            "/tmp/sb-w1",
        ]);
        assert_eq!(
            macos.write,
            vec![PathBuf::from("/tmp/sb-a"), PathBuf::from("/tmp/sb-b")]
        );
        assert_eq!(
            macos.read,
            Some(MacReadMode::Only(vec![
                PathBuf::from("/tmp/sb-r1"),
                PathBuf::from("/tmp/sb-r2"),
            ]))
        );
        assert_eq!(macos.deny_read, vec![PathBuf::from("/tmp/sb-d1")]);
        assert_eq!(macos.deny_write, vec![PathBuf::from("/tmp/sb-w1")]);
    }

    /// N9 边界：一个 `--mac-*` 都不给 ⇒ `MacOsConfig` 保持默认、不施加沙箱。
    #[test]
    fn n9_no_mac_flags_leaves_default_config() {
        let config = config_from_flag_args(Vec::<&str>::new()).expect("空 flag 应能解析");
        assert_eq!(config.macos, MacOsConfig::default());
        assert!(!config.macos.is_configured());
    }

    // ── H1：macOS 上 Linux 专属 flag ⇒ 硬错误 ──

    /// H1：`--landlock` 在 macOS 上必须硬错误，且消息含 `--landlock is Linux-only`
    /// 与 macOS 侧建议文案（`--mac-preset` / `--mac-write` / `--mac-read`）。
    #[test]
    fn h1_landlock_is_rejected_on_macos() {
        let out = std::process::Command::new(super::seabox())
            .args(["run", "--landlock", "/:ro", "--", "echo", "hi"])
            .output()
            .expect("failed to run seabox");
        assert!(!out.status.success(), "macOS 上 --landlock 必须非零退出");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("--landlock is Linux-only"),
            "实际 stderr: {stderr}"
        );
        // H3 对应文案：给出 macOS 替代方案
        for hint in ["--mac-preset", "--mac-write", "--mac-read"] {
            assert!(
                stderr.contains(hint),
                "stderr 应含建议 {hint}，实际: {stderr}"
            );
        }
    }

    /// H1（crate API 侧）：同一条管线的 `config_from_flag_args` 也必须报错。
    #[test]
    fn h1_landlock_is_rejected_via_crate_api() {
        let err = config_from_flag_args(["--landlock", "/:ro"])
            .expect_err("crate API 也应拒绝 macOS 上的 --landlock")
            .to_string();
        assert!(err.contains("--landlock is Linux-only"), "实际: {err}");
    }

    // ── N10 扩展：macOS 上 Linux 专属配置面逐条 bail，且提名冲突字段 ──

    /// N10：`--seccomp-deny-nr` / `--unshare-all` / `--bind` / `--cap-add`
    /// 各自非零退出，消息**指名**冲突字段。
    #[test]
    fn n10_linux_only_flags_are_rejected_on_macos() {
        // (参数, 消息里必须出现的冲突字段标记)
        let cases: [(&[&str], &str); 4] = [
            (&["--seccomp-deny-nr", "165"], "--seccomp-*"),
            (&["--unshare-all"], "--unshare-*"),
            (&["--bind", "/tmp", "/tmp"], "--bind"),
            (&["--cap-add", "ALL"], "--cap-*"),
        ];
        for (args, marker) in cases {
            let out = std::process::Command::new(super::seabox())
                .args(["run"])
                .args(args)
                .args(["--", "echo", "hi"])
                .output()
                .expect("failed to run seabox");
            assert!(!out.status.success(), "macOS 上 {args:?} 必须非零退出");
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(
                stderr.contains(marker),
                "{args:?} 的错误消息应指名冲突字段 {marker}，实际: {stderr}"
            );
            assert!(
                stderr.contains("Linux-only"),
                "{args:?} 的错误消息应说明 Linux-only，实际: {stderr}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 组 3：Linux 专用（H2 / H3）
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux_only {
    use super::MAC_FLAG_ARGS;
    use seabox::cli::config_from_flag_args;

    /// H2 + H3：12 个 `--mac-*` flag **逐一**在 Linux 上硬错误。
    ///
    /// 逐 flag 而非只测一个，是有意为之：bail 的前置条件是
    /// `macos.is_configured() == true`，因此本循环同时充当 Linux 侧的
    /// 「flag 确实被映射进了 `MacOsConfig`」回归守卫——某个 flag 若在
    /// `parse_run` 里漏掉映射，它就不会 bail，这里立刻失败。
    #[test]
    fn h2_each_mac_flag_is_rejected_on_linux() {
        for (flag, args) in MAC_FLAG_ARGS {
            let out = std::process::Command::new(super::seabox())
                .args(["run"])
                .args(args)
                .args(["--", "echo", "hi"])
                .output()
                .expect("failed to run seabox");
            assert!(!out.status.success(), "Linux 上 {flag} 必须非零退出");
            let stderr = String::from_utf8_lossy(&out.stderr);
            // H2：平台互斥的硬错误
            assert!(
                stderr.contains("--mac-* options are macOS-only"),
                "{flag} 的 stderr 应含 macOS-only 提示，实际: {stderr}"
            );
            // H3：建议文案指向 Linux 侧等价机制
            for hint in ["--landlock", "--unshare-*", "--seccomp-deny-nr"] {
                assert!(
                    stderr.contains(hint),
                    "{flag} 的 stderr 应含建议 {hint}，实际: {stderr}"
                );
            }
        }
    }

    /// H2（crate API 侧）：`config_from_flag_args` 同样拒绝，不必 spawn 进程。
    #[test]
    fn h2_mac_preset_is_rejected_via_crate_api() {
        let err = config_from_flag_args(["--mac-preset", "read-only"])
            .expect_err("crate API 也应拒绝 Linux 上的 --mac-*")
            .to_string();
        assert!(
            err.contains("--mac-* options are macOS-only"),
            "实际: {err}"
        );
    }

    /// H3 的 A2 关联：`--mac-net deny` 的值等于 `NetAccess::default()`，
    /// 若 `is_configured()` 用 `PartialEq` 比对默认值就会被误判为「未配置」，
    /// 从而在 Linux 上**静默放行**。本用例守住这条静默失效路径。
    #[test]
    fn h2_mac_net_deny_is_not_silently_ignored_on_linux() {
        let err = config_from_flag_args(["--mac-net", "deny"])
            .expect_err("--mac-net deny 也必须被判为「已配置」而在 Linux 上报错")
            .to_string();
        assert!(
            err.contains("--mac-* options are macOS-only"),
            "实际: {err}"
        );
    }
}
