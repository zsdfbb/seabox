//! 从 TOML 配置文件加载沙箱配置。
//!
//! 运行: `cargo run --example cli_from_toml`
//!
//! 演示如何定义 TOML 格式的配置结构，解析后创建沙箱并执行命令。
//!
//! 注意：sandbox-runtime 本身不提供 serde 序列化支持，
//! 但你可以像本示例一样自己定义可序列化的配置层。

use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

use sandbox_runtime::config::SandboxConfig;
use sandbox_runtime::{CommandSpec, ExitReason, Sandbox};

// ───────────────────────────────────────────────────────────
// 1. 定义 TOML 可解析的配置结构
// ───────────────────────────────────────────────────────────

/// TOML 配置（只包含常用字段，可按需扩展）。
#[derive(Debug, Deserialize)]
struct TomlConfig {
    /// Landlock 规则列表，格式同 `--landlock`：`path:perm`
    #[serde(default)]
    landlock: Vec<String>,

    /// 命名空间隔离设置
    #[serde(default)]
    namespaces: TomlNamespaces,

    /// seccomp 黑名单 syscall 号
    #[serde(default)]
    seccomp_deny_nrs: Vec<u32>,

    /// 默认超时（秒）
    #[serde(default = "default_timeout")]
    timeout_default_secs: u64,

    /// 超时上限（秒）
    #[serde(default = "default_timeout_max")]
    timeout_max_secs: u64,
}

#[derive(Debug, Default, Deserialize)]
struct TomlNamespaces {
    #[serde(default)]
    user: bool,
    #[serde(default)]
    ipc: bool,
    #[serde(default)]
    mnt: bool,
    #[serde(default)]
    pid: bool,
    #[serde(default)]
    net: bool,
    #[serde(default)]
    uts: bool,
    #[serde(default)]
    cgroup: bool,
}

fn default_timeout() -> u64 {
    30
}
fn default_timeout_max() -> u64 {
    300
}

// ───────────────────────────────────────────────────────────
// 2. 转换为 SandboxConfig
// ───────────────────────────────────────────────────────────

impl TryFrom<TomlConfig> for SandboxConfig {
    type Error = anyhow::Error;

    fn try_from(t: TomlConfig) -> Result<Self, Self::Error> {
        let mut config = SandboxConfig::default();

        // Landlock
        for rule in &t.landlock {
            config = config.with_landlock(rule)?;
        }

        // Namespaces
        let ns = &t.namespaces;
        if ns.user {
            config = config.with_unshare_user();
        }
        if ns.ipc {
            config = config.with_unshare_ipc();
        }
        if ns.mnt {
            config = config.with_unshare_mnt();
        }
        if ns.pid {
            config = config.with_unshare_pid();
        }
        if ns.net {
            config = config.with_unshare_net();
        }
        if ns.uts {
            config = config.with_unshare_uts();
        }
        if ns.cgroup {
            config = config.with_unshare_cgroup();
        }

        // Seccomp
        for nr in &t.seccomp_deny_nrs {
            config = config.with_seccomp_deny_nr(*nr);
        }

        // Timeout
        config = config.with_timeout(t.timeout_default_secs, t.timeout_max_secs);

        Ok(config)
    }
}

// ───────────────────────────────────────────────────────────
// 3. 入口
// ───────────────────────────────────────────────────────────

fn main() -> anyhow::Result<()> {
    // ── 3a. TOML 配置字符串（实际使用时可从文件读取） ──
    let toml_str = r#"
        landlock = ["/:ro", "/tmp:rw", "/usr:ro"]

        [namespaces]
        user = true
        pid  = true
        net  = true
        mnt  = true

        seccomp_deny_nrs = [165, 97]

        timeout_default_secs = 15
        timeout_max_secs     = 60
    "#;

    // ── 3b. 解析 TOML ────────────────────────────────
    let toml_config: TomlConfig =
        toml::from_str(toml_str).map_err(|e| anyhow::anyhow!("TOML parse error: {e}"))?;

    println!("parsed config: {toml_config:#?}");

    // ── 3c. 转换为 SandboxConfig ────────────────────
    let config = SandboxConfig::try_from(toml_config)?;

    // ── 3d. 创建沙箱并执行命令 ──────────────────────
    let sandbox = Sandbox::from_config(config)?;

    let spec = CommandSpec::default()
        .with_program("sh")
        .with_args(["-c", "echo 'hello from TOML config'; mount"])
        .with_cwd(PathBuf::from("/tmp"))
        .with_timeout(Duration::from_secs(5));

    let (output, reason) = sandbox.execute(&spec)?;

    println!("exit_code: {}", output.exit_code);
    println!("reason:    {reason:?}");

    match reason {
        ExitReason::Ok => {
            println!("命令成功执行");
        }
        ExitReason::Denied { mechanism, message } => {
            eprintln!("沙箱拒绝 ({mechanism:?}): {message}");
            std::process::exit(126);
        }
        ExitReason::Program(code) => {
            eprintln!("命令以非零退出码 {code} 退出");
            std::process::exit(code);
        }
        ExitReason::InternalError(msg) => {
            eprintln!("内部错误: {msg}");
            std::process::exit(125);
        }
    }

    Ok(())
}
