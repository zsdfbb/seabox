use std::collections::HashMap;
use std::time::Duration;

use clap::Parser;

use sandbox_runtime::config::SandboxConfig;
use sandbox_runtime::{CommandSpec, ExitReason, Sandbox};

#[cfg(target_os = "linux")]
use sandbox_runtime::linux::{self, LinuxSandbox};

// ---------------------------------------------------------------------------
// CLI 定义
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "sandbox-runtime")]
enum Cli {
    /// 在沙箱内运行一条命令
    Run {
        /// 沙箱策略：full-access、read-only、workspace
        #[arg(short = 'p', long)]
        policy: Option<String>,

        /// 允许网络访问
        #[arg(short = 'n', long)]
        allow_network: bool,

        /// 额外的可写路径（可重复指定）
        #[arg(short = 'w', long)]
        allow_write: Vec<String>,

        /// 启用调试输出
        #[arg(short = 'd', long)]
        debug: bool,

        /// 要执行的命令（trailing 参数；使用 -- 进行分隔）
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// 检查当前系统可用的沙箱机制
    Check,

    /// 启动 HTTP API 服务器（占位实现，尚未完成）
    Serve {
        /// 监听的端口
        #[arg(long, default_value_t = 7878)]
        port: u16,
    },
}

// ---------------------------------------------------------------------------
// 入口
// ---------------------------------------------------------------------------

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli {
        Cli::Run {
            policy,
            allow_network,
            allow_write,
            debug,
            command,
        } => cmd_run(policy, allow_network, allow_write, debug, command),
        Cli::Check => cmd_check(),
        Cli::Serve { port } => cmd_serve(port),
    }
}

// ---------------------------------------------------------------------------
// run 子命令
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn cmd_run(
    policy: Option<String>,
    allow_network: bool,
    allow_write: Vec<String>,
    _debug: bool,
    command: Vec<String>,
) -> anyhow::Result<()> {
    if command.is_empty() {
        anyhow::bail!(
            "error: no command specified.\n\
             Usage: sandbox-runtime run [OPTIONS] <COMMAND>...\n\
             For example: sandbox-runtime run ls -la"
        );
    }

    let config = build_config(policy, allow_network, allow_write)?;

    let sandbox = LinuxSandbox { config };

    let program = command[0].clone();
    let args = command[1..].to_vec();
    let env: HashMap<String, String> = std::env::vars().collect();

    let spec = CommandSpec {
        program,
        args,
        cwd: std::env::current_dir()?,
        env,
        timeout: Duration::from_secs(sandbox.config.timeout.default_secs),
        sandbox_policy: sandbox.config.filesystem.policy.clone(),
    };

    let output = sandbox.execute(&spec)?;

    let reason = sandbox.classify_exit(output.exit_code, output.blocked_syscall);

    match reason {
        ExitReason::Ok => std::process::exit(0),
        ExitReason::Denied { mechanism, message } => {
            eprintln!("Sandbox denial ({mechanism:?}): {message}");
            std::process::exit(126)
        }
        ExitReason::Program(code) => {
            if code != 0 {
                eprintln!("[sandbox-runtime] command failed (exit code {code}) under policy \"{:?}\"",
                    sandbox.config.filesystem.policy);
            }
            std::process::exit(code)
        }
        ExitReason::InternalError(msg) => {
            eprintln!("Internal error: {msg}");
            std::process::exit(125)
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn cmd_run(
    _policy: Option<String>,
    _allow_network: bool,
    _allow_write: Vec<String>,
    _debug: bool,
    _command: Vec<String>,
) -> anyhow::Result<()> {
    anyhow::bail!(
        "sandbox-runtime run requires Linux; \
         the current platform is not supported"
    );
}

// ---------------------------------------------------------------------------
// check 子命令
// ---------------------------------------------------------------------------

fn cmd_check() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let landlock_avail = linux::landlock::is_available();
        let landlock_abi = linux::landlock::get_abi_version();
        let seccomp_avail = linux::seccomp::is_available();

        println!("Capability                    Status");
        println!("----------------------------- --------------------");
        println!(
            "Landlock                      {}",
            if landlock_avail {
                format!("available (ABI v{})", landlock_abi.unwrap_or(0))
            } else {
                "not available".to_string()
            }
        );
        println!(
            "Seccomp                       {}",
            if seccomp_avail {
                "available"
            } else {
                "not available"
            }
        );
    }

    #[cfg(not(target_os = "linux"))]
    {
        println!("Capability                    Status");
        println!("----------------------------- --------------------");
        println!("Landlock                      not available (non-Linux)");
        println!("Seccomp                       not available (non-Linux)");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// serve 子命令（占位）
// ---------------------------------------------------------------------------

fn cmd_serve(port: u16) -> anyhow::Result<()> {
    anyhow::bail!("HTTP API server not yet implemented (port {port})");
}

// ---------------------------------------------------------------------------
// 配置辅助函数
// ---------------------------------------------------------------------------

/// 从 CLI flags 构建一个 [`SandboxConfig`]。
fn build_config(
    policy: Option<String>,
    allow_network: bool,
    allow_write: Vec<String>,
) -> anyhow::Result<SandboxConfig> {
    let mut config = SandboxConfig::builder();
    if let Some(p) = policy {
        config = config.policy(p.parse()?);
    }
    Ok(config.allow_write(allow_write).network_enabled(allow_network).build())
}