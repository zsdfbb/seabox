use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;

use sandbox_runtime::config::SandboxConfig;
use sandbox_runtime::{CommandSpec, ExitReason, FsPolicy, Sandbox};

#[cfg(target_os = "linux")]
use sandbox_runtime::linux::{self, LinuxSandbox};

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "sandbox-runtime")]
enum Cli {
    /// Run a command inside the sandbox
    Run {
        /// Path to TOML configuration file
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Sandbox policy: full-access, read-only, workspace
        #[arg(short = 'p', long)]
        policy: Option<String>,

        /// Allow network access
        #[arg(short = 'n', long)]
        allow_network: bool,

        /// Additional writable paths (can be repeated)
        #[arg(short = 'w', long)]
        allow_write: Vec<String>,

        /// Enable debug output
        #[arg(short = 'd', long)]
        debug: bool,

        /// Command to execute (trailing arguments; use -- to separate)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// Check available sandbox mechanisms on this system
    Check,

    /// Start the HTTP API server (stub, not yet implemented)
    Serve {
        /// Port to listen on
        #[arg(long, default_value_t = 7878)]
        port: u16,
    },
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli {
        Cli::Run {
            config,
            policy,
            allow_network,
            allow_write,
            debug,
            command,
        } => cmd_run(config, policy, allow_network, allow_write, debug, command),
        Cli::Check => cmd_check(),
        Cli::Serve { port } => cmd_serve(port),
    }
}

// ---------------------------------------------------------------------------
// run subcommand
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn cmd_run(
    config_path: Option<PathBuf>,
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

    let config = build_config(config_path, policy, allow_network, allow_write)?;

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

    // Forward stdout
    if !output.stdout.is_empty() {
        print!("{}", output.stdout);
    }

    // Forward stderr
    if !output.stderr.is_empty() {
        eprint!("{}", output.stderr);
    }

    let reason = sandbox.classify_exit(output.exit_code, &output.stderr);

    match reason {
        ExitReason::Ok => std::process::exit(0),
        ExitReason::Denied { mechanism, message } => {
            eprintln!("Sandbox denial ({mechanism:?}): {message}");
            std::process::exit(126)
        }
        ExitReason::Program(code) => std::process::exit(code),
        ExitReason::InternalError(msg) => {
            eprintln!("Internal error: {msg}");
            std::process::exit(125)
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn cmd_run(
    _config_path: Option<PathBuf>,
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
// check subcommand
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
// serve subcommand (stub)
// ---------------------------------------------------------------------------

fn cmd_serve(port: u16) -> anyhow::Result<()> {
    anyhow::bail!("HTTP API server not yet implemented (port {port})");
}

// ---------------------------------------------------------------------------
// Configuration helpers
// ---------------------------------------------------------------------------

/// Build a [`SandboxConfig`] by merging optional TOML config with CLI flags.
///
/// CLI flags take precedence over values loaded from the TOML file:
/// - `--policy` overrides `filesystem.policy`
/// - `--allow-write` replaces `filesystem.allow_write` entirely
/// - `--allow-network` sets `network.enabled`
fn build_config(
    config_path: Option<PathBuf>,
    policy: Option<String>,
    allow_network: bool,
    allow_write: Vec<String>,
) -> anyhow::Result<SandboxConfig> {
    let mut config = if let Some(path) = config_path {
        SandboxConfig::from_toml(path)?
    } else {
        SandboxConfig::default()
    };

    // CLI flags override TOML values
    if let Some(p) = policy {
        config.filesystem.policy = parse_policy(&p)?;
    }

    if !allow_write.is_empty() {
        config.filesystem.allow_write = allow_write;
    }

    config.network.enabled = allow_network;

    Ok(config)
}

/// Parse a policy string into an [`FsPolicy`].
fn parse_policy(s: &str) -> anyhow::Result<FsPolicy> {
    match s {
        "full-access" => Ok(FsPolicy::FullAccess),
        "read-only" => Ok(FsPolicy::ReadOnly),
        "workspace" => Ok(FsPolicy::WorkspaceWrite),
        other => anyhow::bail!(
            "unknown policy '{other}'; expected one of: full-access, read-only, workspace"
        ),
    }
}
