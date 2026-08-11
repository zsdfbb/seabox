use clap::{CommandFactory, FromArgMatches};

use seabox::cli::{self, Cli, RunSpec};
use seabox::config::SandboxConfig;
use seabox::{CommandSpec, ExitReason, Sandbox};

fn main() -> anyhow::Result<()> {
    // @file profile 预处理：在 clap 解析前展开 flag 文本进 argv。
    // 只处理选项区（首个裸 -- 之前），命令区 @x 原样。
    let cwd = std::env::current_dir()?;
    let home = dirs::home_dir();
    let args = seabox::profile::preprocess(std::env::args_os(), &cwd, home.as_deref())?;

    // 用 get_matches + from_arg_matches 两步，以便保留挂载 flag 的全局出现顺序
    // （collect_mount_actions 需要 matches.indices_of）。
    let matches = Cli::command().get_matches_from(args);
    let cli = Cli::from_arg_matches(&matches)?;

    match cli {
        Cli::Run { .. } => {
            // bind/ro_bind/tmpfs 属于 Run 子命令，需取子命令的 ArgMatches。
            let run_matches = matches
                .subcommand_matches("run")
                .expect("matched Run subcommand");
            let (config, spec) = cli::parse_run(cli, run_matches)?;
            cmd_run(config, spec)
        }
        Cli::Check => cmd_check(),
        Cli::Serve { port } => cmd_serve(port),
    }
}

// ---------------------------------------------------------------------------
// run 子命令
// ---------------------------------------------------------------------------

fn cmd_run(config: SandboxConfig, spec: RunSpec) -> anyhow::Result<()> {
    let sandbox = Sandbox::from_config(config)?;

    // 处理 --chdir（覆盖默认 cwd）
    let cwd = match spec.chdir {
        Some(path) => path,
        None => std::env::current_dir()?,
    };

    let command = CommandSpec {
        program: spec.command[0].clone(),
        args: spec.command[1..].to_vec(),
        cwd,
        env: spec.env,
        timeout: spec.timeout,
    };

    let (_output, reason) = sandbox.execute(&command)?;

    match reason {
        ExitReason::Ok => std::process::exit(0),
        ExitReason::Denied { mechanism, message } => {
            eprintln!("Sandbox denial ({mechanism:?}): {message}");
            std::process::exit(126)
        }
        ExitReason::Program(code) => {
            if code != 0 {
                eprintln!("[seabox] command failed (exit code {code})");
            }
            std::process::exit(code)
        }
        ExitReason::InternalError(msg) => {
            eprintln!("Internal error: {msg}");
            std::process::exit(125)
        }
    }
}

// ---------------------------------------------------------------------------
// check 子命令
// ---------------------------------------------------------------------------

fn cmd_check() -> anyhow::Result<()> {
    print!("{}", seabox::check_capabilities());
    Ok(())
}

// ---------------------------------------------------------------------------
// serve 子命令（占位）
// ---------------------------------------------------------------------------

fn cmd_serve(port: u16) -> anyhow::Result<()> {
    anyhow::bail!("HTTP API server not yet implemented (port {port})");
}
