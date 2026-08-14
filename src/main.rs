use std::os::unix::process::ExitStatusExt;
use std::sync::atomic::{AtomicI32, Ordering};

use clap::{CommandFactory, FromArgMatches};

use seabox::cli::{self, Cli, RunSpec};
use seabox::config::SandboxConfig;
use seabox::{CommandSpec, ExitReason, Sandbox, StdioConfig};

/// 当前正在执行子进程的 kill_pid（= 其进程组 id，因子进程恒 setpgid(0,0)）。
/// 仅 CLI 层使用；信号 handler 经 `AtomicI32::load` 读取（async-signal-safe）。
static CHILD_PGID: AtomicI32 = AtomicI32::new(0);

/// SIGINT/SIGTERM 转发 handler（§6.5）：把信号转发到子进程组，然后以
/// GNU 惯例退出（`_exit(128 + sig)`）。`kill` / `_exit` / `AtomicI32::load`
/// 均 async-signal-safe，handler 内无锁、无堆。
extern "C" fn forward(sig: libc::c_int) {
    let pgid = CHILD_PGID.load(Ordering::Relaxed);
    if pgid > 0 {
        // SAFETY: kill(2) 纯 syscall；-pgid 为子进程组 id。
        unsafe { libc::kill(-pgid, sig) };
    }
    // SAFETY: _exit(2) 纯 syscall，不运行析构（信号上下文中必须如此）。
    unsafe { libc::_exit(128 + sig) };
}

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
        timeout: Some(spec.timeout),
        stdin: None,
    };

    // 信号转发（§6.5）：process_group=true（默认）使子进程脱离终端前台组 →
    // Ctrl+C 只杀 seabox 自己。CLI 层转发 SIGINT/SIGTERM 到子进程组。
    // 职责边界：只在 CLI 层，不进库（库可被多线程并发调用，全局 pgid 会串扰；
    // CodeWhale 用自己的 tokio::signal 处理）。
    for sig in [libc::SIGINT, libc::SIGTERM] {
        // SAFETY: signal(2) 纯 syscall；handler 为 async-signal-safe 函数。
        let prev = unsafe { libc::signal(sig, forward as *const () as libc::sighandler_t) };
        if prev == libc::SIG_ERR {
            anyhow::bail!("failed to install signal handler for {sig}");
        }
    }

    // 流式：spawn(Inherit)，子进程直写终端 + 交互 stdin 恢复；不走 execute 捕获。
    let mut child = sandbox.spawn(&command, StdioConfig::Inherit)?;
    CHILD_PGID.store(child.id() as i32, Ordering::Relaxed);

    let status = match command.timeout {
        Some(d) => child.wait_timeout(d)?,
        None => child.wait()?,
    };
    CHILD_PGID.store(0, Ordering::Relaxed);

    // 超时强制：wait_timeout 到期已 kill+reap；CLI 以 124 退出（timeout 惯例）。
    if child.timed_out() {
        eprintln!("[seabox] command timed out after {:?}", command.timeout);
        std::process::exit(124);
    }

    // D-A1 约定：被信号杀死时以 `128+sig` 退出（signal-death 不再退化为 1）。
    // `ExitStatusExt::signal()` 在 `code()` 为 None（signal-death）时给出信号号。
    let exit_code = status
        .code()
        .or_else(|| status.signal().map(|s| 128 + s))
        .unwrap_or(1);
    let reason = sandbox.classify_exit(exit_code, child.blocked());

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
