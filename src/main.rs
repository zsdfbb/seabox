use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;

use sandbox_runtime::config::{NamespacesConfig, SandboxConfig};
use sandbox_runtime::{CommandSpec, ExitReason, LandlockPerm, LandlockRule};

// ---------------------------------------------------------------------------
// CLI 定义
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "sandbox-runtime")]
enum Cli {
    /// 在沙箱内运行一条命令
    Run {
        /// Landlock 路径权限规格，格式 path:perm1[,perm2...]
        #[arg(long)]
        landlock: Vec<String>,

        /// 允许网络访问
        #[arg(short = 'n', long)]
        allow_network: bool,

        /// 启用调试输出
        #[arg(short = 'd', long)]
        debug: bool,

        /// 所有的命名空间隔离
        #[arg(long)]
        unshare_all: bool,

        /// User 命名空间隔离
        #[arg(long)]
        unshare_user: bool,
        /// IPC 命名空间隔离
        #[arg(long)]
        unshare_ipc: bool,
        /// PID 命名空间隔离
        #[arg(long)]
        unshare_pid: bool,
        /// 网络命名空间隔离
        #[arg(long)]
        unshare_net: bool,
        /// UTS 命名空间隔离
        #[arg(long)]
        unshare_uts: bool,
        /// Cgroup 命名空间隔离
        #[arg(long)]
        unshare_cgroup: bool,

        /// 软性 User 命名空间（内核不支持时静默回退）
        #[arg(long)]
        unshare_user_try: bool,
        /// 软性 Cgroup 命名空间（内核不支持时静默回退）
        #[arg(long)]
        unshare_cgroup_try: bool,

        /// 在 user 命名空间中映射的 uid
        #[arg(long)]
        uid: Option<u32>,
        /// 在 user 命名空间中映射的 gid
        #[arg(long)]
        gid: Option<u32>,
        /// 在 UTS 命名空间中设置的 hostname
        #[arg(long)]
        hostname: Option<String>,

        /// 覆盖工作目录（而非默认的 cwd）
        #[arg(long)]
        chdir: Option<PathBuf>,

        /// 清空环境变量
        #[arg(long)]
        clearenv: bool,

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
            landlock,
            allow_network,
            debug,
            command,
            unshare_all,
            unshare_user,
            unshare_ipc,
            unshare_pid,
            unshare_net,
            unshare_uts,
            unshare_cgroup,
            unshare_user_try,
            unshare_cgroup_try,
            uid,
            gid,
            hostname,
            chdir,
            clearenv,
        } => cmd_run(
            landlock,
            allow_network,
            debug,
            command,
            unshare_all,
            unshare_user,
            unshare_ipc,
            unshare_pid,
            unshare_net,
            unshare_uts,
            unshare_cgroup,
            unshare_user_try,
            unshare_cgroup_try,
            uid,
            gid,
            hostname,
            chdir,
            clearenv,
        ),
        Cli::Check => cmd_check(),
        Cli::Serve { port } => cmd_serve(port),
    }
}

// ---------------------------------------------------------------------------
// run 子命令
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn cmd_run(
    landlock: Vec<String>,
    allow_network: bool,
    _debug: bool,
    command: Vec<String>,
    // namespace flags
    unshare_all: bool,
    unshare_user: bool,
    unshare_ipc: bool,
    unshare_pid: bool,
    unshare_net: bool,
    unshare_uts: bool,
    unshare_cgroup: bool,
    unshare_user_try: bool,
    unshare_cgroup_try: bool,
    uid: Option<u32>,
    gid: Option<u32>,
    hostname: Option<String>,
    chdir: Option<PathBuf>,
    clearenv: bool,
) -> anyhow::Result<()> {
    if command.is_empty() {
        anyhow::bail!(
            "error: no command specified.\n\
             Usage: sandbox-runtime run [OPTIONS] <COMMAND>...\n\
             For example: sandbox-runtime run ls -la"
        );
    }

    // --uid/--gid 需要 --unshare-user
    if uid.is_some() && !unshare_user && !unshare_all {
        anyhow::bail!("--uid requires --unshare-user or --unshare-all");
    }
    if gid.is_some() && !unshare_user && !unshare_all {
        anyhow::bail!("--gid requires --unshare-user or --unshare-all");
    }
    // --hostname 需要 --unshare-uts
    if hostname.is_some() && !unshare_uts && !unshare_all {
        anyhow::bail!("--hostname requires --unshare-uts or --unshare-all");
    }

    let config = build_config(
        landlock,
        allow_network,
        unshare_all,
        unshare_user,
        unshare_ipc,
        unshare_pid,
        unshare_net,
        unshare_uts,
        unshare_cgroup,
        unshare_user_try,
        unshare_cgroup_try,
        uid,
        gid,
        hostname,
    )?;

    let timeout = Duration::from_secs(config.timeout.default_secs);
    let sandbox = sandbox_runtime::create_sandbox(config)?;

    let program = command[0].clone();
    let args = command[1..].to_vec();

    // 处理 --clearenv
    let env: HashMap<String, String> = if clearenv {
        HashMap::new()
    } else {
        std::env::vars().collect()
    };

    // 处理 --chdir（覆盖默认 cwd）
    let cwd = match chdir {
        Some(path) => path,
        None => std::env::current_dir()?,
    };

    let spec = CommandSpec {
        program,
        args,
        cwd,
        env,
        timeout,
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
                eprintln!("[sandbox-runtime] command failed (exit code {code})");
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
    print!("{}", sandbox_runtime::check_capabilities());
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
#[allow(clippy::too_many_arguments)]
fn build_config(
    landlock: Vec<String>,
    allow_network: bool,
    // namespace flags
    unshare_all: bool,
    unshare_user: bool,
    unshare_ipc: bool,
    unshare_pid: bool,
    unshare_net: bool,
    unshare_uts: bool,
    unshare_cgroup: bool,
    unshare_user_try: bool,
    unshare_cgroup_try: bool,
    uid: Option<u32>,
    gid: Option<u32>,
    hostname: Option<String>,
) -> anyhow::Result<SandboxConfig> {
    let rules = landlock
        .iter()
        .map(|s| parse_landlock_spec(s))
        .collect::<anyhow::Result<Vec<_>>>()?;

    // --unshare-pid 在非 root 下需要 user ns 来获取 CAP_SYS_ADMIN
    let pid_without_user = (unshare_pid || unshare_all) && !unshare_user && !unshare_all;
    let need_user_for_pid = pid_without_user && unsafe { libc::geteuid() } != 0;
    let effective_user = unshare_user || unshare_all || need_user_for_pid;

    Ok(SandboxConfig::builder()
        .landlock(rules)
        .network_enabled(allow_network)
        .namespaces(NamespacesConfig {
            user: effective_user,
            ipc: unshare_ipc || unshare_all,
            pid: unshare_pid || unshare_all,
            net: unshare_net || unshare_all,
            uts: unshare_uts || unshare_all,
            cgroup: unshare_cgroup || unshare_all,
            user_try: unshare_user_try,
            cgroup_try: unshare_cgroup_try,
            uid,
            gid,
            hostname,
        })
        .build())
}

/// 解析 --landlock 参数：path:perm1[,perm2...]
fn parse_landlock_spec(s: &str) -> anyhow::Result<LandlockRule> {
    let (path, perms_str) = s.split_once(':').ok_or_else(|| {
        anyhow::anyhow!("invalid --landlock spec '{s}'; expected format: path:perm1[,perm2...]")
    })?;
    let perms = perms_str.split(',').flat_map(expand_perm).collect();
    Ok(LandlockRule {
        path: path.into(),
        perms,
    })
}

/// 将权限字符串展开为个体权限列表。
///
/// 预设组合（`ro`/`rx`、`rw`、`rwx`、`all`）会被展开为对应的个体权限；
/// 个体权限名直接解析为 [`LandlockPerm`] 单元素向量。
fn expand_perm(s: &str) -> Vec<LandlockPerm> {
    match s {
        "ro" | "rx" => vec![
            LandlockPerm::Execute,
            LandlockPerm::ReadFile,
            LandlockPerm::ReadDir,
        ],
        "rw" => vec![
            LandlockPerm::Execute,
            LandlockPerm::ReadFile,
            LandlockPerm::ReadDir,
            LandlockPerm::WriteFile,
            LandlockPerm::RemoveDir,
            LandlockPerm::RemoveFile,
            LandlockPerm::MakeDir,
            LandlockPerm::MakeReg,
            LandlockPerm::MakeSym,
            LandlockPerm::Truncate,
        ],
        "rwx" => vec![
            LandlockPerm::Execute,
            LandlockPerm::ReadFile,
            LandlockPerm::ReadDir,
            LandlockPerm::WriteFile,
            LandlockPerm::RemoveDir,
            LandlockPerm::RemoveFile,
            LandlockPerm::MakeDir,
            LandlockPerm::MakeReg,
            LandlockPerm::MakeSym,
            LandlockPerm::Truncate,
            LandlockPerm::MakeSock,
            LandlockPerm::MakeFifo,
            LandlockPerm::MakeBlock,
            LandlockPerm::MakeChar,
        ],
        "all" => vec![
            LandlockPerm::Execute,
            LandlockPerm::ReadFile,
            LandlockPerm::ReadDir,
            LandlockPerm::WriteFile,
            LandlockPerm::RemoveDir,
            LandlockPerm::RemoveFile,
            LandlockPerm::MakeDir,
            LandlockPerm::MakeReg,
            LandlockPerm::MakeSym,
            LandlockPerm::Truncate,
            LandlockPerm::MakeSock,
            LandlockPerm::MakeFifo,
            LandlockPerm::MakeBlock,
            LandlockPerm::MakeChar,
            LandlockPerm::Refer,
            LandlockPerm::IoctlDev,
        ],
        other => vec![other.parse::<LandlockPerm>().unwrap()],
    }
}
