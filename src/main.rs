use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;

use sandbox_runtime::config::{parse_landlock_spec, NamespacesConfig, SandboxConfig};
use sandbox_runtime::{CommandSpec, ExitReason, Sandbox};

/// 解析 `KEY=VALUE` 格式的环境变量，返回 `(key, value)`。
fn parse_env_var(s: &str) -> Result<(String, String), String> {
    let (key, val) = s.split_once('=').ok_or_else(|| {
        format!("invalid --env value '{s}': expected KEY=VALUE format (missing '=')")
    })?;
    if key.is_empty() {
        return Err("invalid --env value: KEY must not be empty".into());
    }
    Ok((key.to_owned(), val.to_owned()))
}

// ---------------------------------------------------------------------------
// CLI 定义
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "sandbox-runtime")]
#[allow(clippy::large_enum_variant)]
enum Cli {
    /// 在沙箱内运行一条命令
    Run {
        /// Landlock 路径权限规格，格式 path:perm1[,perm2...]
        #[arg(long)]
        landlock: Vec<String>,

        /// 允许网络访问（正交于 --unshare-net，同义于 --share-net）
        #[arg(short = 'n', long)]
        allow_network: bool,

        /// 共享宿主机网络（bwrap 兼容别名，等价于 --allow-network）
        #[arg(long)]
        share_net: bool,

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

        /// 设置或覆盖环境变量，格式 KEY=VALUE（可重复）
        #[arg(long, value_parser = parse_env_var)]
        env: Vec<(String, String)>,

        /// 删除环境变量（可重复）
        #[arg(long)]
        unsetenv: Vec<String>,

        /// 命令超时秒数（默认 30，不超过 --timeout-max）
        #[arg(long)]
        timeout: Option<u64>,

        /// 命令超时上限秒数（仅 config 层，影响默认值上限）
        #[arg(long)]
        timeout_max: Option<u64>,

        /// 清空环境变量
        #[arg(long)]
        clearenv: bool,

        /// 通过 USER_NOTIF 拦截指定 syscall 号（可重复）
        #[arg(long)]
        seccomp_deny_nr: Vec<u32>,

        /// 从文件描述符读取外部原始 cBPF filter（可重复）
        #[arg(long)]
        seccomp_filter_fd: Vec<std::os::unix::io::RawFd>,

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
            share_net,
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
            env: env_vars,
            unsetenv,
            clearenv,
            seccomp_deny_nr,
            seccomp_filter_fd,
            timeout,
            timeout_max,
        } => cmd_run(
            landlock,
            allow_network,
            share_net,
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
            env_vars,
            unsetenv,
            clearenv,
            seccomp_deny_nr,
            seccomp_filter_fd,
            timeout,
            timeout_max,
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
    share_net: bool,
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
    env_vars: Vec<(String, String)>,
    unsetenv: Vec<String>,
    clearenv: bool,
    seccomp_deny_nrs: Vec<u32>,
    seccomp_filter_fds: Vec<std::os::unix::io::RawFd>,
    timeout: Option<u64>,
    timeout_max: Option<u64>,
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

    let (effective_net, effective_network) = resolve_network_config(
        unshare_net, share_net, allow_network, unshare_all,
    );

    let mut config = build_config(
        landlock,
        effective_network,
        unshare_all,
        unshare_user,
        unshare_ipc,
        unshare_pid,
        effective_net,
        unshare_uts,
        unshare_cgroup,
        unshare_user_try,
        unshare_cgroup_try,
        uid,
        gid,
        hostname,
        timeout_max,
    )?;

    // --seccomp-deny-nr: 添加 syscall 号到配置
    for nr in seccomp_deny_nrs {
        config = config.with_seccomp_deny_nr(nr);
    }

    // --seccomp-filter-fd: 从 fd 读取原始 cBPF 字节
    for fd in seccomp_filter_fds {
        use std::os::fd::FromRawFd;
        // SAFETY: fd 来自 CLI 参数，用户负责确保其有效性。
        // 转为 OwnedFd 确保读取后自动 close。
        let owned_fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
        let mut file = std::fs::File::from(owned_fd);
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut file, &mut bytes)
            .map_err(|e| anyhow::anyhow!("failed to read seccomp BPF from fd {fd}: {e}"))?;
        config = config.with_seccomp_filter(bytes);
    }

    // --timeout SECS 覆盖默认值，但不允许超过 timeout_max_secs
    let timeout_secs = match timeout {
        Some(s) => s.min(config.timeout_max_secs),
        None => config.timeout_default_secs,
    };
    let timeout = Duration::from_secs(timeout_secs);
    let sandbox = Sandbox::from_config(config)?;

    let program = command[0].clone();
    let args = command[1..].to_vec();

    // 处理 --clearenv + --unsetenv + --env
    let mut env: HashMap<String, String> = if clearenv {
        HashMap::new()
    } else {
        std::env::vars().collect()
    };
    for key in &unsetenv {
        env.remove(key);
    }
    for (key, value) in &env_vars {
        env.insert(key.clone(), value.clone());
    }

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

    let (_output, reason) = sandbox.execute(&spec)?;

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

/// 解析网络标志冲突，返回 (effective_net, effective_network)。
///
/// `--share-net` 或 `--allow-network` 会抑制 `--unshare-net`，使宿主机网络保持可用。
/// 最后 flag 获胜。
fn resolve_network_config(
    unshare_net: bool,
    share_net: bool,
    allow_network: bool,
    unshare_all: bool,
) -> (bool, bool) {
    if share_net || allow_network {
        (false, true)
    } else if unshare_net || unshare_all {
        (true, false)
    } else {
        (false, false)
    }
}

#[allow(clippy::too_many_arguments)]
fn build_config(
    landlock: Vec<String>,
    loopback_enabled: bool,
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
    timeout_max: Option<u64>,
) -> anyhow::Result<SandboxConfig> {
    let rules = landlock
        .iter()
        .map(|s| parse_landlock_spec(s))
        .collect::<anyhow::Result<Vec<_>>>()?;

    // --unshare-pid 在非 root 下需要 user ns 来获取 CAP_SYS_ADMIN
    let pid_without_user = unshare_pid && !unshare_all && !unshare_user;
    let need_user_for_pid = pid_without_user && unsafe { libc::geteuid() } != 0;
    let effective_user = unshare_user || unshare_all || need_user_for_pid;

    Ok(SandboxConfig {
        landlock: rules,
        namespaces: NamespacesConfig {
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
        },
        network: sandbox_runtime::config::NetworkConfig {
            loopback: loopback_enabled,
        },
        timeout_default_secs: 30,
        timeout_max_secs: timeout_max.unwrap_or(300),
        seccomp_deny_nrs: vec![],
        seccomp_filter_bytes: vec![],
    })
}
