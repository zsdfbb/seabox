use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;

use seabox::config::{parse_landlock_spec, NamespacesConfig, SandboxConfig};
use seabox::{CommandSpec, ExitReason, Sandbox};

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
#[command(
    name = "seabox",
    about = "Landlock + seccomp + namespace 沙箱",
    long_about = "\
为 AI Agent 设计的跨平台 OS 级沙箱。\
 在 OS 层面强制施加文件系统与进程限制，无需容器运行时。\
 当前支持 Linux（Landlock + seccomp + namespaces），macOS 计划中。

核心理念：Agent 每次执行命令都应默认受限。\
 配置一次策略，Agent 自动遵守。
"
)]
#[allow(clippy::large_enum_variant)]
enum Cli {
    /// 在沙箱内运行一条命令
    Run {
        /// Landlock 文件系统 ACL，格式 `path:perm`（可重复）
        ///
        /// 权限预设：ro（只读读执行）/ rw（读写）/ rwx（完全读写+设备创建）/ all（全部）
        /// 示例：--landlock '/:ro' --landlock '/tmp:rw'
        #[arg(long, value_name = "PATH:PERM")]
        landlock: Vec<String>,

        /// 在隔离 netns 中放通 loopback 网络
        ///
        /// 与 --unshare-net 正交组合：不加 --unshare-net 时无效果（主机网络已可用）；
        /// 加 --unshare-net 时放通 lo 接口（127.0.0.1/8）
        #[arg(short = 'n', long)]
        allow_network: bool,

        /// 共享宿主机网络（bwrap 兼容别名）
        ///
        /// 优先级最高：抑制 --unshare-net 的隔离效果。
        /// 与 --allow-network 不同——后者在 --unshare-net 时放通 loopback，不抑制隔离。
        #[arg(long)]
        share_net: bool,

        /// 启用调试输出
        #[arg(short = 'd', long)]
        debug: bool,

        /// 隔离全部 7 种命名空间（user/ipc/mnt/pid/net/uts/cgroup）
        ///
        /// 非 root 下自动启用 user namespace。
        #[arg(long)]
        unshare_all: bool,

        /// 隔离 user 命名空间
        ///
        /// 子进程拥有独立的 UID/GID 映射，ns 内无特权。
        /// 非 root 下是 pid/net namespace 的前置依赖。
        #[arg(long)]
        unshare_user: bool,
        /// 隔离 IPC 命名空间
        ///
        /// 子进程拥有独立的 System V IPC 和 POSIX 消息队列，
        /// 无法与宿主机或其他容器通信。
        #[arg(long)]
        unshare_ipc: bool,
        /// 隔离 mount 命名空间
        ///
        /// 子进程拥有独立的挂载表，配合 --bind/--ro-bind/--tmpfs 使用。
        /// 非 root 下需配合 --unshare-user。
        #[arg(long)]
        unshare_mnt: bool,
        /// 隔离 PID 命名空间
        ///
        /// 子进程无法看到宿主机进程；自身为 PID 1（实际为 reaper）。
        /// 非 root 下自动启用 user namespace。
        #[arg(long)]
        unshare_pid: bool,
        /// 隔离网络命名空间
        ///
        /// 子进程拥有独立的网络栈（默认 lo DOWN，无网络访问）。
        /// 配合 --allow-network 可放通 loopback。
        /// 非 root 下自动启用 user namespace。
        #[arg(long)]
        unshare_net: bool,
        /// 隔离 UTS 命名空间
        ///
        /// 子进程拥有独立的 hostname/domainname。
        /// 配合 --hostname 可自定义主机名。
        #[arg(long)]
        unshare_uts: bool,
        /// 隔离 cgroup 命名空间
        ///
        /// 子进程拥有独立的 cgroup 层次结构视图。
        #[arg(long)]
        unshare_cgroup: bool,

        /// 软性 user 命名空间（内核不支持时静默回退）
        #[arg(long)]
        unshare_user_try: bool,
        /// 软性 cgroup 命名空间（内核不支持时静默回退）
        #[arg(long)]
        unshare_cgroup_try: bool,

        /// 在 user 命名空间中映射的 uid（需 --unshare-user）
        #[arg(long)]
        uid: Option<u32>,
        /// 在 user 命名空间中映射的 gid（需 --unshare-user）
        #[arg(long)]
        gid: Option<u32>,
        /// 在 UTS 命名空间中设置 hostname（需 --unshare-uts）
        #[arg(long, value_name = "NAME")]
        hostname: Option<String>,

        /// 覆盖工作目录（而非继承父进程 cwd）
        #[arg(long, value_name = "DIR")]
        chdir: Option<PathBuf>,

        /// 设置或覆盖环境变量，格式 KEY=VALUE（可重复）
        #[arg(long, value_name = "KEY=VALUE", value_parser = parse_env_var)]
        env: Vec<(String, String)>,

        /// 删除环境变量（可重复）
        #[arg(long, value_name = "KEY")]
        unsetenv: Vec<String>,

        /// 命令超时秒数（默认 30，不超过 --timeout-max）
        #[arg(long)]
        timeout: Option<u64>,

        /// 命令超时上限秒数（影响默认值上限）
        #[arg(long)]
        timeout_max: Option<u64>,

        /// 清空环境变量（不从父进程继承任何环境变量）
        #[arg(long)]
        clearenv: bool,

        /// 可写递归 bind mount，格式 `--bind SRC DST`（可重复）
        ///
        /// 将宿主机路径 SRC 以可写方式挂载到容器内路径 DST。
        /// 非 root 下需配合 --unshare-user。
        #[arg(long, value_names = ["SRC", "DST"], num_args = 2)]
        bind: Vec<String>,

        /// 只读递归 bind mount，格式 `--ro-bind SRC DST`（可重复）
        ///
        /// 将宿主机路径 SRC 以只读方式挂载到容器内路径 DST。
        /// 非 root 下需配合 --unshare-user。
        #[arg(long, value_names = ["SRC", "DST"], num_args = 2)]
        ro_bind: Vec<String>,

        /// 挂载 tmpfs 到指定路径，格式 `--tmpfs DST`（可重复）
        ///
        /// 在容器内 DST 处创建一个空的内存文件系统。
        /// 非 root 下需配合 --unshare-user。
        #[arg(long, value_names = ["DST"])]
        tmpfs: Vec<String>,

        /// 通过 USER_NOTIF 拦截指定 syscall 号（可重复）
        ///
        /// 示例：--seccomp-deny-nr 165（拦截 mount）
        ///        --seccomp-deny-nr 165 --seccomp-deny-nr 97（拦截 mount + unshare）
        /// 常见 syscall 号（x86_64）：165=mount, 97=unshare, 173=ptrace
        #[arg(long, value_name = "NR")]
        seccomp_deny_nr: Vec<u32>,

        /// 从文件描述符读取外部原始 cBPF filter（可重复）
        ///
        /// 从指定 fd 读取原始 cBPF 字节码并追加到 seccomp filter 链。
        /// 字节序必须匹配宿主机的 sock_filter 布局。
        #[arg(long, value_name = "FD")]
        seccomp_filter_fd: Vec<std::os::unix::io::RawFd>,

        /// 要执行的命令（使用 `--` 分隔选项与命令）
        ///
        /// 示例：seabox run --landlock '/:ro' -- ls -la
        ///        seabox run --unshare-all -- sh -c 'echo hello'
        /// 注意：本工具直接 execve 目标程序，不解释 shell 元字符 (>, |, &&)。
        /// 需要 shell 语法时显式调用 sh -c。
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// 检查当前系统可用的沙箱能力
    ///
    /// 显示 Landlock ABI 版本、seccomp 可用性、以及 7 种 namespace
    /// 在当前内核上的支持情况。
    Check,

    /// 启动 HTTP API 服务器（尚未实现）
    Serve {
        /// 服务器监听端口
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
            unshare_mnt,
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
            ref bind,
            ref ro_bind,
            ref tmpfs,
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
            unshare_mnt,
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
            bind,
            ro_bind,
            tmpfs,
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
    unshare_mnt: bool,
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
    bind: &[String],
    ro_bind: &[String],
    tmpfs: &[String],
    seccomp_deny_nrs: Vec<u32>,
    seccomp_filter_fds: Vec<std::os::unix::io::RawFd>,
    timeout: Option<u64>,
    timeout_max: Option<u64>,
) -> anyhow::Result<()> {
    if command.is_empty() {
        anyhow::bail!(
            "error: no command specified.\n\
             Usage: seabox run [OPTIONS] <COMMAND>...\n\
             For example: seabox run ls -la"
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

    let (effective_net, effective_network) =
        resolve_network_config(unshare_net, share_net, allow_network, unshare_all);

    let mut config = build_config(
        landlock,
        effective_network,
        unshare_all,
        unshare_user,
        unshare_ipc,
        unshare_mnt,
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

    // --bind / --ro-bind / --tmpfs: 添加 mount 规格
    for pair in bind.chunks(2) {
        if pair.len() == 2 {
            config = config.with_bind(&pair[0], &pair[1]);
        }
    }
    for pair in ro_bind.chunks(2) {
        if pair.len() == 2 {
            config = config.with_ro_bind(&pair[0], &pair[1]);
        }
    }
    for target in tmpfs {
        config = config.with_tmpfs(target);
    }

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

// ---------------------------------------------------------------------------
// 配置辅助函数
// ---------------------------------------------------------------------------

/// 解析网络标志冲突，返回 (是否隔离 netns, 是否放通 loopback)。
///
/// - `--share-net` 强制共享宿主机网络（bwrap 兼容别名），抑制 netns 隔离。
/// - `--allow-network` 只放通 loopback：配合 `--unshare-net` 时在隔离 netns 内
///   lo UP（127.0.0.1/8）；不隔离时对宿主机网络无效果。
/// - 两者相互正交，互不抑制。
fn resolve_network_config(
    unshare_net: bool,
    share_net: bool,
    allow_network: bool,
    unshare_all: bool,
) -> (bool, bool) {
    let effective_net = !share_net && (unshare_net || unshare_all);
    let effective_loopback = allow_network;
    (effective_net, effective_loopback)
}

#[allow(clippy::too_many_arguments)]
fn build_config(
    landlock: Vec<String>,
    loopback_enabled: bool,
    // namespace flags
    unshare_all: bool,
    unshare_user: bool,
    unshare_ipc: bool,
    unshare_mnt: bool,
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

    // --unshare-pid / --unshare-net 在非 root 下需要 user ns 来获取 CAP_SYS_ADMIN
    let pid_without_user = unshare_pid && !unshare_all && !unshare_user;
    let need_user_for_pid = pid_without_user && unsafe { libc::geteuid() } != 0;
    let net_without_user = unshare_net && !unshare_all && !unshare_user;
    let need_user_for_net = net_without_user && unsafe { libc::geteuid() } != 0;
    let effective_user = unshare_user || unshare_all || need_user_for_pid || need_user_for_net;

    Ok(SandboxConfig {
        landlock: rules,
        namespaces: NamespacesConfig {
            user: effective_user,
            ipc: unshare_ipc || unshare_all,
            mnt: unshare_mnt || unshare_all,
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
        network: seabox::config::NetworkConfig {
            loopback: loopback_enabled,
        },
        mount: seabox::config::MountConfig::default(),
        timeout_default_secs: 30,
        timeout_max_secs: timeout_max.unwrap_or(300),
        seccomp_deny_nrs: vec![],
        seccomp_filter_bytes: vec![],
    })
}

#[cfg(test)]
mod tests {
    use super::resolve_network_config;

    #[test]
    fn default_no_network_flags() {
        assert_eq!(
            resolve_network_config(false, false, false, false),
            (false, false)
        );
    }

    #[test]
    fn unshare_net_isolates() {
        assert_eq!(
            resolve_network_config(true, false, false, false),
            (true, false)
        );
    }

    #[test]
    fn allow_network_is_orthogonal_to_unshare_net() {
        // 核心修复：--unshare-net --allow-network → 隔离 netns + lo UP
        assert_eq!(
            resolve_network_config(true, false, true, false),
            (true, true)
        );
    }

    #[test]
    fn allow_network_alone_does_not_isolate() {
        assert_eq!(
            resolve_network_config(false, false, true, false),
            (false, true)
        );
    }

    #[test]
    fn share_net_suppresses_unshare_net() {
        assert_eq!(
            resolve_network_config(true, true, false, false),
            (false, false)
        );
    }

    #[test]
    fn share_net_beats_allow_network_for_isolation() {
        // share-net 抑制隔离；allow-network 仍设 loopback 标志（无 netns 时无效）
        assert_eq!(
            resolve_network_config(true, true, true, false),
            (false, true)
        );
    }

    #[test]
    fn unshare_all_isolates_net() {
        assert_eq!(
            resolve_network_config(false, false, false, true),
            (true, false)
        );
    }

    #[test]
    fn unshare_all_with_allow_network_loopback() {
        assert_eq!(
            resolve_network_config(false, false, true, true),
            (true, true)
        );
    }
}
