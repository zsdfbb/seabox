//! seabox 的核心类型与 trait。
//!
//! 本模块定义平台无关的抽象：
//! - [`SandboxImpl`] trait（沙箱后端的主要抽象，非 pub）
//! - [`Sandbox`] struct（公开的沙箱包装器）
//! - [`LandlockPerm`]、[`LandlockRule`]、[`DenyMechanism`]、[`ExitReason`]
//! - 命令规格：[`CommandSpec`]、[`CommandOutput`]

use std::collections::HashMap;
use std::io;
#[cfg(unix)]
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::process::ExitStatus;
use std::time::Duration;

pub mod child;
#[cfg(feature = "cli")]
pub mod cli;
pub mod config;
pub mod profile;

pub use config::{CapOp, Capability, CapabilityConfig, SandboxConfig};

#[cfg(target_os = "linux")]
pub mod linux;

// ---------------------------------------------------------------------------
// LandlockPerm + LandlockRule
// ---------------------------------------------------------------------------

/// Landlock 路径权限，对应内核 `AccessFs` 的个体权限。
///
/// 预设组合（如 `ro`、`rw`、`rwx`、`all`）在 CLI 层通过
/// [`expand_perm`](crate::config::expand_perm) 展开，不在此枚举中。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LandlockPerm {
    Execute,
    ReadFile,
    ReadDir,
    WriteFile,
    RemoveDir,
    RemoveFile,
    MakeChar,
    MakeDir,
    MakeReg,
    MakeSock,
    MakeFifo,
    MakeBlock,
    MakeSym,
    Refer,
    Truncate,
    IoctlDev,
}

impl std::str::FromStr for LandlockPerm {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "execute" => Ok(LandlockPerm::Execute),
            "read-file" => Ok(LandlockPerm::ReadFile),
            "read-dir" => Ok(LandlockPerm::ReadDir),
            "write-file" => Ok(LandlockPerm::WriteFile),
            "remove-dir" => Ok(LandlockPerm::RemoveDir),
            "remove-file" => Ok(LandlockPerm::RemoveFile),
            "make-char" => Ok(LandlockPerm::MakeChar),
            "make-dir" => Ok(LandlockPerm::MakeDir),
            "make-reg" => Ok(LandlockPerm::MakeReg),
            "make-sock" => Ok(LandlockPerm::MakeSock),
            "make-fifo" => Ok(LandlockPerm::MakeFifo),
            "make-block" => Ok(LandlockPerm::MakeBlock),
            "make-sym" => Ok(LandlockPerm::MakeSym),
            "refer" => Ok(LandlockPerm::Refer),
            "truncate" => Ok(LandlockPerm::Truncate),
            "ioctl-dev" => Ok(LandlockPerm::IoctlDev),
            _ => anyhow::bail!("unknown landlock perm '{s}'"),
        }
    }
}

/// 一条 Landlock 规则：路径 + 权限列表。
#[derive(Debug, Clone)]
pub struct LandlockRule {
    pub path: PathBuf,
    pub perms: Vec<LandlockPerm>,
}

// ---------------------------------------------------------------------------
// NamespaceType
// ---------------------------------------------------------------------------

/// Linux 命名空间类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NamespaceType {
    User,
    Ipc,
    Pid,
    Net,
    Uts,
    Cgroup,
}

impl std::fmt::Display for NamespaceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::User => write!(f, "user"),
            Self::Ipc => write!(f, "ipc"),
            Self::Pid => write!(f, "pid"),
            Self::Net => write!(f, "net"),
            Self::Uts => write!(f, "uts"),
            Self::Cgroup => write!(f, "cgroup"),
        }
    }
}

// ---------------------------------------------------------------------------
// DenyMechanism
// ---------------------------------------------------------------------------

/// 拒绝沙箱化操作的内核机制。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyMechanism {
    /// 由 Landlock（文件系统 ACL）拒绝。
    Landlock,
    /// 由 seccomp（系统调用过滤）拒绝。
    Seccomp,
    /// 未知或无法识别的机制。
    Unknown,
}

// ---------------------------------------------------------------------------
// ExitReason
// ---------------------------------------------------------------------------

/// 对沙箱化命令退出状态的分类。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitReason {
    /// 命令正常退出（退出码 0）。
    Ok,
    /// 命令被沙箱机制拒绝。
    Denied {
        /// 触发拒绝的机制。
        mechanism: DenyMechanism,
        /// 内核或运行时产生的诊断信息。
        message: String,
    },
    /// 命令以非零退出码退出（与沙箱无关）。
    Program(i32),
    /// 发生了内部错误（如超时、I/O 错误）。
    InternalError(String),
}

impl ExitReason {
    /// 若命令被沙箱拒绝则返回 `true`。
    pub fn is_denied(&self) -> bool {
        matches!(self, Self::Denied { .. })
    }

    /// 若命令成功退出则返回 `true`。
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Ok)
    }
}

// ---------------------------------------------------------------------------
// 平台工厂
// ---------------------------------------------------------------------------

fn create_sandbox_impl(config: config::SandboxConfig) -> anyhow::Result<Box<dyn SandboxImpl>> {
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(linux::LinuxSandbox { config }))
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = config;
        anyhow::bail!(
            "seabox requires Linux; \
             the current platform is not supported"
        );
    }
}

/// 检查当前系统的沙箱能力，返回格式化诊断文本。
///
/// Linux:   Landlock ABI、Seccomp、6 种 namespace 可用性
/// macOS:   全部标记为 not available
pub fn check_capabilities() -> String {
    #[cfg(target_os = "linux")]
    {
        let landlock = if linux::landlock::is_available() {
            format!(
                "available (ABI v{})",
                linux::landlock::get_abi_version().unwrap_or(0)
            )
        } else {
            "not available".to_string()
        };
        let seccomp = if linux::seccomp::is_available() {
            "available"
        } else {
            "not available"
        };
        let user_ns = if linux::namespaces::is_user_namespace_available() {
            "available"
        } else {
            "not available"
        };
        let ipc_ns = if linux::namespaces::is_ipc_namespace_available() {
            "available"
        } else {
            "not available"
        };
        let pid_ns = if linux::namespaces::is_pid_namespace_available() {
            "available"
        } else {
            "not available"
        };
        let net_ns = if linux::namespaces::is_net_namespace_available() {
            "available"
        } else {
            "not available"
        };
        let uts_ns = if linux::namespaces::is_uts_namespace_available() {
            "available"
        } else {
            "not available"
        };
        let cgroup_ns = if linux::namespaces::is_cgroup_namespace_available() {
            "available"
        } else {
            "not available"
        };

        format!(
            "Capability                    Status\n\
             ----------------------------- --------------------\n\
             Landlock                      {landlock}\n\
             Seccomp                       {seccomp}\n\
             User namespace                {user_ns}\n\
             IPC namespace                 {ipc_ns}\n\
             PID namespace                 {pid_ns}\n\
             Network namespace             {net_ns}\n\
             UTS namespace                 {uts_ns}\n\
             Cgroup namespace              {cgroup_ns}\n"
        )
    }

    #[cfg(not(target_os = "linux"))]
    {
        format!(
            "Capability                    Status\n\
             ----------------------------- --------------------\n\
             Landlock                      not available (non-Linux)\n\
             Seccomp                       not available (non-Linux)\n\
             User namespace                not available (non-Linux)\n\
             IPC namespace                 not available (non-Linux)\n\
             PID namespace                 not available (non-Linux)\n\
             Network namespace             not available (non-Linux)\n\
             UTS namespace                 not available (non-Linux)\n\
             Cgroup namespace              not available (non-Linux)\n"
        )
    }
}

// ---------------------------------------------------------------------------
// StdioConfig
// ---------------------------------------------------------------------------

/// 子进程标准流配置。恰好覆盖 CodeWhale 三条执行路径。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdioConfig {
    /// 继承父进程的 0/1/2，零额外 fd。
    Inherit,
    /// 内部 pipe；通过 `SandboxChild::take_stdout` / `take_stderr` / `take_stdin` 取出。
    Piped,
    /// 预开 fd → dup2；`-1` 表示不修改对应标准流。
    Fd {
        stdin: i32,
        stdout: i32,
        stderr: i32,
    },
}

// ---------------------------------------------------------------------------
// CommandSpec
// ---------------------------------------------------------------------------

/// 在沙箱内运行的完整命令规格。
///
/// 这是 [`Sandbox::execute`] 的输入。
///
/// 可通过 `with_*` 链式方法配置：
///
/// ```
/// use seabox::CommandSpec;
///
/// let spec = CommandSpec::default()
///     .with_program("sh")
///     .with_args(["-c", "echo $FOO"])
///     .with_clearenv()
///     .with_env("FOO", "bar");
/// assert_eq!(spec.env.get("FOO"), Some(&"bar".into()));
/// assert_eq!(spec.env.len(), 1);
/// ```
#[derive(Debug, Clone)]
pub struct CommandSpec {
    /// 要执行的程序（路径或通过 `PATH` 解析的名称）。
    pub program: String,
    /// 传递给程序的参数（不包含程序名本身）。
    pub args: Vec<String>,
    /// 命令的工作目录。
    pub cwd: PathBuf,
    /// 命令使用的环境变量。
    pub env: HashMap<String, String>,
    /// 命令在被杀死前的最大运行时间（wall-clock）。
    ///
    /// `None` 表示不强制超时（库默认，向后兼容）；CLI 显式传 `Some(...)`。
    pub timeout: Option<Duration>,
    /// 同步便捷 stdin 数据（`execute` 内部写入；`spawn` 忽略）。
    /// `None` 表示不写 stdin，子进程读端立即 EOF。
    pub stdin: Option<Vec<u8>>,
}

impl Default for CommandSpec {
    fn default() -> Self {
        Self {
            program: String::new(),
            args: Vec::new(),
            cwd: PathBuf::from("/"),
            env: HashMap::new(),
            timeout: None,
            stdin: None,
        }
    }
}

impl CommandSpec {
    /// 设置要执行的程序。
    pub fn with_program(mut self, program: impl Into<String>) -> Self {
        self.program = program.into();
        self
    }

    /// 设置传递给程序的参数（不包含程序名本身）。
    pub fn with_args(mut self, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    /// 设置工作目录。
    pub fn with_cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
        self.cwd = cwd.into();
        self
    }

    /// 设置超时时间。`Some(d)` 表示 `d` 后强制杀死命令。
    ///
    /// 对应 CLI 的 `--timeout`。
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// 清除超时（`timeout = None`），命令可无限运行。
    pub fn with_no_timeout(mut self) -> Self {
        self.timeout = None;
        self
    }

    /// 设置同步便捷 stdin 数据（`execute` 内部写入；`spawn` 忽略）。
    pub fn with_stdin(mut self, data: impl Into<Vec<u8>>) -> Self {
        self.stdin = Some(data.into());
        self
    }

    /// 清空所有环境变量。
    pub fn with_clearenv(mut self) -> Self {
        self.env.clear();
        self
    }

    /// 设置（或覆盖）一个环境变量。
    ///
    /// 对应 CLI 的 `--env KEY=VALUE`。
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    /// 移除一个环境变量。
    ///
    /// 对应 CLI 的 `--unsetenv KEY`。
    pub fn with_unsetenv(mut self, key: impl Into<String>) -> Self {
        self.env.remove(&key.into());
        self
    }
}

// ---------------------------------------------------------------------------
// CommandOutput
// ---------------------------------------------------------------------------

/// 执行沙箱化命令的结果。
#[derive(Debug, Clone)]
pub struct CommandOutput {
    /// 命令的退出码。
    ///
    /// 约定：正常退出为 0..255；被信号杀死时为 `128 + signal`（D-A1，保持 `i32`）。
    pub exit_code: i32,
    /// 若黑名单 syscall 被 seccomp USER_NOTIF 拦截，由 worker 线程
    /// 通过 listener fd 上报的 `(syscall_nr, arch)`。
    /// `None` 表示未被拦截。
    pub blocked_syscall: Option<(u32, u32)>,
    /// 命令 stdout 的全部内容（`execute` 捕获）。
    pub stdout: Vec<u8>,
    /// 命令 stderr 的全部内容（`execute` 捕获）。
    pub stderr: Vec<u8>,
    /// 命令是否因超时被强制杀死。
    pub timed_out: bool,
}

// ---------------------------------------------------------------------------
// SandboxChild + SandboxChildImpl
// ---------------------------------------------------------------------------

/// 平台无关的沙箱子进程句柄。刻意镜像 `std::process::Child`。
///
/// 通过 [`Sandbox::spawn`] 获得。所有方法透传内部实现
/// （`SandboxChildImpl`，bin crate 访问不到其 trait 方法，故在此暴露公开 wrapper）。
pub struct SandboxChild {
    inner: Box<dyn SandboxChildImpl>,
}

impl SandboxChild {
    /// 非阻塞收割（`WNOHANG`）。已收割后幂等返回缓存状态。
    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.inner.try_wait()
    }

    /// 阻塞收割至进程退出。
    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        self.inner.wait()
    }

    /// 有界等待 `d`；到期强制 `kill()` + 收割后返回已退出状态（超时被强杀为 137），
    /// 是否超时用 [`timed_out`](Self::timed_out) 查询。
    pub fn wait_timeout(&mut self, d: Duration) -> io::Result<ExitStatus> {
        self.inner.wait_timeout(d)
    }

    /// 杀死进程（`process_group` 时 `kill(-pgid)`，否则 `kill(pid)`）。ESRCH 视为 Ok。
    pub fn kill(&mut self) -> io::Result<()> {
        self.inner.kill()
    }

    /// business 进程在宿主命名空间的 pid（= kill 目标）。
    pub fn id(&self) -> u32 {
        self.inner.id()
    }

    /// 取出 stdout 读端 fd（`Piped` 时）。
    #[cfg(unix)]
    pub fn take_stdout(&mut self) -> Option<OwnedFd> {
        self.inner.take_stdout()
    }

    /// 取出 stderr 读端 fd（`Piped` 时）。
    #[cfg(unix)]
    pub fn take_stderr(&mut self) -> Option<OwnedFd> {
        self.inner.take_stderr()
    }

    /// 取出 stdin 写端 fd（`Piped` 时）。
    #[cfg(unix)]
    pub fn take_stdin(&mut self) -> Option<OwnedFd> {
        self.inner.take_stdin()
    }

    /// 若黑名单 syscall 被 seccomp USER_NOTIF 拦截，返回 `(syscall_nr, arch)`。
    pub fn blocked(&self) -> Option<(u32, u32)> {
        self.inner.blocked()
    }

    /// 进程是否因超时被强制杀死。
    pub fn timed_out(&self) -> bool {
        self.inner.timed_out()
    }
}

/// 沙箱子进程句柄的后端抽象（内部 trait，与 [`SandboxImpl`] 同构，
/// 为 macOS Phase 3 提供扩展点）。
pub(crate) trait SandboxChildImpl: Send {
    /// 非阻塞收割（WNOHANG）；已收割后幂等返回缓存。
    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>>;
    /// 阻塞收割至进程退出。
    fn wait(&mut self) -> io::Result<ExitStatus>;
    /// 有界等待 `d`；到期强制 kill + reap 后返回已退出状态（超时被强杀为 137），
    /// 是否超时用 [`timed_out`](Self::timed_out) 查询。
    fn wait_timeout(&mut self, d: Duration) -> io::Result<ExitStatus>;
    /// 杀死进程（`process_group` 时 `kill(-pgid)`，否则 `kill(pid)`）。
    fn kill(&mut self) -> io::Result<()>;
    /// business 进程在宿主命名空间的 pid（= kill 目标）。
    fn id(&self) -> u32;
    /// 取出 stdout 读端 fd（`Piped` 时）。
    #[cfg(unix)]
    fn take_stdout(&mut self) -> Option<OwnedFd>;
    /// 取出 stderr 读端 fd（`Piped` 时）。
    #[cfg(unix)]
    fn take_stderr(&mut self) -> Option<OwnedFd>;
    /// 取出 stdin 写端 fd（`Piped` 时）。
    #[cfg(unix)]
    fn take_stdin(&mut self) -> Option<OwnedFd>;
    /// 若黑名单 syscall 被 seccomp USER_NOTIF 拦截，返回 `(syscall_nr, arch)`。
    fn blocked(&self) -> Option<(u32, u32)>;
    /// 进程是否因超时被强制杀死。
    fn timed_out(&self) -> bool;
}

// ---------------------------------------------------------------------------
// SandboxImpl trait（内部，非 pub）
// ---------------------------------------------------------------------------

/// 与平台无关的沙箱抽象（内部 trait）。
///
/// 各实现使用目标平台上可用的内核机制来提供文件系统隔离与系统调用过滤
///（例如 Linux 上的 Landlock + seccomp、macOS 上的 Seatbelt）。
trait SandboxImpl: Send + Sync {
    /// 在沙箱限制下启动命令，返回活句柄（非阻塞）。
    fn spawn(&self, spec: &CommandSpec, stdio: StdioConfig) -> anyhow::Result<SandboxChild>;

    /// 在沙箱限制下执行命令并捕获全部输出（阻塞至退出）。
    ///
    /// 默认实现：`spawn(Piped)` 后委托 [`crate::child::run_to_output`]
    ///（平台无关的 drain + 超时 + kill 组合，写一次）。
    fn execute(&self, spec: &CommandSpec) -> anyhow::Result<CommandOutput> {
        crate::child::run_to_output(self.spawn(spec, StdioConfig::Piped)?, spec)
    }

    /// 将已完成命令的退出码归类为一个 [`ExitReason`]，
    /// 区分沙箱拒绝（Landlock、seccomp 等）、正常程序退出与内部错误。
    ///
    /// `blocked` 仅在 seccomp 黑名单被 USER_NOTIF 拦截时有值，
    /// 由实现从 worker 线程上报的 listener fd 读取 `(nr, arch)`。
    fn classify_exit(&self, exit_code: i32, blocked: Option<(u32, u32)>) -> ExitReason;
}

// ---------------------------------------------------------------------------
// Sandbox struct（公开 API）
// ---------------------------------------------------------------------------

/// 公开的沙箱包装器。
///
/// 持有配置与内部实现，提供 `execute` 方法返回 `(CommandOutput, ExitReason)`。
pub struct Sandbox {
    pub config: config::SandboxConfig,
    inner: Box<dyn SandboxImpl>,
}

impl Sandbox {
    /// 从已有配置创建沙箱。
    ///
    /// 自动处理 PID ns 与 user ns 的依赖关系：
    /// 非 root 下 `pid` 隐式启用 `user` 命名空间。
    pub fn from_config(config: config::SandboxConfig) -> anyhow::Result<Self> {
        let ns = &config.namespaces;
        // D2：--cap-add 需要 userns 承载新 cap（防 cap 回灌宿主命名空间），
        // 与 pid/net 自动叠加 userns 的模式一致。
        let effective_user = (ns.pid && !ns.user && unsafe { libc::geteuid() } != 0)
            || config.capabilities.has_add();
        let config = if effective_user {
            let mut c = config;
            c.namespaces.user = true;
            c
        } else {
            config
        };
        let inner = create_sandbox_impl(config.clone())?;
        Ok(Self { config, inner })
    }

    /// 启动命令并返回活句柄（非阻塞）。`stdio` 决定子进程 0/1/2 的接法。
    pub fn spawn(&self, spec: &CommandSpec, stdio: StdioConfig) -> anyhow::Result<SandboxChild> {
        self.inner.spawn(spec, stdio)
    }

    /// 执行命令，返回 `(CommandOutput, ExitReason)`。
    ///
    /// 捕获全部输出（`Piped`）；命令超时被强制杀死时 `reason` 为
    /// [`ExitReason::InternalError`]（`CommandOutput.timed_out` 消歧）。
    pub fn execute(&self, spec: &CommandSpec) -> anyhow::Result<(CommandOutput, ExitReason)> {
        let output = self.inner.execute(spec)?;
        let mut reason = self
            .inner
            .classify_exit(output.exit_code, output.blocked_syscall);
        if output.timed_out {
            reason = ExitReason::InternalError(format!(
                "command '{}' timed out (wall-clock deadline exceeded)",
                spec.program
            ));
        }
        Ok((output, reason))
    }

    /// 直接对给定的退出码和 blocked 信息进行分类（委托给内部实现）。
    pub fn classify_exit(&self, exit_code: i32, blocked: Option<(u32, u32)>) -> ExitReason {
        self.inner.classify_exit(exit_code, blocked)
    }
}
