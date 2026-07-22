//! sandbox-runtime 的核心类型与 trait。
//!
//! 本模块定义平台无关的抽象：
//! - [`SandboxImpl`] trait（沙箱后端的主要抽象，非 pub）
//! - [`Sandbox`] struct（公开的沙箱包装器）
//! - [`LandlockPerm`]、[`LandlockRule`]、[`DenyMechanism`]、[`ExitReason`]
//! - 命令规格：[`CommandSpec`]、[`CommandOutput`]

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

pub mod config;

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
            "sandbox-runtime requires Linux; \
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

/// 在沙箱内运行的完整命令规格。
///
/// 这是 [`Sandbox::execute`] 的输入。
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
    pub timeout: Duration,
}

// ---------------------------------------------------------------------------
// CommandOutput
// ---------------------------------------------------------------------------

/// 执行沙箱化命令的结果。
#[derive(Debug, Clone)]
pub struct CommandOutput {
    /// 命令的退出码。
    pub exit_code: i32,
    /// 若子进程被 seccomp 黑名单命中后被 SIGSYS 杀死，
    /// 从 `/proc/<pid>/syscall` post-mortem 读取到的
    /// `(syscall_nr, arch)`。`None` 表示未被拦截或读取失败。
    pub blocked_syscall: Option<(u32, u32)>,
}

// ---------------------------------------------------------------------------
// SandboxImpl trait（内部，非 pub）
// ---------------------------------------------------------------------------

/// 与平台无关的沙箱抽象（内部 trait）。
///
/// 各实现使用目标平台上可用的内核机制来提供文件系统隔离与系统调用过滤
///（例如 Linux 上的 Landlock + seccomp、macOS 上的 Seatbelt）。
trait SandboxImpl: Send + Sync {
    /// 在沙箱限制下执行命令，并返回其输出。
    fn execute(&self, spec: &CommandSpec) -> anyhow::Result<CommandOutput>;

    /// 将已完成命令的退出码归类为一个 [`ExitReason`]，
    /// 区分沙箱拒绝（Landlock、seccomp 等）、正常程序退出与内部错误。
    ///
    /// `blocked` 仅在 seccomp 命中黑名单（子进程被 SIGSYS 杀死）时有值，
    /// 由实现从 `/proc/<pid>/syscall` post-mortem 读取。
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
        let effective_user = ns.pid && !ns.user && unsafe { libc::geteuid() } != 0;
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

    /// 执行命令，返回 `(CommandOutput, ExitReason)`。
    pub fn execute(&self, spec: &CommandSpec) -> anyhow::Result<(CommandOutput, ExitReason)> {
        let output = self.inner.execute(spec)?;
        let reason = self
            .inner
            .classify_exit(output.exit_code, output.blocked_syscall);
        Ok((output, reason))
    }

    /// 直接对给定的退出码和 blocked 信息进行分类（委托给内部实现）。
    pub fn classify_exit(&self, exit_code: i32, blocked: Option<(u32, u32)>) -> ExitReason {
        self.inner.classify_exit(exit_code, blocked)
    }
}
