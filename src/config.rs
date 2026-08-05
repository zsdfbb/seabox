//! 沙箱配置。
//!
//! 提供 [`SandboxConfig`]（可编程构造，支持链式 `with_*` 方法）、
//! [`NamespacesConfig`]（namespace 隔离设置），
//! 以及用于路径展开的 [`expand_tilde`]、权限展开的 [`expand_perm`]、
//! landlock 规格解析的 [`parse_landlock_spec`] 等工具函数。

use crate::{LandlockPerm, LandlockRule};

// mount(2) flags 数值（不依赖 libc，config 层不需要 libc）
const MS_BIND: u64 = 4096;
const MS_REC: u64 = 16384;
const MS_NOSUID: u64 = 2;
const MS_NODEV: u64 = 4;

// ---------------------------------------------------------------------------
// SandboxConfig
// ---------------------------------------------------------------------------

/// 完整的沙箱配置。
///
/// 可直接构造、通过 `Default::default()` 创建，或通过 `with_*` 链式方法配置。
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    pub landlock: Vec<LandlockRule>,
    pub namespaces: NamespacesConfig,
    pub network: NetworkConfig,
    pub mount: MountConfig,
    pub timeout_default_secs: u64,
    pub timeout_max_secs: u64,
    /// syscall 号列表，通过 USER_NOTIF 拦截（`--seccomp-deny-nr`）。
    pub seccomp_deny_nrs: Vec<u32>,
    /// 外部原始 cBPF 字节（`--seccomp-filter-fd`，从 fd 读取后存入）。
    pub seccomp_filter_bytes: Vec<Vec<u8>>,
    /// capability 权限操作（`--cap-add`/`--cap-drop`/`--cap-inherit`）。
    pub capabilities: CapabilityConfig,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            landlock: vec![],
            namespaces: NamespacesConfig::default(),
            network: NetworkConfig::default(),
            mount: MountConfig::default(),
            timeout_default_secs: 30,
            timeout_max_secs: 300,
            seccomp_deny_nrs: vec![],
            seccomp_filter_bytes: vec![],
            capabilities: CapabilityConfig::default(),
        }
    }
}

/// 网络配置。
///
/// 控制沙箱内的网络访问行为。
#[derive(Debug, Clone, Default)]
pub struct NetworkConfig {
    /// 在隔离 netns 中放通 loopback（lo UP + 127.0.0.1/8）。
    /// 仅在 `namespaces.net == true` 时生效。
    pub loopback: bool,
}

impl NetworkConfig {
    /// 启用或禁用 loopback 网络访问。
    pub fn with_loopback(mut self, enabled: bool) -> Self {
        self.loopback = enabled;
        self
    }
}

// ---------------------------------------------------------------------------
// MountSpec & MountConfig
// ---------------------------------------------------------------------------

/// 单条 mount 操作规格。
#[derive(Debug, Clone)]
pub struct MountSpec {
    /// 源路径（tmpfs 时为 None）。
    pub source: Option<String>,
    /// 挂载目标路径。
    pub target: String,
    /// 文件系统类型（"none" = bind mount, "tmpfs" = tmpfs）。
    pub fstype: String,
    /// mount(2) flags（MS_BIND, MS_REC, MS_RDONLY 等）。
    pub flags: u64,
    /// 可选 data 字符串（如 "size=1G"）。
    pub data: Option<String>,
    /// 是否只读（ro_bind 用，父进程据此展开为两条 RawMountOp）。
    pub readonly: bool,
}

impl MountSpec {
    /// 创建一条 bind mount 规格（读写）。
    pub fn bind(source: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            source: Some(source.into()),
            target: target.into(),
            fstype: "none".into(),
            flags: MS_BIND | MS_REC,
            data: None,
            readonly: false,
        }
    }

    /// 创建一条只读 bind mount 规格（ro_bind，父进程展开为 bind + readonly remount）。
    pub fn ro_bind(source: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            source: Some(source.into()),
            target: target.into(),
            fstype: "none".into(),
            flags: MS_BIND | MS_REC,
            data: None,
            readonly: true,
        }
    }

    /// 创建一条 tmpfs mount 规格。
    pub fn tmpfs(target: impl Into<String>) -> Self {
        Self {
            source: None,
            target: target.into(),
            fstype: "tmpfs".into(),
            flags: MS_NOSUID | MS_NODEV,
            data: None,
            readonly: false,
        }
    }
}

/// Mount 配置。
#[derive(Debug, Clone, Default)]
pub struct MountConfig {
    /// 明确要求 unshare mount ns（当 specs 为空时仍可设置）。
    pub enabled: bool,
    /// mount 操作列表。
    pub specs: Vec<MountSpec>,
}

impl SandboxConfig {
    /// 追加一条 landlock 规则（等价于 `--landlock path:perm`）。
    pub fn with_landlock(mut self, spec: &str) -> anyhow::Result<Self> {
        self.landlock
            .push(crate::config::parse_landlock_spec(spec)?);
        Ok(self)
    }

    /// 启用 user 命名空间隔离。
    pub fn with_unshare_user(mut self) -> Self {
        self.namespaces.user = true;
        self
    }

    /// 启用 IPC 命名空间隔离。
    pub fn with_unshare_ipc(mut self) -> Self {
        self.namespaces.ipc = true;
        self
    }

    /// 启用 PID 命名空间隔离。
    pub fn with_unshare_pid(mut self) -> Self {
        self.namespaces.pid = true;
        self
    }

    /// 启用网络命名空间隔离。
    pub fn with_unshare_net(mut self) -> Self {
        self.namespaces.net = true;
        self
    }

    /// 启用 UTS 命名空间隔离。
    pub fn with_unshare_uts(mut self) -> Self {
        self.namespaces.uts = true;
        self
    }

    /// 启用 cgroup 命名空间隔离。
    pub fn with_unshare_cgroup(mut self) -> Self {
        self.namespaces.cgroup = true;
        self
    }

    /// 启用全部命名空间隔离（user/ipc/mnt/pid/net/uts/cgroup）。
    pub fn with_unshare_all(mut self) -> Self {
        self.namespaces.user = true;
        self.namespaces.ipc = true;
        self.namespaces.mnt = true;
        self.namespaces.pid = true;
        self.namespaces.net = true;
        self.namespaces.uts = true;
        self.namespaces.cgroup = true;
        self
    }

    /// 在 user 命名空间中映射 uid。
    pub fn with_uid(mut self, uid: u32) -> Self {
        self.namespaces.uid = Some(uid);
        self
    }

    /// 在 user 命名空间中映射 gid。
    pub fn with_gid(mut self, gid: u32) -> Self {
        self.namespaces.gid = Some(gid);
        self
    }

    /// 在 UTS 命名空间中设置 hostname。
    pub fn with_hostname(mut self, name: impl Into<String>) -> Self {
        self.namespaces.hostname = Some(name.into());
        self
    }

    /// 启用或禁用网络访问（loopback 别名，兼容旧 API）。
    pub fn with_network(mut self, enabled: bool) -> Self {
        self.network.loopback = enabled;
        self
    }

    /// 启用 mount 命名空间隔离。
    pub fn with_unshare_mnt(mut self) -> Self {
        self.namespaces.mnt = true;
        self
    }

    /// 添加一条 bind mount 规格，并自动启用 mount 命名空间。
    pub fn with_bind(mut self, source: &str, target: &str) -> Self {
        self.mount.specs.push(MountSpec::bind(source, target));
        self.namespaces.mnt = true;
        self
    }

    /// 添加一条只读 bind mount 规格，并自动启用 mount 命名空间。
    pub fn with_ro_bind(mut self, source: &str, target: &str) -> Self {
        self.mount.specs.push(MountSpec::ro_bind(source, target));
        self.namespaces.mnt = true;
        self
    }

    /// 添加一条 tmpfs mount 规格，并自动启用 mount 命名空间。
    pub fn with_tmpfs(mut self, target: &str) -> Self {
        self.mount.specs.push(MountSpec::tmpfs(target));
        self.namespaces.mnt = true;
        self
    }

    /// 同时设置默认与最大超时（秒）。
    pub fn with_timeout(mut self, default_secs: u64, max_secs: u64) -> Self {
        self.timeout_default_secs = default_secs;
        self.timeout_max_secs = max_secs;
        self
    }

    /// 添加一个要通过 USER_NOTIF 拦截的 syscall 号（等价于 `--seccomp-deny-nr`）。
    pub fn with_seccomp_deny_nr(mut self, nr: u32) -> Self {
        self.seccomp_deny_nrs.push(nr);
        self
    }

    /// 添加一段外部原始 cBPF filter（等价于 `--seccomp-filter-fd`）。
    pub fn with_seccomp_filter(mut self, bytes: Vec<u8>) -> Self {
        self.seccomp_filter_bytes.push(bytes);
        self
    }

    /// 追加一条 cap 添加操作（等价于 `--cap-add name`）。
    ///
    /// 名称解析失败时返回错误（仿 [`Self::with_landlock`]）。
    pub fn with_cap_add(mut self, name: &str) -> anyhow::Result<Self> {
        self.capabilities.ops.push(CapOp::from_cli(name, true)?);
        Ok(self)
    }

    /// 追加一条 cap 丢弃操作（等价于 `--cap-drop name`）。
    ///
    /// 名称解析失败时返回错误。
    pub fn with_cap_drop(mut self, name: &str) -> anyhow::Result<Self> {
        self.capabilities.ops.push(CapOp::from_cli(name, false)?);
        Ok(self)
    }

    /// 追加"添加全部 cap"操作（等价于 `--cap-add ALL`）。
    pub fn with_cap_add_all(mut self) -> Self {
        self.capabilities.ops.push(CapOp::AddAll);
        self
    }

    /// 追加"丢弃全部 cap"操作（等价于 `--cap-drop ALL`）。
    pub fn with_cap_drop_all(mut self) -> Self {
        self.capabilities.ops.push(CapOp::DropAll);
        self
    }

    /// 设置是否继承当前进程 effective caps 作为起点（等价于 `--cap-inherit`）。
    ///
    /// 默认 `false`：从空集开始，仅显式添加的 cap 会进入。
    pub fn with_cap_inherit(mut self, inherit: bool) -> Self {
        self.capabilities.inherit_base = inherit;
        self
    }

    /// 创建沙箱实例（返回 [`crate::Sandbox`]）。
    pub fn into_sandbox(self) -> anyhow::Result<crate::Sandbox> {
        crate::Sandbox::from_config(self)
    }
}

// ---------------------------------------------------------------------------
// NamespacesConfig
// ---------------------------------------------------------------------------

/// Linux 命名空间隔离配置。
///
/// 控制哪些命名空间被 unshare(2) 隔离。
/// `user_try` / `cgroup_try` 是软性选项：若内核不支持则静默回退，不报错。
#[derive(Debug, Clone, Default)]
pub struct NamespacesConfig {
    /// 隔离 user 命名空间（需要 `CAP_SETUID`、`CAP_SETGID`）。
    pub user: bool,
    /// 隔离 IPC 命名空间。
    pub ipc: bool,
    /// 隔离 mount 命名空间。
    pub mnt: bool,
    /// 隔离 PID 命名空间。
    pub pid: bool,
    /// 隔离网络命名空间。
    pub net: bool,
    /// 隔离 UTS（hostname）命名空间。
    pub uts: bool,
    /// 隔离 cgroup 命名空间。
    pub cgroup: bool,
    /// 软性 user 命名空间（内核不支持时静默回退）。
    pub user_try: bool,
    /// 软性 cgroup 命名空间（内核不支持时静默回退）。
    pub cgroup_try: bool,
    /// 在 user 命名空间中映射的 uid（仅在 `user` 或 `user_try` 生效时使用）。
    pub uid: Option<u32>,
    /// 在 user 命名空间中映射的 gid（仅在 `user` 或 `user_try` 生效时使用）。
    pub gid: Option<u32>,
    /// 在 UTS 命名空间中设置的 hostname（仅在 `uts` 生效时使用）。
    pub hostname: Option<String>,
}

// ---------------------------------------------------------------------------
// Capability
// ---------------------------------------------------------------------------

/// Linux capability 编号（`u16` 新类型）。
///
/// 编号是稳定 ABI 常量（`uapi/linux/capability.h`），config 层不依赖 libc，
/// 与 `MS_*` mount 常量并列，属纯数据层。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Capability(u16);

impl Capability {
    // capability 编号来自 uapi/linux/capability.h；ABI 稳定，
    // 最高位 CHECKPOINT_RESTORE(40) 于 Linux 5.9 引入。
    pub const CHOWN: Capability = Capability(0);
    pub const DAC_OVERRIDE: Capability = Capability(1);
    pub const DAC_READ_SEARCH: Capability = Capability(2);
    pub const FOWNER: Capability = Capability(3);
    pub const FSETID: Capability = Capability(4);
    pub const KILL: Capability = Capability(5);
    pub const SETGID: Capability = Capability(6);
    pub const SETUID: Capability = Capability(7);
    pub const SETPCAP: Capability = Capability(8);
    pub const LINUX_IMMUTABLE: Capability = Capability(9);
    pub const NET_BIND_SERVICE: Capability = Capability(10);
    pub const NET_BROADCAST: Capability = Capability(11);
    pub const NET_ADMIN: Capability = Capability(12);
    pub const NET_RAW: Capability = Capability(13);
    pub const IPC_LOCK: Capability = Capability(14);
    pub const IPC_OWNER: Capability = Capability(15);
    pub const SYS_MODULE: Capability = Capability(16);
    pub const SYS_RAWIO: Capability = Capability(17);
    pub const SYS_CHROOT: Capability = Capability(18);
    pub const SYS_PTRACE: Capability = Capability(19);
    pub const SYS_PACCT: Capability = Capability(20);
    pub const SYS_ADMIN: Capability = Capability(21);
    pub const SYS_BOOT: Capability = Capability(22);
    pub const SYS_NICE: Capability = Capability(23);
    pub const SYS_RESOURCE: Capability = Capability(24);
    pub const SYS_TIME: Capability = Capability(25);
    pub const SYS_TTY_CONFIG: Capability = Capability(26);
    pub const MKNOD: Capability = Capability(27);
    pub const LEASE: Capability = Capability(28);
    pub const AUDIT_WRITE: Capability = Capability(29);
    pub const AUDIT_CONTROL: Capability = Capability(30);
    pub const SETFCAP: Capability = Capability(31);
    pub const MAC_OVERRIDE: Capability = Capability(32);
    pub const MAC_ADMIN: Capability = Capability(33);
    pub const SYSLOG: Capability = Capability(34);
    pub const WAKE_ALARM: Capability = Capability(35);
    pub const BLOCK_SUSPEND: Capability = Capability(36);
    pub const AUDIT_READ: Capability = Capability(37);
    pub const PERFMON: Capability = Capability(38);
    pub const BPF: Capability = Capability(39);
    pub const CHECKPOINT_RESTORE: Capability = Capability(40);

    /// 按名称解析 capability。
    ///
    /// 接受 `"CHOWN"` / `"cap_chown"` / `"cap.CHOWN"` 等大小写变体（转大写、
    /// 去 `CAP_`/`CAP.` 前缀后查表）；未知名称返回 `None`。
    pub fn from_name(name: &str) -> Option<Capability> {
        const TABLE: &[(&str, Capability)] = &[
            ("CHOWN", Capability::CHOWN),
            ("DAC_OVERRIDE", Capability::DAC_OVERRIDE),
            ("DAC_READ_SEARCH", Capability::DAC_READ_SEARCH),
            ("FOWNER", Capability::FOWNER),
            ("FSETID", Capability::FSETID),
            ("KILL", Capability::KILL),
            ("SETGID", Capability::SETGID),
            ("SETUID", Capability::SETUID),
            ("SETPCAP", Capability::SETPCAP),
            ("LINUX_IMMUTABLE", Capability::LINUX_IMMUTABLE),
            ("NET_BIND_SERVICE", Capability::NET_BIND_SERVICE),
            ("NET_BROADCAST", Capability::NET_BROADCAST),
            ("NET_ADMIN", Capability::NET_ADMIN),
            ("NET_RAW", Capability::NET_RAW),
            ("IPC_LOCK", Capability::IPC_LOCK),
            ("IPC_OWNER", Capability::IPC_OWNER),
            ("SYS_MODULE", Capability::SYS_MODULE),
            ("SYS_RAWIO", Capability::SYS_RAWIO),
            ("SYS_CHROOT", Capability::SYS_CHROOT),
            ("SYS_PTRACE", Capability::SYS_PTRACE),
            ("SYS_PACCT", Capability::SYS_PACCT),
            ("SYS_ADMIN", Capability::SYS_ADMIN),
            ("SYS_BOOT", Capability::SYS_BOOT),
            ("SYS_NICE", Capability::SYS_NICE),
            ("SYS_RESOURCE", Capability::SYS_RESOURCE),
            ("SYS_TIME", Capability::SYS_TIME),
            ("SYS_TTY_CONFIG", Capability::SYS_TTY_CONFIG),
            ("MKNOD", Capability::MKNOD),
            ("LEASE", Capability::LEASE),
            ("AUDIT_WRITE", Capability::AUDIT_WRITE),
            ("AUDIT_CONTROL", Capability::AUDIT_CONTROL),
            ("SETFCAP", Capability::SETFCAP),
            ("MAC_OVERRIDE", Capability::MAC_OVERRIDE),
            ("MAC_ADMIN", Capability::MAC_ADMIN),
            ("SYSLOG", Capability::SYSLOG),
            ("WAKE_ALARM", Capability::WAKE_ALARM),
            ("BLOCK_SUSPEND", Capability::BLOCK_SUSPEND),
            ("AUDIT_READ", Capability::AUDIT_READ),
            ("PERFMON", Capability::PERFMON),
            ("BPF", Capability::BPF),
            ("CHECKPOINT_RESTORE", Capability::CHECKPOINT_RESTORE),
        ];
        let upper = name.to_uppercase();
        let stripped = upper
            .strip_prefix("CAP_")
            .or_else(|| upper.strip_prefix("CAP."))
            .unwrap_or(upper.as_str());
        TABLE
            .iter()
            .find(|(n, _)| *n == stripped)
            .map(|(_, cap)| *cap)
    }

    /// 返回 capability 编号。
    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

/// 单条 capability 操作。
///
/// 由 `--cap-add` / `--cap-drop`（含 `ALL`）展开，按命令行顺序应用。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapOp {
    /// 添加单个 capability（`--cap-add CHOWN`）。
    Add(Capability),
    /// 丢弃单个 capability（`--cap-drop CHOWN`）。
    Drop(Capability),
    /// 添加全部 capability（`--cap-add ALL`）。
    AddAll,
    /// 丢弃全部 capability（`--cap-drop ALL`）。
    DropAll,
}

impl CapOp {
    /// 从 CLI 名称解析操作。
    ///
    /// `"ALL"`（大小写不敏感）→ [`CapOp::AddAll`]/[`CapOp::DropAll`]；
    /// 其余名称交给 [`Capability::from_name`]，未知名 `anyhow::bail!`。
    pub fn from_cli(name: &str, is_add: bool) -> anyhow::Result<Self> {
        if name.eq_ignore_ascii_case("ALL") {
            return Ok(if is_add {
                CapOp::AddAll
            } else {
                CapOp::DropAll
            });
        }
        let cap = Capability::from_name(name)
            .ok_or_else(|| anyhow::anyhow!("unknown capability name: '{name}'"))?;
        Ok(if is_add {
            CapOp::Add(cap)
        } else {
            CapOp::Drop(cap)
        })
    }
}

/// capability 权限配置。
///
/// 默认零 cap（起点空集，D1）；`inherit_base` 为 `--cap-inherit` 逃生门，
/// 使起点位图继承当前进程 effective caps。
#[derive(Debug, Clone, Default)]
pub struct CapabilityConfig {
    /// 按命令行顺序应用的 cap 操作列表。
    pub ops: Vec<CapOp>,
    /// 是否继承当前进程 effective caps 作为起点。
    pub inherit_base: bool,
}

impl CapabilityConfig {
    /// 是否存在 cap-add 类操作（Add/AddAll）。D2：仅 cap-add 需要自动叠加 userns。
    pub fn has_add(&self) -> bool {
        self.ops
            .iter()
            .any(|op| matches!(op, CapOp::Add(_) | CapOp::AddAll))
    }
}

// ---------------------------------------------------------------------------
// expand_tilde
// ---------------------------------------------------------------------------

/// 将路径字符串开头的 `~` 或 `~/` 展开为用户主目录。
///
/// 若 `$HOME` 未设置（在 Linux/macOS 上罕见），则原样返回字符串。
///
/// # 示例
///
/// ```
/// use seabox::config::expand_tilde;
///
/// let expanded = expand_tilde("~/projects");
/// assert!(!expanded.starts_with("~/"));
/// assert!(expanded.ends_with("/projects"));
///
/// // 绝对路径原样返回。
/// assert_eq!(expand_tilde("/tmp"), "/tmp");
/// ```
pub fn expand_tilde(s: &str) -> String {
    if s.starts_with("~/") || s == "~" {
        if let Some(home) = dirs::home_dir() {
            return s.replacen('~', &home.to_string_lossy(), 1);
        }
    }
    s.to_string()
}

// ---------------------------------------------------------------------------
// 权限展开
// ---------------------------------------------------------------------------

/// 将权限字符串展开为个体权限列表。
///
/// 预设组合（`ro`/`rx`、`rw`、`rwx`、`all`）会被展开为对应的个体权限；
/// 个体权限名直接解析为 [`LandlockPerm`] 单元素向量。
pub fn expand_perm(s: &str) -> Vec<LandlockPerm> {
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

/// 解析 `path:perm1[,perm2...]` 格式为一条 [`LandlockRule`]。
///
/// 等价于 CLI 的 `--landlock /:ro` 语法。
pub fn parse_landlock_spec(s: &str) -> anyhow::Result<LandlockRule> {
    let (path, perms_str) = s.split_once(':').ok_or_else(|| {
        anyhow::anyhow!("invalid landlock spec '{s}'; expected format: path:perm1[,perm2...]")
    })?;
    let perms = perms_str.split(',').flat_map(expand_perm).collect();
    Ok(LandlockRule {
        path: path.into(),
        perms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_tilde() {
        let result = expand_tilde("~/test");
        assert!(!result.starts_with("~/"), "tilde should be expanded");
        assert!(result.ends_with("/test"), "suffix should be preserved");

        let just_tilde = expand_tilde("~");
        assert!(!just_tilde.starts_with('~'), "bare tilde should expand");

        // 绝对路径原样返回。
        assert_eq!(expand_tilde("/tmp/foo"), "/tmp/foo");

        // 不以 ~ 开头的路径原样返回。
        assert_eq!(expand_tilde("relative/path"), "relative/path");
    }

    #[test]
    fn test_expand_perm_ro() {
        let perms = expand_perm("ro");
        assert_eq!(perms.len(), 3);
        assert!(perms.contains(&LandlockPerm::Execute));
        assert!(perms.contains(&LandlockPerm::ReadFile));
        assert!(perms.contains(&LandlockPerm::ReadDir));
    }

    #[test]
    fn test_expand_perm_all() {
        let perms = expand_perm("all");
        assert!(perms.contains(&LandlockPerm::Refer));
        assert!(perms.contains(&LandlockPerm::IoctlDev));
        assert!(perms.contains(&LandlockPerm::MakeSock));
        assert!(perms.contains(&LandlockPerm::WriteFile));
    }

    #[test]
    fn test_namespaces_default() {
        let ns = NamespacesConfig::default();
        assert!(!ns.user);
        assert!(!ns.ipc);
        assert!(!ns.mnt);
        assert!(!ns.pid);
        assert!(!ns.net);
        assert!(!ns.uts);
        assert!(!ns.cgroup);
        assert!(!ns.user_try);
        assert!(!ns.cgroup_try);
        assert!(ns.uid.is_none());
        assert!(ns.gid.is_none());
        assert!(ns.hostname.is_none());
    }

    #[test]
    fn test_with_landlock() {
        let config = SandboxConfig::default()
            .with_landlock("/:ro")
            .expect("valid spec");
        assert_eq!(config.landlock.len(), 1);
        assert_eq!(config.landlock[0].path.as_os_str(), "/");
    }

    #[test]
    fn test_with_unshare_all() {
        let config = SandboxConfig::default().with_unshare_all();
        assert!(config.namespaces.user);
        assert!(config.namespaces.ipc);
        assert!(config.namespaces.mnt);
        assert!(config.namespaces.pid);
        assert!(config.namespaces.net);
        assert!(config.namespaces.uts);
        assert!(config.namespaces.cgroup);
    }

    #[test]
    fn test_with_uid_gid() {
        let config = SandboxConfig::default().with_uid(1000).with_gid(100);
        assert_eq!(config.namespaces.uid, Some(1000));
        assert_eq!(config.namespaces.gid, Some(100));
    }

    #[test]
    fn test_sandbox_config_default() {
        let config = SandboxConfig::default();
        assert!(config.landlock.is_empty());
        assert!(!config.network.loopback);
        assert_eq!(config.timeout_default_secs, 30);
        assert_eq!(config.timeout_max_secs, 300);
    }

    #[test]
    fn test_network_config() {
        let config = SandboxConfig::default().with_network(true);
        assert!(config.network.loopback);

        let config = SandboxConfig::default().with_network(false);
        assert!(!config.network.loopback);
    }

    #[test]
    fn test_network_config_loopback() {
        let config = SandboxConfig::default().with_network(true);
        assert!(config.network.loopback);

        let config = SandboxConfig::default().with_network(false);
        assert!(!config.network.loopback);
    }

    #[test]
    fn test_mount_config() {
        let config = SandboxConfig::default()
            .with_bind("/src", "/dst")
            .with_tmpfs("/tmp");
        assert!(config.namespaces.mnt);
        assert_eq!(config.mount.specs.len(), 2);
    }

    #[test]
    fn test_mount_spec_bind() {
        let spec = MountSpec::bind("/host/src", "/container/dst");
        assert_eq!(spec.source, Some("/host/src".into()));
        assert_eq!(spec.target, "/container/dst");
        assert_eq!(spec.fstype, "none");
        assert_eq!(spec.flags, MS_BIND | MS_REC);
        assert!(!spec.readonly);
    }

    #[test]
    fn test_mount_spec_ro_bind() {
        let spec = MountSpec::ro_bind("/host/src", "/container/dst");
        assert_eq!(spec.source, Some("/host/src".into()));
        assert_eq!(spec.target, "/container/dst");
        assert!(spec.readonly);
    }

    #[test]
    fn test_mount_spec_tmpfs() {
        let spec = MountSpec::tmpfs("/mnt/tmp");
        assert!(spec.source.is_none());
        assert_eq!(spec.target, "/mnt/tmp");
        assert_eq!(spec.fstype, "tmpfs");
        assert_eq!(spec.flags, MS_NOSUID | MS_NODEV);
    }

    #[test]
    fn test_capability_from_name() {
        assert_eq!(Capability::from_name("CHOWN"), Some(Capability::CHOWN));
        assert_eq!(Capability::from_name("cap_chown"), Some(Capability::CHOWN));
        assert_eq!(Capability::from_name("cap.CHOWN"), Some(Capability::CHOWN));
        assert_eq!(Capability::from_name("chown"), Some(Capability::CHOWN));
        assert_eq!(Capability::from_name("NET_RAW"), Some(Capability::NET_RAW));
        assert_eq!(Capability::from_name("net_raw"), Some(Capability::NET_RAW));
        assert_eq!(
            Capability::from_name("SYS_ADMIN"),
            Some(Capability::SYS_ADMIN)
        );
        assert_eq!(Capability::from_name("not_a_cap"), None);
        assert_eq!(Capability::from_name(""), None);
    }

    #[test]
    fn test_capability_as_u16() {
        assert_eq!(Capability::CHOWN.as_u16(), 0);
        assert_eq!(Capability::NET_RAW.as_u16(), 13);
        assert_eq!(Capability::CHECKPOINT_RESTORE.as_u16(), 40);
    }

    #[test]
    fn test_cap_op_from_cli() {
        assert_eq!(CapOp::from_cli("ALL", true).unwrap(), CapOp::AddAll);
        assert_eq!(CapOp::from_cli("all", false).unwrap(), CapOp::DropAll);
        assert_eq!(
            CapOp::from_cli("chown", true).unwrap(),
            CapOp::Add(Capability::CHOWN)
        );
        assert_eq!(
            CapOp::from_cli("NET_RAW", false).unwrap(),
            CapOp::Drop(Capability::NET_RAW)
        );
        assert!(CapOp::from_cli("unknown_cap", true).is_err());
    }

    #[test]
    fn test_capability_config_default() {
        let cfg = CapabilityConfig::default();
        assert!(cfg.ops.is_empty());
        assert!(!cfg.inherit_base);
    }

    #[test]
    fn test_capability_config_has_add() {
        // 空配置无 cap-add → 不触发 userns（D2）。
        assert!(!SandboxConfig::default().capabilities.has_add());
        // 仅 cap-drop 不触发（cap-drop 无回灌风险）。
        assert!(!SandboxConfig::default()
            .with_cap_drop("chown")
            .expect("valid cap")
            .capabilities
            .has_add());
        assert!(!SandboxConfig::default()
            .with_cap_drop_all()
            .capabilities
            .has_add());
        // cap-add 单条与 ALL 都触发。
        assert!(SandboxConfig::default()
            .with_cap_add("chown")
            .expect("valid cap")
            .capabilities
            .has_add());
        assert!(SandboxConfig::default()
            .with_cap_add_all()
            .capabilities
            .has_add());
    }

    #[test]
    fn test_with_cap_add_drop() {
        let config = SandboxConfig::default()
            .with_cap_add("chown")
            .expect("valid cap")
            .with_cap_drop("net_raw")
            .expect("valid cap")
            .with_cap_add_all()
            .with_cap_drop_all()
            .with_cap_inherit(true);

        assert_eq!(config.capabilities.ops.len(), 4);
        assert_eq!(config.capabilities.ops[0], CapOp::Add(Capability::CHOWN));
        assert_eq!(config.capabilities.ops[1], CapOp::Drop(Capability::NET_RAW));
        assert_eq!(config.capabilities.ops[2], CapOp::AddAll);
        assert_eq!(config.capabilities.ops[3], CapOp::DropAll);
        assert!(config.capabilities.inherit_base);
    }

    #[test]
    fn test_with_cap_add_drop_error() {
        assert!(SandboxConfig::default().with_cap_add("not_a_cap").is_err());
        assert!(SandboxConfig::default().with_cap_drop("not_a_cap").is_err());
    }

    #[test]
    fn test_sandbox_config_default_capabilities() {
        let config = SandboxConfig::default();
        assert!(config.capabilities.ops.is_empty());
        assert!(!config.capabilities.inherit_base);
    }
}
