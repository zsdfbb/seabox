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
// expand_tilde
// ---------------------------------------------------------------------------

/// 将路径字符串开头的 `~` 或 `~/` 展开为用户主目录。
///
/// 若 `$HOME` 未设置（在 Linux/macOS 上罕见），则原样返回字符串。
///
/// # 示例
///
/// ```
/// use sandbox_runtime::config::expand_tilde;
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
        assert_eq!(spec.flags, (MS_BIND | MS_REC) as u64);
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
        assert_eq!(spec.flags, (MS_NOSUID | MS_NODEV) as u64);
    }
}
