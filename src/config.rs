//! 沙箱配置解析与 Builder。
//!
//! 提供 [`SandboxConfig`]（可从 TOML 反序列化）、[`SandboxConfigBuilder`]，
//! 以及用于路径展开的 [`expand_tilde`] 工具函数。
//!
//! ## TOML 示例
//!
//! ```toml
//! [filesystem]
//! policy = "workspace"
//! allow_write = [".", "/tmp"]
//!
//! [network]
//! enabled = false
//!
//! [timeout]
//! default_secs = 30
//! max_secs = 300
//! ```

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::LandlockRule;

#[cfg(test)]
use crate::LandlockPerm;

// ---------------------------------------------------------------------------
// SandboxConfig
// ---------------------------------------------------------------------------

/// 完整的沙箱配置。
///
/// 可从 TOML 反序列化。可直接构造、通过 [`SandboxConfig::from_toml`] 加载，
/// 或通过 [`SandboxConfig::builder`] 流式 API 构造。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SandboxConfig {
    #[serde(default)]
    pub filesystem: FilesystemConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub namespaces: NamespacesConfig,
    #[serde(default)]
    pub timeout: TimeoutConfig,
}

impl SandboxConfig {
    /// 从磁盘上的 TOML 文件加载一个 [`SandboxConfig`]。
    pub fn from_toml(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())?;
        let config: SandboxConfig = toml::from_str(&content)?;
        Ok(config)
    }

    /// 创建一个用于程序化构造的 [`SandboxConfigBuilder`]。
    pub fn builder() -> SandboxConfigBuilder {
        SandboxConfigBuilder::default()
    }
}

// ---------------------------------------------------------------------------
// SandboxConfigBuilder
// ---------------------------------------------------------------------------

/// 用于 [`SandboxConfig`] 的流式 Builder。
///
/// # 示例
///
/// ```ignore
/// use sandbox_runtime::config::SandboxConfig;
/// use sandbox_runtime::LandlockRule;
///
/// let config = SandboxConfig::builder()
///     .landlock(vec![LandlockRule { path: "/tmp".into(), perms: vec![] }])
///     .network_enabled(false)
///     .timeout(60, 600)
///     .build();
/// ```
#[derive(Debug)]
pub struct SandboxConfigBuilder {
    landlock: Vec<LandlockRule>,
    network_enabled: bool,
    namespaces: NamespacesConfig,
    timeout_default_secs: u64,
    timeout_max_secs: u64,
}

impl Default for SandboxConfigBuilder {
    fn default() -> Self {
        Self {
            landlock: Vec::new(),
            network_enabled: false,
            namespaces: NamespacesConfig::default(),
            timeout_default_secs: 30,
            timeout_max_secs: 300,
        }
    }
}

impl SandboxConfigBuilder {
    /// 设置 Landlock 规则。
    pub fn landlock(mut self, rules: Vec<LandlockRule>) -> Self {
        self.landlock = rules;
        self
    }

    /// 启用或禁用网络访问（Phase 1：仅占位）。
    pub fn network_enabled(mut self, enabled: bool) -> Self {
        self.network_enabled = enabled;
        self
    }

    /// 直接设置 NamespacesConfig。
    pub fn namespaces(mut self, ns: NamespacesConfig) -> Self {
        self.namespaces = ns;
        self
    }

    /// 启用全部命名空间隔离（user/ipc/pid/net/uts/cgroup）。
    ///
    /// 不包括 `user_try` 和 `cgroup_try` 变体。
    pub fn unshare_all(mut self) -> Self {
        self.namespaces = NamespacesConfig {
            user: true,
            ipc: true,
            pid: true,
            net: true,
            uts: true,
            cgroup: true,
            ..self.namespaces
        };
        self
    }

    /// 同时设置默认与最大超时（秒）。
    ///
    /// `default_secs` 是调用方未指定时使用的超时；`max_secs` 是沙箱接受
    /// 的硬性上限。
    pub fn timeout(mut self, default_secs: u64, max_secs: u64) -> Self {
        self.timeout_default_secs = default_secs;
        self.timeout_max_secs = max_secs;
        self
    }

    /// 消费 Builder 并产出一个 [`SandboxConfig`]。
    pub fn build(self) -> SandboxConfig {
        SandboxConfig {
            filesystem: FilesystemConfig {
                landlock: self.landlock,
            },
            network: NetworkConfig {
                enabled: self.network_enabled,
            },
            namespaces: self.namespaces,
            timeout: TimeoutConfig {
                default_secs: self.timeout_default_secs,
                max_secs: self.timeout_max_secs,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// FilesystemConfig
// ---------------------------------------------------------------------------

/// 沙箱的文件系统访问配置。
///
/// `landlock` 字段指定 Landlock 路径权限规则。
/// 空列表表示不激活 Landlock。
///
/// # TOML
///
/// ```toml
/// [filesystem]
/// landlock = [{ path = "/", perms = ["ro"] }]
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FilesystemConfig {
    /// Landlock 路径权限规则。
    #[serde(default)]
    pub landlock: Vec<LandlockRule>,
}

// ---------------------------------------------------------------------------
// NetworkConfig
// ---------------------------------------------------------------------------

/// 网络访问配置。
///
/// Phase 1：这是占位实现。网络沙箱化尚未实现。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// 是否启用网络访问。
    #[serde(default)]
    pub enabled: bool,
}

// ---------------------------------------------------------------------------
// NamespacesConfig
// ---------------------------------------------------------------------------

/// Linux 命名空间隔离配置。
///
/// 控制哪些命名空间被 unshare(2) 隔离。
/// `user_try` / `cgroup_try` 是软性选项：若内核不支持则静默回退，不报错。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NamespacesConfig {
    /// 隔离 user 命名空间（需要 `CAP_SETUID`、`CAP_SETGID`）。
    #[serde(default)]
    pub user: bool,
    /// 隔离 IPC 命名空间。
    #[serde(default)]
    pub ipc: bool,
    /// 隔离 PID 命名空间。
    #[serde(default)]
    pub pid: bool,
    /// 隔离网络命名空间。
    #[serde(default)]
    pub net: bool,
    /// 隔离 UTS（hostname）命名空间。
    #[serde(default)]
    pub uts: bool,
    /// 隔离 cgroup 命名空间。
    #[serde(default)]
    pub cgroup: bool,
    /// 软性 user 命名空间（内核不支持时静默回退）。
    #[serde(default)]
    pub user_try: bool,
    /// 软性 cgroup 命名空间（内核不支持时静默回退）。
    #[serde(default)]
    pub cgroup_try: bool,
    /// 在 user 命名空间中映射的 uid（仅在 `user` 或 `user_try` 生效时使用）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    /// 在 user 命名空间中映射的 gid（仅在 `user` 或 `user_try` 生效时使用）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
    /// 在 UTS 命名空间中设置的 hostname（仅在 `uts` 生效时使用）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
}

// ---------------------------------------------------------------------------
// TimeoutConfig
// ---------------------------------------------------------------------------

/// 沙箱化命令的超时配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutConfig {
    /// 默认命令超时（秒）。
    #[serde(default = "default_timeout")]
    pub default_secs: u64,
    /// 允许的最大命令超时（秒）。
    #[serde(default = "default_max_timeout")]
    pub max_secs: u64,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            default_secs: default_timeout(),
            max_secs: default_max_timeout(),
        }
    }
}

fn default_timeout() -> u64 {
    30
}

fn default_max_timeout() -> u64 {
    300
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
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_default_config() {
        let config = SandboxConfig::default();
        assert!(config.filesystem.landlock.is_empty());
        assert!(!config.network.enabled);
        assert_eq!(config.timeout.default_secs, 30);
        assert_eq!(config.timeout.max_secs, 300);
    }

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
    fn test_builder_default() {
        let config = SandboxConfig::builder().build();
        assert!(config.filesystem.landlock.is_empty());
        assert!(!config.network.enabled);
        assert_eq!(config.timeout.default_secs, 30);
        assert_eq!(config.timeout.max_secs, 300);
    }

    #[test]
    fn test_builder_roundtrip() {
        let ro_perms = vec![
            LandlockPerm::Execute,
            LandlockPerm::ReadFile,
            LandlockPerm::ReadDir,
        ];
        let rw_perms = vec![
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
        ];
        let config = SandboxConfig::builder()
            .landlock(vec![
                LandlockRule {
                    path: "/".into(),
                    perms: ro_perms.clone(),
                },
                LandlockRule {
                    path: "/tmp".into(),
                    perms: rw_perms.clone(),
                },
                LandlockRule {
                    path: "./output".into(),
                    perms: rw_perms,
                },
            ])
            .network_enabled(true)
            .timeout(60, 600)
            .build();

        assert_eq!(config.filesystem.landlock.len(), 3);
        assert_eq!(config.filesystem.landlock[0].path, PathBuf::from("/"));
        assert_eq!(config.filesystem.landlock[0].perms, ro_perms);
        assert!(config.network.enabled);
        assert_eq!(config.timeout.default_secs, 60);
        assert_eq!(config.timeout.max_secs, 600);
    }

    #[test]
    fn test_filesystem_default() {
        let fs = FilesystemConfig::default();
        assert!(fs.landlock.is_empty());
    }

    #[test]
    fn test_network_default() {
        let net = NetworkConfig::default();
        assert!(!net.enabled);
    }

    #[test]
    fn test_timeout_default() {
        let t = TimeoutConfig::default();
        assert_eq!(t.default_secs, 30);
        assert_eq!(t.max_secs, 300);
    }

    #[test]
    fn test_from_toml_nonexistent() {
        let err = SandboxConfig::from_toml("/nonexistent/path.toml").unwrap_err();
        assert!(
            err.to_string().contains("No such file") || err.to_string().contains("file not found")
        );
    }

    #[test]
    fn test_toml_roundtrip() {
        let ro_perms = vec![
            LandlockPerm::Execute,
            LandlockPerm::ReadFile,
            LandlockPerm::ReadDir,
        ];
        let rw_perms = vec![
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
        ];
        let config = SandboxConfig {
            filesystem: FilesystemConfig {
                landlock: vec![
                    LandlockRule {
                        path: "/".into(),
                        perms: ro_perms.clone(),
                    },
                    LandlockRule {
                        path: "/data".into(),
                        perms: rw_perms.clone(),
                    },
                ],
            },
            network: NetworkConfig { enabled: false },
            namespaces: NamespacesConfig::default(),
            timeout: TimeoutConfig {
                default_secs: 60,
                max_secs: 600,
            },
        };

        let toml_str = toml::to_string(&config).expect("serialisation should succeed");
        let deserialised: SandboxConfig =
            toml::from_str(&toml_str).expect("deserialisation should succeed");

        assert_eq!(deserialised.filesystem.landlock.len(), 2);
        assert_eq!(deserialised.filesystem.landlock[0].perms, ro_perms);
        assert_eq!(deserialised.filesystem.landlock[1].perms, rw_perms);
        assert!(!deserialised.network.enabled);
        assert_eq!(deserialised.timeout.default_secs, 60);
        assert_eq!(deserialised.timeout.max_secs, 600);
    }

    #[test]
    fn test_toml_deserialize_landlock() {
        let ro_perms = vec![
            LandlockPerm::Execute,
            LandlockPerm::ReadFile,
            LandlockPerm::ReadDir,
        ];
        let rw_perms = vec![
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
        ];
        let toml_str = r#"
[filesystem]
landlock = [
  { path = "/", perms = ["execute", "read-file", "read-dir"] },
  { path = "/tmp", perms = ["execute", "read-file", "read-dir", "write-file", "remove-dir", "remove-file", "make-dir", "make-reg", "make-sym", "truncate"] },
]

[network]
enabled = true

[timeout]
default_secs = 10
max_secs = 120
"#;
        let config: SandboxConfig = toml::from_str(toml_str).expect("TOML should parse");
        assert_eq!(config.filesystem.landlock.len(), 2);
        assert_eq!(config.filesystem.landlock[0].perms, ro_perms);
        assert_eq!(config.filesystem.landlock[1].perms, rw_perms);
        assert!(config.network.enabled);
        assert_eq!(config.timeout.default_secs, 10);
        assert_eq!(config.timeout.max_secs, 120);
    }

    #[test]
    fn test_toml_empty_landlock() {
        let toml_str = r#"
[filesystem]
landlock = []
"#;
        let config: SandboxConfig = toml::from_str(toml_str).expect("TOML should parse");
        assert!(config.filesystem.landlock.is_empty());
    }

    #[test]
    fn test_toml_invalid_landlock_perm() {
        let toml_str = r#"
[filesystem]
landlock = [{ path = "/", perms = ["invalid-perm"] }]
"#;
        let result: Result<SandboxConfig, _> = toml::from_str(toml_str);
        assert!(
            result.is_err(),
            "invalid landlock perm should fail to deserialise"
        );
    }

    #[test]
    fn test_tilde_in_builder_paths() {
        // Builder 原样存储路径；展开是运行时的职责。
        let config = SandboxConfig::builder()
            .landlock(vec![LandlockRule {
                path: "~/workspace".into(),
                perms: vec![
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
            }])
            .build();
        assert_eq!(
            config.filesystem.landlock[0].path,
            PathBuf::from("~/workspace")
        );
        // 运行时调用 expand_tilde
        let expanded = expand_tilde(config.filesystem.landlock[0].path.to_str().unwrap());
        assert!(!expanded.starts_with("~/"));
        assert!(expanded.ends_with("/workspace"));
    }

    // -----------------------------------------------------------------------
    // NamespacesConfig 测试
    // -----------------------------------------------------------------------

    #[test]
    fn test_namespaces_default_values() {
        let ns = NamespacesConfig::default();
        assert!(!ns.user);
        assert!(!ns.ipc);
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
    fn test_namespaces_builder_unshare_all() {
        let config = SandboxConfig::builder().unshare_all().build();
        assert!(config.namespaces.user);
        assert!(config.namespaces.ipc);
        assert!(config.namespaces.pid);
        assert!(config.namespaces.net);
        assert!(config.namespaces.uts);
        assert!(config.namespaces.cgroup);
        // unshare_all 不影响 try 变体
        assert!(!config.namespaces.user_try);
        assert!(!config.namespaces.cgroup_try);
    }

    #[test]
    fn test_namespaces_serialize_deserialize() {
        let ns = NamespacesConfig {
            user: true,
            ipc: true,
            pid: false,
            net: true,
            uts: false,
            cgroup: false,
            user_try: false,
            cgroup_try: true,
            uid: Some(1000),
            gid: Some(100),
            hostname: Some("sandbox".into()),
        };
        let toml_str = toml::to_string(&ns).expect("serialisation should succeed");
        let deserialised: NamespacesConfig =
            toml::from_str(&toml_str).expect("deserialisation should succeed");

        assert!(deserialised.user);
        assert!(deserialised.ipc);
        assert!(!deserialised.pid);
        assert!(deserialised.net);
        assert!(!deserialised.uts);
        assert!(!deserialised.cgroup);
        assert!(!deserialised.user_try);
        assert!(deserialised.cgroup_try);
        assert_eq!(deserialised.uid, Some(1000));
        assert_eq!(deserialised.gid, Some(100));
        assert_eq!(deserialised.hostname, Some("sandbox".into()));
    }

    #[test]
    fn test_namespaces_toml_parse() {
        let toml_str = r#"
user = true
pid = true
net = true
uts = true
uid = 1000
hostname = "sandbox-vm"
"#;
        let ns: NamespacesConfig = toml::from_str(toml_str).expect("TOML should parse");
        assert!(ns.user);
        assert!(!ns.ipc);
        assert!(ns.pid);
        assert!(ns.net);
        assert!(ns.uts);
        assert!(!ns.cgroup);
        assert!(!ns.user_try);
        assert!(!ns.cgroup_try);
        assert_eq!(ns.uid, Some(1000));
        assert!(ns.gid.is_none());
        assert_eq!(ns.hostname, Some("sandbox-vm".into()));
    }

    #[test]
    fn test_namespaces_toml_parse_sandboxconfig() {
        let toml_str = r#"
[filesystem]
landlock = [{ path = "/", perms = ["execute", "read-file", "read-dir"] }]

[network]
enabled = false

[namespaces]
user = true
pid = true
net = true
uts = true
uid = 1000
hostname = "sandbox-vm"

[timeout]
default_secs = 30
max_secs = 300
"#;
        let config: SandboxConfig = toml::from_str(toml_str).expect("TOML should parse");
        assert!(config.namespaces.user);
        assert!(!config.namespaces.ipc);
        assert!(config.namespaces.pid);
        assert!(config.namespaces.net);
        assert!(config.namespaces.uts);
        assert!(!config.namespaces.cgroup);
        assert_eq!(config.namespaces.uid, Some(1000));
        assert_eq!(config.namespaces.hostname, Some("sandbox-vm".into()));
        assert_eq!(config.network.enabled, false);
        assert_eq!(config.timeout.default_secs, 30);
    }

    #[test]
    fn test_sandboxconfig_with_namespaces() {
        let config = SandboxConfig {
            filesystem: FilesystemConfig { landlock: vec![] },
            network: NetworkConfig { enabled: false },
            namespaces: NamespacesConfig {
                user: true,
                pid: true,
                net: true,
                ..NamespacesConfig::default()
            },
            timeout: TimeoutConfig {
                default_secs: 30,
                max_secs: 300,
            },
        };
        let toml_str = toml::to_string(&config).expect("serialisation should succeed");
        let deserialised: SandboxConfig =
            toml::from_str(&toml_str).expect("deserialisation should succeed");

        assert!(deserialised.namespaces.user);
        assert!(deserialised.namespaces.pid);
        assert!(deserialised.namespaces.net);
        assert!(!deserialised.namespaces.ipc);
        assert!(!deserialised.namespaces.uts);
        assert!(!deserialised.namespaces.cgroup);
    }
}
