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

use crate::FsPolicy;

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
/// use sandbox_runtime::FsPolicy;
///
/// let config = SandboxConfig::builder()
///     .policy(FsPolicy::ReadOnly)
///     .allow_write(vec!["/tmp".to_string()])
///     .network_enabled(false)
///     .timeout(60, 600)
///     .build();
/// ```
#[derive(Debug)]
pub struct SandboxConfigBuilder {
    policy: Option<FsPolicy>,
    allow_write: Vec<String>,
    network_enabled: bool,
    timeout_default_secs: u64,
    timeout_max_secs: u64,
}

impl Default for SandboxConfigBuilder {
    fn default() -> Self {
        Self {
            policy: None,
            allow_write: Vec::new(),
            network_enabled: false,
            timeout_default_secs: 30,
            timeout_max_secs: 300,
        }
    }
}

impl SandboxConfigBuilder {
    /// 设置文件系统策略。
    pub fn policy(mut self, policy: FsPolicy) -> Self {
        self.policy = Some(policy);
        self
    }

    /// 设置额外的可写路径（追加在工作区目录与 `/tmp` 之外）。
    pub fn allow_write(mut self, paths: impl Into<Vec<String>>) -> Self {
        self.allow_write = paths.into();
        self
    }

    /// 启用或禁用网络访问（Phase 1：仅占位）。
    pub fn network_enabled(mut self, enabled: bool) -> Self {
        self.network_enabled = enabled;
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
                policy: self.policy.unwrap_or(FsPolicy::WorkspaceWrite),
                allow_write: self.allow_write,
            },
            network: NetworkConfig {
                enabled: self.network_enabled,
            },
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
/// `policy` 字段控制粗粒度的访问模式；`allow_write` 列出
///（除工作区目录与 `/tmp` 之外）沙箱化进程允许写入的路径。
///
/// # TOML
///
/// ```toml
/// [filesystem]
/// policy = "workspace"       # "full-access" | "read-only" | "workspace"
/// allow_write = ["output", "/var/log/app"]
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemConfig {
    /// 访问策略预设。
    ///
    /// `#[serde(flatten)]` 将 `FsPolicy` 的 tag 内联展开，使得 TOML 直接写成
    /// `policy = "read-only"`，而不是嵌套在 `[filesystem.policy]` 中。
    #[serde(flatten)]
    pub policy: FsPolicy,

    /// 额外的可写路径（除工作区目录与 `/tmp` 之外）。
    ///
    /// 路径以字符串形式存储，运行时支持 `~` 展开。
    #[serde(default)]
    pub allow_write: Vec<String>,
}

impl Default for FilesystemConfig {
    fn default() -> Self {
        Self {
            policy: FsPolicy::WorkspaceWrite,
            allow_write: Vec::new(),
        }
    }
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
    use crate::FsPolicy;

    #[test]
    fn test_default_config() {
        let config = SandboxConfig::default();
        assert_eq!(config.filesystem.policy, FsPolicy::WorkspaceWrite);
        assert!(config.filesystem.allow_write.is_empty());
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
        assert_eq!(config.filesystem.policy, FsPolicy::WorkspaceWrite);
        assert!(!config.network.enabled);
        assert_eq!(config.timeout.default_secs, 30);
        assert_eq!(config.timeout.max_secs, 300);
    }

    #[test]
    fn test_builder_roundtrip() {
        let config = SandboxConfig::builder()
            .policy(FsPolicy::ReadOnly)
            .allow_write(vec!["/tmp".to_string(), "./output".to_string()])
            .network_enabled(true)
            .timeout(60, 600)
            .build();

        assert_eq!(config.filesystem.policy, FsPolicy::ReadOnly);
        assert_eq!(config.filesystem.allow_write, vec!["/tmp", "./output"]);
        assert!(config.network.enabled);
        assert_eq!(config.timeout.default_secs, 60);
        assert_eq!(config.timeout.max_secs, 600);
    }

    #[test]
    fn test_filesystem_default() {
        let fs = FilesystemConfig::default();
        assert_eq!(fs.policy, FsPolicy::WorkspaceWrite);
        assert!(fs.allow_write.is_empty());
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
        assert!(err.to_string().contains("No such file") || err.to_string().contains("file not found"));
    }

    #[test]
    fn test_toml_roundtrip() {
        // 将 config 序列化为 TOML，再反序列化回来。
        let config = SandboxConfig {
            filesystem: FilesystemConfig {
                policy: FsPolicy::WorkspaceWrite,
                allow_write: vec!["/data".to_string()],
            },
            network: NetworkConfig { enabled: false },
            timeout: TimeoutConfig {
                default_secs: 60,
                max_secs: 600,
            },
        };

        let toml_str = toml::to_string(&config).expect("serialisation should succeed");
        let deserialised: SandboxConfig =
            toml::from_str(&toml_str).expect("deserialisation should succeed");

        assert_eq!(deserialised.filesystem.policy, FsPolicy::WorkspaceWrite);
        assert_eq!(deserialised.filesystem.allow_write, vec!["/data"]);
        assert!(!deserialised.network.enabled);
        assert_eq!(deserialised.timeout.default_secs, 60);
        assert_eq!(deserialised.timeout.max_secs, 600);
    }

    #[test]
    fn test_toml_deserialize_flattened_policy() {
        // 验证被 flatten 的 `policy` tag：应在 `[filesystem]` 顶层写
        // `policy = "read-only"`，而不是嵌套的 `[filesystem.policy]`。
        let toml_str = r#"
[filesystem]
policy = "read-only"
allow_write = ["/tmp"]

[network]
enabled = true

[timeout]
default_secs = 10
max_secs = 120
"#;
        let config: SandboxConfig = toml::from_str(toml_str).expect("TOML should parse");
        assert_eq!(config.filesystem.policy, FsPolicy::ReadOnly);
        assert_eq!(config.filesystem.allow_write, vec!["/tmp"]);
        assert!(config.network.enabled);
        assert_eq!(config.timeout.default_secs, 10);
        assert_eq!(config.timeout.max_secs, 120);
    }

    #[test]
    fn test_toml_full_access() {
        let toml_str = r#"
[filesystem]
policy = "full-access"
"#;
        let config: SandboxConfig = toml::from_str(toml_str).expect("TOML should parse");
        assert_eq!(config.filesystem.policy, FsPolicy::FullAccess);
    }

    #[test]
    fn test_toml_invalid_policy() {
        let toml_str = r#"
[filesystem]
policy = "invalid-policy"
"#;
        let result: Result<SandboxConfig, _> = toml::from_str(toml_str);
        assert!(result.is_err(), "invalid policy should fail to deserialise");
    }

    #[test]
    fn test_tilde_in_builder_paths() {
        // Builder 原样存储路径；展开是运行时的职责。
        let config = SandboxConfig::builder()
            .allow_write(vec!["~/workspace".to_string()])
            .build();
        assert_eq!(config.filesystem.allow_write, vec!["~/workspace"]);
        // 运行时调用 expand_tilde
        let expanded = expand_tilde(&config.filesystem.allow_write[0]);
        assert!(!expanded.starts_with("~/"));
        assert!(expanded.ends_with("/workspace"));
    }
}