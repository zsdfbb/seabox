//! SandboxConfig 的集成测试：TOML 反序列化、Builder 构造、
//! expand_tilde、无效策略拒绝、部分 TOML 默认值，以及往返一致性。
//!
//! 这些测试覆盖公开的 `sandbox_runtime::config` API。

use sandbox_runtime::config::SandboxConfig;
use sandbox_runtime::{LandlockPerm, LandlockRule};

// ---------------------------------------------------------------------------
// TOML → SandboxConfig 反序列化（三种策略变体）
// ---------------------------------------------------------------------------

#[test]
fn test_toml_full_access() {
    let toml_str = r#"
[filesystem]
landlock = []
"#;
    let config: SandboxConfig = toml::from_str(toml_str).unwrap();
    assert!(config.filesystem.landlock.is_empty());
    // 未指定 section 的默认值
    assert!(!config.network.enabled);
    assert_eq!(config.timeout.default_secs, 30);
    assert_eq!(config.timeout.max_secs, 300);
}

#[test]
fn test_toml_read_only() {
    let toml_str = r#"
[filesystem]
landlock = [{ path = "/", perms = ["ro"] }]
"#;
    let config: SandboxConfig = toml::from_str(toml_str).unwrap();
    assert_eq!(config.filesystem.landlock.len(), 1);
    assert_eq!(config.filesystem.landlock[0].perms, vec![LandlockPerm::Ro]);
}

#[test]
fn test_toml_workspace_write() {
    let toml_str = r#"
[filesystem]
landlock = [{ path = "/", perms = ["ro", "rw"] }]
"#;
    let config: SandboxConfig = toml::from_str(toml_str).unwrap();
    assert_eq!(config.filesystem.landlock.len(), 1);
    assert_eq!(
        config.filesystem.landlock[0].perms,
        vec![LandlockPerm::Ro, LandlockPerm::Rw]
    );
}

// ---------------------------------------------------------------------------
// Builder → SandboxConfig 构造，与 TOML 反序列化等价
// ---------------------------------------------------------------------------

#[test]
fn test_builder_matches_toml() {
    let builder_config = SandboxConfig::builder()
        .landlock(vec![LandlockRule {
            path: "/".into(),
            perms: vec![LandlockPerm::Ro],
        }])
        .network_enabled(true)
        .timeout(60, 600)
        .build();

    let toml_str = r#"
[filesystem]
landlock = [{ path = "/", perms = ["ro"] }]

[network]
enabled = true

[timeout]
default_secs = 60
max_secs = 600
"#;
    let toml_config: SandboxConfig = toml::from_str(toml_str).unwrap();

    assert_eq!(
        builder_config.filesystem.landlock.len(),
        1
    );
    assert_eq!(
        toml_config.filesystem.landlock.len(),
        1
    );
    assert_eq!(
        builder_config.filesystem.landlock[0].perms,
        toml_config.filesystem.landlock[0].perms
    );
    assert_eq!(builder_config.network.enabled, toml_config.network.enabled);
    assert_eq!(
        builder_config.timeout.default_secs,
        toml_config.timeout.default_secs
    );
    assert_eq!(
        builder_config.timeout.max_secs,
        toml_config.timeout.max_secs
    );
}

// ---------------------------------------------------------------------------
// expand_tilde
// ---------------------------------------------------------------------------

#[test]
fn test_expand_tilde() {
    // ~/path → $HOME/path
    let expanded = sandbox_runtime::config::expand_tilde("~/projects");
    assert!(!expanded.starts_with("~/"));
    assert!(expanded.ends_with("/projects"));

    // 单独的 ~ → $HOME
    let bare = sandbox_runtime::config::expand_tilde("~");
    assert!(!bare.starts_with('~'), "bare tilde should expand");

    // ~otheruser 保持不变（只有开头的 ~/ 或单独的 ~ 会被展开）
    assert_eq!(
        sandbox_runtime::config::expand_tilde("~otheruser"),
        "~otheruser"
    );

    // 不含 ~ 的绝对路径 → 原样
    assert_eq!(
        sandbox_runtime::config::expand_tilde("/absolute/path"),
        "/absolute/path"
    );

    // 不含 ~ 的相对路径 → 原样
    assert_eq!(
        sandbox_runtime::config::expand_tilde("relative/path"),
        "relative/path"
    );
}

// ---------------------------------------------------------------------------
// 无效的 landlock 权限值会被 serde 拒绝
// ---------------------------------------------------------------------------

#[test]
fn test_invalid_policy_rejected() {
    let toml_str = r#"
[filesystem]
landlock = [{ path = "/", perms = ["invalid-perm"] }]
"#;
    let result: Result<SandboxConfig, _> = toml::from_str(toml_str);
    assert!(result.is_err(), "invalid landlock perm should fail to deserialise");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unknown variant") || err.contains("unknown"),
        "error should mention unknown variant, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// 部分 TOML（只有 [filesystem]）时 [network] 与 [timeout] 使用默认值
// ---------------------------------------------------------------------------

#[test]
fn test_partial_toml_uses_defaults() {
    let toml_str = r#"
[filesystem]
landlock = []
"#;
    let config: SandboxConfig = toml::from_str(toml_str).unwrap();
    assert!(config.filesystem.landlock.is_empty());
    // 未指定 section 的默认值
    assert!(!config.network.enabled);
    assert_eq!(config.timeout.default_secs, 30);
    assert_eq!(config.timeout.max_secs, 300);
}

// ---------------------------------------------------------------------------
// TOML 往返：序列化 → 反序列化 → 值不变
// ---------------------------------------------------------------------------

#[test]
fn test_toml_round_trip() {
    let original = SandboxConfig::builder()
        .landlock(vec![LandlockRule {
            path: "/data".into(),
            perms: vec![LandlockPerm::Rw],
        }])
        .network_enabled(false)
        .timeout(60, 600)
        .build();

    let toml_str = toml::to_string(&original).unwrap();
    let deserialized: SandboxConfig = toml::from_str(&toml_str).unwrap();

    assert_eq!(
        original.filesystem.landlock.len(),
        deserialized.filesystem.landlock.len()
    );
    assert_eq!(
        original.filesystem.landlock[0].perms,
        deserialized.filesystem.landlock[0].perms
    );
    assert_eq!(original.network.enabled, deserialized.network.enabled);
    assert_eq!(
        original.timeout.default_secs,
        deserialized.timeout.default_secs
    );
    assert_eq!(
        original.timeout.max_secs,
        deserialized.timeout.max_secs
    );
}
