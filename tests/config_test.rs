//! SandboxConfig 的集成测试。
//!
//! 这些测试覆盖公开的 `sandbox_runtime::config` API。

// ---------------------------------------------------------------------------
// expand_tilde
// ---------------------------------------------------------------------------

#[test]
fn test_expand_tilde() {
    // ~/path -> $HOME/path
    let expanded = sandbox_runtime::config::expand_tilde("~/projects");
    assert!(!expanded.starts_with("~/"));
    assert!(expanded.ends_with("/projects"));

    // 单独的 ~ -> $HOME
    let bare = sandbox_runtime::config::expand_tilde("~");
    assert!(!bare.starts_with('~'), "bare tilde should expand");

    // ~otheruser 保持不变（只有开头的 ~/ 或单独的 ~ 会被展开）
    assert_eq!(
        sandbox_runtime::config::expand_tilde("~otheruser"),
        "~otheruser"
    );

    // 不含 ~ 的绝对路径 -> 原样
    assert_eq!(
        sandbox_runtime::config::expand_tilde("/absolute/path"),
        "/absolute/path"
    );

    // 不含 ~ 的相对路径 -> 原样
    assert_eq!(
        sandbox_runtime::config::expand_tilde("relative/path"),
        "relative/path"
    );
}
