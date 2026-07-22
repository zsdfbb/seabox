# API Refactor: 精简公开接口，删除 serde/Builder

## 决策记录

### 核心改动

1. **Trait 重命名与可见性**：`trait Sandbox` -> `trait SandboxImpl`（去掉 `pub`），内部 crate 可见。新增 `pub struct Sandbox` 作为对外公开的包装类型，持有 `Box<dyn SandboxImpl>` 并暴露 `execute()` -> `(CommandOutput, ExitReason)`。

2. **删除 `SandboxConfigBuilder`**：Builder 模式在 Rust 社区虽常见，但对本项目而言过度设计。`SandboxConfig` 改为直接公开字段 + `with_*()` 方法，方法返回 `&mut Self` 支持链式调用。

3. **删除 serde/serde_json/toml 依赖**：当前 `SandboxConfig` 的 TOML 解析能力从未在实际场景中使用。CLI 侧通过 clap 直接解析参数并构造 config。删除序列化框架后 `SandboxConfig` 更轻量，编译更快，避免 serde 的宏膨胀。

4. **子配置内联**：`FilesystemConfig`、`NetworkConfig`、`TimeoutConfig` 从独立 struct 内联为 `SandboxConfig` 的直接字段。减少类型层级，用户无需跳转查找。

5. **`SandboxConfig::with_*()` 方法 + `into_sandbox()` 工厂**：
   - `with_*()` 方法直接修改字段，返回 `&mut Self`
   - `into_sandbox()` -> `Result<Box<dyn SandboxImpl>>` 调用平台特定的 `create_sandbox_impl()`

6. **`create_sandbox()` -> `create_sandbox_impl()`**：非 pub 函数，仅 crate 内部可见。

7. **`execute()` 返回类型**：从 `Result<CommandOutput>` 改为 `Result<(CommandOutput, ExitReason)>`，调用方无需额外调用 `classify_exit()`。

### 用户代码变化

```rust
// 旧 API — Builder + 两次调用
let config = SandboxConfig::builder()
    .with_unshare_all(true)
    .with_uid(1000)
    .with_landlock("/:ro")?
    .build()?;

let sandbox = create_sandbox(config)?;
let output = sandbox.execute(&spec)?;
let reason = sandbox.classify_exit(output.exit_code, output.blocked_syscall);

// 新 API — 链式 + 一次调用
let (output, reason) = SandboxConfig::default()
    .with_unshare_all()
    .with_uid(1000)
    .with_landlock("/:ro")?
    .into_sandbox()?
    .execute(&spec)?;
```

### 波及文件

| 文件 | 改动 |
|---|---|
| `src/config.rs` | 删除 Builder/serde/子配置，加 `with_*` 方法 |
| `src/lib.rs` | `Sandbox` -> `SandboxImpl`（非 pub），加 `pub struct Sandbox` 包装，`create_sandbox` -> `create_sandbox_impl` |
| `src/linux/mod.rs` | 同步 trait 重命名，`create_sandbox_impl` |
| `src/main.rs` | 删除 `build_config` 中的 Builder 调用 |
| `tests/config_test.rs` | 用 `with_*` 风格重写 |
| `tests/landlock_test.rs` | 更新 trait 引用 |
| `tests/seccomp_test.rs` | 更新 trait 引用 |
| `tests/namespace_test.rs` | 更新 trait 引用（如存在） |
| `examples/crate_api.rs` | 更新为 `with_*` 风格 |
| `Cargo.toml` | 删除 serde/serde_json/toml/thiserror |
| `docs/adr/0002-config-landlock-rules.md` | 更新或标记过期 |
