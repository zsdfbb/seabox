# API Refactor 执行计划

```yaml
tasks:
  - id: config-rewrite
    type: impl
    description: "重写 config.rs: 删除 Builder/serde/内联子配置，加 with_* 方法"
    files: [src/config.rs]
    depends_on: []

  - id: config-test-rewrite
    type: test
    description: "重写 tests/config_test.rs: 用 with_* 风格测试，不涉及 TOML/Builder"
    files: [tests/config_test.rs]
    depends_on: [config-rewrite]

  - id: trait-rename
    type: impl
    description: "Sandbox -> SandboxImpl，create_sandbox -> create_sandbox_impl，加 Sandbox struct + SandboxConfig::into_sandbox"
    files: [src/lib.rs, src/linux/mod.rs]
    depends_on: [config-rewrite]

  - id: test-trait-update
    type: test
    description: "更新测试中引用 trait Sandbox -> SandboxImpl"
    files: [tests/landlock_test.rs, tests/seccomp_test.rs, tests/namespace_test.rs]
    depends_on: [trait-rename]

  - id: main-rs-update
    type: impl
    description: "更新 main.rs 使用新 API，删除 build_config 中的 Builder"
    files: [src/main.rs]
    depends_on: [trait-rename]

  - id: example-update
    type: impl
    description: "更新 crate_api 示例为 with_* 风格"
    files: [examples/crate_api.rs]
    depends_on: [trait-rename]

  - id: cargo-cleanup
    type: impl
    description: "从 Cargo.toml 删除 serde/serde_json/toml/thiserror，删除过期文档"
    files: [Cargo.toml, docs/adr/0002-config-landlock-rules.md]
    depends_on: [config-rewrite]

  - id: regression
    type: test
    description: "cargo clippy -- -D warnings + cargo fmt + 全量 cargo test"
    depends_on:
      - cargo-cleanup
      - main-rs-update
      - example-update
      - test-trait-update
      - config-test-rewrite
```
