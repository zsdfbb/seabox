# Configuration

`SandboxConfig` 结构体支持三种构造方式（同一份定义，serde 反序列化共享）。

## 1. TOML 文件（推荐 — 用户项目级别）

```toml
# 用户项目里 .sandbox.toml
[filesystem]
deny_read = ["~/.ssh", "~/.aws"]
allow_read = ["."]
allow_write = [".", "/tmp"]
deny_write = [".env", "config/production.json"]

[network]
enabled = false

[timeout]
default = "30s"
max = "300s"

[sandbox]
# 策略预设
#   full-access = 绕过沙箱
#   read-only   = 只读
#   workspace   = 工作区可写（默认）
policy = "workspace"
```

引用：`sandbox-runtime --config .sandbox.toml <command>`

## 2. Builder Pattern（Crate API — CodeWhale 集成）

```rust
let config = SandboxConfig::builder()
    .policy(SandboxPolicy::WorkspaceWrite)
    .deny_read(vec!["~/.ssh"])
    .allow_write(vec![".", "/tmp"])
    .build();
let sandbox = LinuxSandbox::new(config)?;
```

## 3. CLI Flags（一次性场景）

```bash
sandbox-runtime \
  --policy workspace \
  --deny-read ~/.ssh \
  --allow-write . \
  --allow-write /tmp \
  -- cargo build
```

## Config File Strategy

本仓库不提供默认配置；仅在 `templates/` 目录提供样板。

```
用户项目：  复制 templates/<policy>.toml.example → 自己的 .sandbox.toml
CLI 引用：  sandbox-runtime --config .sandbox.toml <command>
examples：  cli_from_toml.rs 默认读取 templates/workspace-write.toml.example 作 fixture
```

`SandboxConfig` 结构体：
- 同一份定义供 CLI flags 和 TOML/JSON 共享
- `serde::Deserialize` 实现供 TOML/JSON 解析
- Builder pattern 供 programmatic 构造
- 由 library API 暴露给集成方（如 CodeWhale）