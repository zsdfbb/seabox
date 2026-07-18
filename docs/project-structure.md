# Project Structure

## 目录树

```
sandbox-runtime-rs/
├── Cargo.toml
├── README.md
├── LICENSE                     # MIT
├── CLAUDE.md                   # 本文件 — 入口索引
├── docs/                       # 详细文档（按需查阅）
│   ├── architecture.md         # 系统架构
│   ├── project-structure.md    # 本文件
│   ├── config.md               # 配置格式详解
│   ├── cli.md                  # CLI 接口
│   ├── http-api.md             # HTTP API (OpenSandbox v1 兼容)
│   ├── linux-sandbox.md        # Linux 沙箱策略
│   ├── macos-sandbox.md        # macOS 沙箱策略
│   ├── development-phases.md   # 开发阶段路线
│   └── future-extensions.md    # 未来扩展（动态授权、eBPF、PID ns 等）
├── src/
│   ├── main.rs                 # CLI 入口（clap）
│   ├── lib.rs                  # pub trait Sandbox, pub types
│   ├── config.rs               # SandboxConfig 解析（serde + toml）
│   ├── linux/
│   │   ├── mod.rs              # LinuxSandbox 结构体 + dispatch
│   │   ├── landlock.rs         # landlock_create_ruleset / add_rule / restrict_self
│   │   ├── seccomp.rs          # 预编译 BPF 规则 + prctl 加载
│   │   └── namespace.rs        # unshare(CLONE_NEWUSER/NEWNET) + netns 配置
│   ├── macos/
│   │   ├── mod.rs              # MacOsSandbox 结构体 + dispatch
│   │   └── seatbelt.rs         # SBPL 模板生成 + sandbox-exec 包装
│   ├── integration/
│   │   └── codewhale.rs        # → codewhale::sandbox::SandboxExecutor
│   └── api/
│       └── http.rs             # axum 服务器, POST /v1/sandbox/run
├── tests/
│   ├── landlock_test.rs        # 实际 Landlock 行为测试（需要内核 5.13+）
│   ├── deny_detect_test.rs     # 拒绝检测模式匹配测试
│   └── config_test.rs          # 配置解析测试
├── examples/
│   ├── cli_basic.rs            # 通过 CLI flags 构造 config 并执行
│   ├── cli_from_toml.rs        # 从 TOML 文件加载 config（默认用 templates/ 样板）
│   ├── crate_api.rs            # 通过 crate API 直接调用 Sandbox
│   ├── codewhale_adapter.rs    # CodeWhale SandboxExecutor adapter 示例
│   └── http_server.rs          # 启动 HTTP API 守护进程示例
└── templates/                  # 配置模板（用户复制改写，examples 也引用）
    ├── workspace-write.toml.example
    ├── read-only.toml.example
    ├── full-access.toml.example
    └── README.md               # 模板说明 + 各策略适用场景
```

## 模块职责

| 目录 | 职责 |
|---|---|
| `src/linux/` | Linux 后端实现，Landlock/seccomp/namespace 三个底层能力 |
| `src/macos/` | macOS Seatbelt profile 动态生成 |
| `src/integration/` | 与外部 Agent (CodeWhale) 的 trait 适配 |
| `src/api/` | HTTP API 服务，提供 OpenSandbox v1 兼容端点 |
| `tests/` | 集成测试（需要真实内核能力） |
| `examples/` | 可运行的示例 binary（`cargo run --example <name>`） |
| `templates/` | TOML 配置样板（用户复制、examples 引用） |
| `docs/` | 按需查阅的详细文档（不读全也能开工） |