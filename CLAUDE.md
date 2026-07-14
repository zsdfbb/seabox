# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A **standalone** Rust sandbox tool that enforces filesystem and process restrictions on arbitrary commands at the OS level, without requiring a container runtime. Targets Linux (Landlock + seccomp + user_namespace) and macOS (Seatbelt).

### Motivation

Agentic coding tools (Claude Code, CodeWhale, Cursor, …) routinely invoke shell commands and edit files on the user's behalf. Permission prompts alone are not enough — they fatigue the user, who then clicks "allow" reflexively. A **kernel-level sandbox** enforces policy declaratively: most commands run without interruption, dangerous ones are blocked outright, only edge cases surface a prompt. Anthropic shipped `@anthropic-ai/sandbox-runtime` for Claude Code; this project is the **Agent-agnostic, Rust-native, zero-external-dependency** equivalent that any Agent can embed.

### Target Users

- Agent runtimes that need a sandbox backend (CodeWhale, Claude Code, custom)
- Local CI runners that want lightweight command isolation without Docker
- Developers who want to wrap risky shell commands with declarative policy

### Positioning

| 对比项 | sandbox-runtime (TS) | CodeWhale sandbox (Rust) | sandbox-runtime-rs (目标) |
|---|---|---|---|
| Linux 方案 | bwrap | Landlock (标记态) + 可选 bwrap | **Landlock + seccomp + user_namespace, 零外部依赖** |
| 集成方式 | CLI wrap | 内嵌模块 | **CLI + crate + HTTP API** |
| 网络策略 | 代理级域名过滤 | 仅标记 | **netns 全阻断或全放通** |
| macOS 方案 | sandbox-exec | sandbox-exec | sandbox-exec（Seatbelt profile） |
| 分发 | npm | 随 CodeWhale 发布 | **crates.io + 静态二进制** |
| Agent 绑定 | Claude Code | CodeWhale | **Agent 无关** |

### Relationship to Docker

This tool is **not** a Docker replacement. It occupies a different point on the isolation/overhead curve:

| | Docker | sandbox-runtime-rs |
|---|---|---|
| File system | Independent rootfs (image) | Shares host rootfs, Landlock ACL |
| Process view | 6 namespaces (PID 1 isolated) | Same `/proc` (unless user_ns), kernel boundaries |
| Resources | cgroup v1/v2 | setrlimit + optional cgroup |
| Startup | Hundreds of ms + daemon | Few ms, single static binary |
| Use case | Untrusted code, multi-tenant | Trusted Agent commands, defensive depth |

Use Docker when running genuinely untrusted code; use sandbox-runtime-rs when constraining a trusted Agent.

## Documentation Index

详细设计按需查阅。开始一个新任务时，先看对应的文档再动手。

| 文档 | 内容 |
|---|---|
| [docs/architecture.md](docs/architecture.md) | 系统架构图 + Core trait + 模块职责映射 |
| [docs/project-structure.md](docs/project-structure.md) | 完整目录树 + 模块职责说明 |
| [docs/config.md](docs/config.md) | SandboxConfig 三种构造方式（TOML / Builder / flags）+ 模板策略 |
| [docs/cli.md](docs/cli.md) | CLI 接口 + 常用模式 + Examples |
| [docs/http-api.md](docs/http-api.md) | HTTP API（OpenSandbox v1 兼容）端点定义 |
| [docs/linux-sandbox.md](docs/linux-sandbox.md) | Linux 内核能力矩阵 + 环境适配策略 + Landlock ABI 版本 |
| [docs/macos-sandbox.md](docs/macos-sandbox.md) | macOS Seatbelt profile 映射 + 与 Linux 差异 |
| [docs/development-phases.md](docs/development-phases.md) | Phase 1-4 路线 + 依赖关系 |
| [docs/future-extensions.md](docs/future-extensions.md) | 动态授权 / eBPF / PID ns / 网络代理（路线预留） |

## Directory Tree（核心骨架）

```
sandbox-runtime-rs/
├── Cargo.toml
├── README.md
├── LICENSE                     # MIT
├── CLAUDE.md                   # 本文件 — 入口索引
├── docs/                       # 详细文档（按需查阅）
├── src/
│   ├── main.rs                 # CLI 入口（clap）
│   ├── lib.rs                  # pub trait Sandbox, pub types
│   ├── config.rs               # SandboxConfig 解析（serde + toml）
│   ├── linux/
│   │   ├── mod.rs              # LinuxSandbox 结构体 + dispatch
│   │   ├── landlock.rs         # landlock_create_ruleset / add_rule / restrict_self
│   │   ├── seccomp.rs          # 预编译 BPF 规则 + prctl 加载
│   │   └── namespace.rs        # unshare(CLONE_NEW*) + setrlimit
│   ├── macos/
│   │   ├── mod.rs              # MacOsSandbox 结构体 + dispatch
│   │   └── seatbelt.rs         # SBPL 模板生成 + sandbox-exec 包装
│   ├── integration/
│   │   └── codewhale.rs        # → codewhale::sandbox::SandboxExecutor
│   └── api/
│       └── http.rs             # axum 服务器, POST /v1/sandbox/run
├── tests/                      # 集成测试（需要真实内核能力）
├── examples/                   # 可运行示例 binary
└── templates/                  # TOML 配置样板（用户复制、examples 引用）
```

完整目录见 [docs/project-structure.md](docs/project-structure.md)。

## File Index

| 路径 | 用途 |
|---|---|
| `src/main.rs` | CLI 入口 |
| `src/lib.rs` | `pub trait Sandbox` + 公共类型 |
| `src/config.rs` | `SandboxConfig` serde 反序列化 + Builder |
| `src/linux/mod.rs` | `LinuxSandbox` 结构体 + dispatch |
| `src/linux/landlock.rs` | Landlock ruleset 构造 + restrict_self |
| `src/linux/seccomp.rs` | BPF 规则生成 + `prctl` 加载 |
| `src/linux/namespace.rs` | `unshare(CLONE_NEW*)` + setrlimit |
| `src/macos/mod.rs` | `MacOsSandbox` 结构体 + dispatch |
| `src/macos/seatbelt.rs` | SBPL 模板 + sandbox-exec wrapper |
| `src/integration/codewhale.rs` | CodeWhale `SandboxExecutor` adapter |
| `src/api/http.rs` | axum 服务器（OpenSandbox v1 兼容） |
| `tests/landlock_test.rs` | Landlock 实际行为测试（需要 5.13+） |
| `tests/deny_detect_test.rs` | 拒绝检测模式匹配测试 |
| `tests/config_test.rs` | 配置解析测试 |
| `examples/cli_basic.rs` | CLI flags 用法 |
| `examples/cli_from_toml.rs` | TOML 文件加载用法 |
| `examples/crate_api.rs` | crate API 用法 |
| `examples/codewhale_adapter.rs` | CodeWhale 集成示例 |
| `examples/http_server.rs` | HTTP API 服务示例 |
| `templates/*.toml.example` | 配置模板（workspace / read-only / full-access） |

## Commands

```bash
# 构建
cargo build
cargo build --release

# 运行沙箱
cargo run -- ls -la
cargo run -- --policy read-only ls -la /
cargo run -- --allow-network curl example.com
cargo run -- --config .sandbox.toml cargo build

# 检查当前系统沙箱能力
cargo run -- check

# 测试
cargo test
cargo test landlock                # 按名称过滤
cargo test -- --nocapture          # 显示 stdout
cargo test --test config_test      # 指定集成测试

# 代码质量
cargo clippy -- -D warnings
cargo fmt
cargo check

# 依赖审计
cargo audit
```

## Conventions

- 错误处理：`anyhow` (CLI/api), `thiserror` (lib 错误类型)
- CLI 参数：`clap` derive API
- 配置：`serde` + TOML
- Linux syscall 常量从内核头文件直接翻译，在常量声明处注释内核版本和来源（如 `include/uapi/linux/landlock.h`）
- 所有 `unsafe` syscall 调用封装在 safe 函数内，附 `// man:landlock_create_ruleset(2)` 格式引用
- `classify_exit()` 同时检查 `exit_code` 和 `stderr` 特征串
- 交叉编译目标：`x86_64-unknown-linux-musl`（静态链接），`aarch64-apple-darwin`
- License: MIT (per `/LICENSE`) — 注意集成方许可证兼容性