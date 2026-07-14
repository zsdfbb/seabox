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

```
sandbox-runtime (TypeScript, Anthropic)
│  依赖 Node.js + bwrap + socat
│
│                  sandbox-runtime-rs (Rust, 本仓库)
│                  │
│                  ├── 零外部依赖：静态编译单二进制
│                  ├── 优先集成 CodeWhale (crate 依赖，实现 SandboxExecutor trait)
│                  ├── 也可独立使用 (CLI / HTTP API)
│                  └── Linux 内核原生 Landlock + seccomp + user_namespace
│
CubeSandbox (Python, KVM-VM)
    硬件级隔离，适合多租户云部署
```

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

## Architecture

```
┌───────────── API 层 ─────────────┐
│                                   │
│  CLI (sandbox-runtime <cmd>)      │
│  Rust crate (pub trait Sandbox)   │
│  HTTP API (POST /v1/sandbox/run)  │
│                                   │
└────────┬──────────────────────────┘
         │
┌────────▼────── Core ──────────────┐
│                                   │
│  SandboxConfig → 策略解析         │
│  CommandSpec  → 命令规格          │
│  Sandbox trait → 平台无关抽象     │
│                                   │
└────────┬──────────────────────────┘
         │
┌────────▼──── Platform Backends ───┐
│                                   │
│  LinuxSandbox (本地):              │
│    Landlock ruleset (ABI v1/v2)   │
│    seccomp BPF filter             │
│    user_namespace + netns         │
│                                   │
│  LinuxEbpfSandbox (云容器, 未来):  │
│    aya + cgroup_sock_addr eBPF    │
│    cgroup v2 进程绑定              │
│    for Cloud/CI/容器环境           │
│                                   │
│  MacOsSandbox:                    │
│    Seatbelt profile 生成          │
│    sandbox-exec wrapper           │
│                                   │
└────────┬──────────────────────────┘
         │
┌────────▼──── Integration ─────────┐
│                                   │
│  CodeWhale SandboxExecutor adapt  │
│                                   │
└───────────────────────────────────┘
```

### Core Trait

```rust
/// 核心沙箱抽象 — CLI / HTTP / crate 使用者共享
pub trait Sandbox: Send + Sync {

    /// 包装命令：返回沙箱化的 Command + 环境变量
    /// CLI 模式和 spawn 前调用
    fn prepare(&self, spec: &CommandSpec) -> Result<PreparedCommand>;

    /// 直接执行：内部创建子进程，返回输出
    /// crate 使用者直接调用
    fn execute(&self, spec: &CommandSpec) -> Result<CommandOutput>;

    /// 判断退出码 + stderr 是否因沙箱拒绝导致
    fn classify_exit(&self, exit_code: i32, stderr: &str) -> ExitReason;
}

/// CodeWhale 集成：adapter 实现 codewhale_tui::sandbox::SandboxExecutor
/// 位于 src/integration/codewhale.rs
```

## Config File

`SandboxConfig` 结构体支持三种构造方式（同一份定义，serde 反序列化共享）：

**1. 用户项目提供的 TOML 文件（推荐）**

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

**2. Builder pattern（Crate API，CodeWhale 集成用）**

```rust
let config = SandboxConfig::builder()
    .policy(SandboxPolicy::WorkspaceWrite)
    .deny_read(vec!["~/.ssh"])
    .allow_write(vec![".", "/tmp"])
    .build();
let sandbox = LinuxSandbox::new(config)?;
```

**3. CLI flags（一次性场景）**

```bash
sandbox-runtime \
  --policy workspace \
  --deny-read ~/.ssh \
  --allow-write . \
  --allow-write /tmp \
  -- cargo build
```

本仓库的 `templates/` 目录提供各策略的样板文件，用户复制改名即可。

## CLI Interface

```
sandbox-runtime [OPTIONS] <COMMAND>...
sandbox-runtime check
sandbox-runtime serve [--port 7878]

  -c, --config FILE       配置文件
  -p, --policy POLICY     full-access | read-only | workspace
  -n, --allow-network     放通网络
  -w, --allow-write PATH  额外可写路径（可重复）
  -d, --debug             debug 日志
```

无子命令时默认走 "run" 模式，直接执行 `<COMMAND>...`。

### HTTP API (serve 模式)

兼容 OpenSandbox v1 协议，方便 CodeWhale 的 `SandboxBackend` trait 直接对接：

```http
POST /v1/sandbox/run
Content-Type: application/json

{"cmd": "ls -la", "env": {"KEY": "value"}}

→ 200 OK
{"stdout": "...", "stderr": "...", "exit_code": 0}
```

错误响应：`4xx` 表示请求不合法，`5xx` 表示沙箱内部错误。

## Linux 沙箱策略

最低支持内核：Linux 5.13（Landlock ABI v1）。低于 5.13 时 `sandbox-runtime check` 会报告不支持并退出非零。

所有机制均通过 Rust 直接调用内核 syscall，**零外部二进制依赖**：

| 维度 | 机制 | 内核要求 |
|---|---|---|
| 文件系统读写 | Landlock ruleset (`landlock_create_ruleset`, `landlock_add_rule`, `landlock_restrict_self`) | 5.13+ (ABI v1) |
| 危险 syscall 拦截 | seccomp BPF (`prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)`) | 3.5+ |
| 用户/UID 隔离 | `unshare(CLONE_NEWUSER)` | 3.8+ |
| 网络阻断（本地） | `unshare(CLONE_NEWNET)` + lo down | 2.6.24+ |
| 进程命名空间 | `unshare(CLONE_NEWPID)` *(可选, 见 Future Extensions)* | 2.6.24+ |
| 网络过滤（云容器，未来） | eBPF `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` + aya | 4.10+, cgroup v2 |
| 资源限制 | `setrlimit` (RLIMIT_AS, RLIMIT_NPROC, RLIMIT_NOFILE) | 长期 |

### 环境适配策略

Linux 后端根据运行环境自动选择最佳机制：

```
可用性矩阵：

                  本地笔记本    云 VM (KVM)    容器内 (K8s)
  Landlock         ✅             ❌ 常见关闭     ❌
  user_namespace   ✅             ⚠️ 受限         ❌ 无 CAP
  netns            ✅             ✅             ❌ 无 CAP_NET_ADMIN
  cgroup v2        ⚠️ 不一定      ✅             ✅
  eBPF             ✅             ✅             ✅

路由逻辑：
  首选 Landlock + netns（本地，零额外依赖）
  ↓ Landlock/netns 不可用时
  降级 eBPF + cgroup v2（云 VM / 容器）
  ↓ 都不支持时
  跳过沙箱，报 warning
```

### Landlock ABI 版本

- ABI v1 (5.13): `FS_READ_FILE`, `FS_WRITE_FILE`, `FS_READ_DIR`, `FS_EXECUTE`
- ABI v2 (5.19): `FS_TRUNCATE`
- ABI v3 (6.2): `FS_IOCTL_DEV`, `FS_REFER`（硬链接/重命名限制）

运行时通过 `landlock_create_ruleset(... LANDLOCK_CREATE_RULESET_VERSION)` 探测可用 ABI，按高到低降级到 v1。

## macOS 沙箱策略

通过 `sandbox-exec` 生成 Seatbelt profile（SBPL）：

```
profile 以 SBPL 格式动态生成，根据配置的 allow/deny 路径注入
(version 1)
(deny default)
(allow file-read* (subpath "/"))
(deny file-read* (subpath "/Users/secret"))
(allow file-write* (subpath "/tmp"))
(allow network* (loopback))
```

`SandboxManager::was_denied()` 检测 stderr 中的 `Sandbox: ... denied ...` / `Operation not permitted` 模式。

## Development Phases

```
Phase 1 ─── Core + Linux 文件系统隔离
 ├── Sandbox trait + Config + CommandSpec
 ├── Linux: Landlock ruleset 实现
 ├── Linux: seccomp 基础过滤（禁用 mount, ptrace, kexec 等）
 ├── CLI: sandbox-runtime <command>
 └── cargo test 验证允许/拒绝路径

Phase 2 ─── Linux 完整进程隔离
 ├── user_namespace（必需，netns 依赖）
 ├── netns 网络阻断
 ├── setrlimit 资源限制
 └── 自定义 seccomp 策略

Phase 2b ─── eBPF 云容器后端（未来扩展）
 ├── aya eBPF 库集成
 ├── BPF_PROG_TYPE_CGROUP_SOCK_ADDR connect 拦截
 ├── BPF_MAP_TYPE_LPM_TRIE 白名单 IP 前缀
 ├── 用户态 DNS 解析 + IP 集同步
 ├── 自动探测 Landlock → eBPF 降级
 └── K8s/Docker 内验证

Phase 3 ─── macOS 支持
 ├── Seatbelt profile 动态生成
 ├── sandbox-exec 包装
 ├── 拒绝检测
 └── 跨平台 Sandbox enum（Linux | MacOs | None）

Phase 4 ─── CodeWhale 集成
 ├── adapter → codewhale::sandbox::SandboxExecutor
 ├── CodeWhale 的 SandboxManager 改用本 crate
 └── HTTP API serve 模式（OpenSandbox 兼容）
```

## Future Extensions（暂不实现，路线预留）

### 动态授权：Violation Hook + SECCOMP_RET_USER_NOTIF

当前 Phase 1-4 的策略都是**静态配置 + 明确拒绝**。未来需要 Agent 在沙箱拒绝时**主动询问用户**或根据运行时上下文调整策略，可考虑以下机制：

**Violation Hook（轻量）**

```rust
pub trait Sandbox: Send + Sync {
    /// 沙箱拒绝前回调，让上层决定如何处理
    /// 默认 = 直接拒绝
    fn on_violation(&self, event: &ViolationEvent) -> ViolationDecision {
        ViolationDecision::Deny
    }
}

pub enum ViolationDecision {
    AllowOnce,    // 这次放行
    AllowPersist, // 加入 allowlist
    Deny,
}
```

实现方式：
- `execute()` 前预判可能的 violation，统一询问
- 用户返回决策 → 动态调整 Landlock ruleset → re-exec

**SECCOMP_RET_USER_NOTIF（重量，5.0+ 内核）**

```
沙箱进程 syscall 被 BPF 拦截
  ↓
内核挂起 syscall，挂到 notify fd
  ↓
policy manager 进程通过 ioctl 读 syscall 详情
  ↓
决策后返回 SECCOMP_RET_ALLOW / SECCOMP_RET_ERRNO
```

适用场景：
- 文件访问的细粒度运行时决策（不仅是路径白名单）
- 网络连接的运行时决策（域名级而非 IP 级）
- 需要"暂时提升权限"的安全模式（如一次性 token）

实现复杂度：需要 supervisor 进程管理 notify fd，比单进程方案复杂。**只在前述场景明确出现时再实现**。

### eBPF 云容器后端

见 Phase 2b（环境适配策略部分）。

### 网络代理（macOS / 兜底）

代理模式仅在 Landlock/eBPF 不可用时作为 fallback。需要时再引入。

### PID namespace

防御深度特性，不是必需。Phase 2 末评估后再决定是否纳入。

## Project Structure

```
src/
├── main.rs                    # CLI 入口（clap）
├── lib.rs                     # pub trait Sandbox, pub types
├── config.rs                  # SandboxConfig 解析（serde + toml）
├── linux/
│   ├── mod.rs                 # LinuxSandbox 结构体 + dispatch
│   ├── landlock.rs            # landlock_create_ruleset / add_rule / restrict_self
│   ├── seccomp.rs             # 预编译 BPF 规则 + prctl 加载
│   └── namespace.rs           # unshare(CLONE_NEW*) + setrlimit
├── macos/
│   ├── mod.rs                 # MacOsSandbox 结构体 + dispatch
│   └── seatbelt.rs            # SBPL 模板生成 + sandbox-exec 包装
├── integration/
│   └── codewhale.rs           # → codewhale::sandbox::SandboxExecutor
└── api/
    └── http.rs                # axum 服务器, POST /v1/sandbox/run

tests/
├── landlock_test.rs           # 实际 Landlock 行为测试（需要内核 5.13+）
├── deny_detect_test.rs        # 拒绝检测模式匹配测试
└── config_test.rs             # 配置解析测试

examples/
├── cli_basic.rs               # 通过 CLI flags 构造 config 并执行
├── cli_from_toml.rs           # 从 TOML 文件加载 config 并执行（默认用 templates/ 下的样板）
├── crate_api.rs               # 通过 crate API 直接调用 Sandbox
├── codewhale_adapter.rs       # CodeWhale SandboxExecutor adapter 使用示例
└── http_server.rs             # 启动 HTTP API 守护进程示例

templates/                     # 配置模板（用户复制改写，examples 也引用它们）
├── workspace-write.toml.example
├── read-only.toml.example
├── full-access.toml.example
└── README.md                  # 模板说明 + 各策略适用场景
```

### Config File Strategy

```
本仓库不提供默认配置；仅提供 templates/ 目录下的样板

用户项目：  复制 templates/<policy>.toml.example → 自己的 .sandbox.toml
CLI 引用：  sandbox-runtime --config .sandbox.toml <command>
examples：  cli_from_toml.rs 默认读取 templates/workspace-write.toml.example 作 fixture

本仓库的 SandboxConfig 结构体：
  ├── 同一份定义供 CLI flags 和 TOML/JSON 共享
  ├── serde::Deserialize 实现供 TOML/JSON 解析
  ├── Builder pattern 供 programmatic 构造
  └── 由本仓库的 library API 暴露给集成方（如 CodeWhale）
```

### Example Binaries（参考 Anthropic sandbox-runtime）

通过 `cargo run --example <name>` 运行：

```bash
cargo run --example cli_basic -- ls -la
cargo run --example cli_from_toml -- --config templates/workspace-write.toml.example cargo build
cargo run --example crate_api              # 演示 crate API 嵌入
cargo run --example codewhale_adapter      # 演示与 CodeWhale 集成
cargo run --example http_server            # 启动 :7878 HTTP API
```

## Commands

```bash
# 构建
cargo build
cargo build --release

# 运行沙箱
cargo run -- ls -la
cargo run -- --policy read-only ls -la /
cargo run -- --allow-network curl example.com

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