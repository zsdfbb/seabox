# Architecture

## System Overview

```
┌───────────── API 层 ─────────────┐
│                                   │
│  CLI (seabox <cmd>)      │
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

## Core Trait

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

## Module Map

| 模块 | 路径 | 说明 |
|---|---|---|
| `Sandbox` trait | `src/lib.rs` | 平台无关抽象 |
| `SandboxConfig` | `src/config.rs` | serde 反序列化 + Builder |
| Linux 后端 | `src/linux/{mod,landlock,seccomp,namespace}.rs` | Landlock + seccomp + ns |
| macOS 后端 | `src/macos/{mod,seatbelt}.rs` | Seatbelt profile 生成 |
| HTTP API | `src/api/http.rs` | axum, OpenSandbox v1 兼容 |
| CodeWhale adapter | `src/integration/codewhale.rs` | 实现 `SandboxExecutor` |

详见 `project-structure.md` 中的目录树。