# CLAUDE.md

本文件为 Claude Code (claude.ai/code) 在本仓库工作时提供指引。

## 项目概述

一个**独立**的 Rust 沙箱工具，在 OS 层面强制对任意命令施加文件系统与进程限制，**无需容器运行时**。目标平台：Linux（Landlock + seccomp + user_namespace）与 macOS（Seatbelt）。

### 动机

Agent 类编程工具（Claude Code、CodeWhale、Cursor……）会代表用户频繁执行 shell 命令、修改文件。仅靠权限弹窗并不够——它会让用户疲劳，最终形成"看见就点允许"的肌肉记忆。**内核级沙箱**以声明式方式强制执行策略：大多数命令无感放行，危险命令直接阻断，仅边缘情况弹窗。Anthropic 为 Claude Code 发布了 `@anthropic-ai/sandbox-runtime`；本项目是其**Agent 无关、Rust 原生、零外部依赖**的等价实现，任何 Agent 都可嵌入。

### 目标用户

- 需要沙箱后端的 Agent 运行时（CodeWhale、Claude Code、自研）
- 希望对命令做轻量隔离但又不想引入 Docker 的本地 CI runner
- 希望用声明式策略封装高风险 shell 命令的开发者

### 定位

| 对比项 | sandbox-runtime (TS) | CodeWhale sandbox (Rust) | sandbox-runtime-rs (目标) |
|---|---|---|---|
| Linux 方案 | bwrap | Landlock（标记态） + 可选 bwrap | **Landlock + seccomp + user_namespace，零外部依赖** |
| 集成方式 | CLI wrap | 内嵌模块 | **CLI + crate + HTTP API** |
| 网络策略 | 代理级域名过滤 | 仅标记 | **netns 全阻断或全放通** |
| macOS 方案 | sandbox-exec | sandbox-exec | sandbox-exec（Seatbelt profile） |
| 分发 | npm | 随 CodeWhale 发布 | **crates.io + 静态二进制** |
| Agent 绑定 | Claude Code | CodeWhale | **Agent 无关** |

### 与 Docker 的关系

本工具**不是** Docker 的替代品，它处在隔离强度/开销曲线上的不同位置：

| | Docker | sandbox-runtime-rs |
|---|---|---|
| 文件系统 | 独立 rootfs（镜像） | 共享宿主机 rootfs，Landlock ACL |
| 进程视图 | 6 个 namespace（PID 1 隔离） | 共享 `/proc`（除非用 user_ns），内核边界 |
| 资源 | cgroup v1/v2 | setrlimit + 可选 cgroup |
| 启动 | 数百毫秒 + 守护进程 | 几毫秒，单个静态二进制 |
| 适用场景 | 不可信代码、多租户 | 可信 Agent 命令、防御性加固 |

运行真正不可信的代码时用 Docker；约束可信 Agent 时用 sandbox-runtime-rs。

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
│   ├── api/
│   │   └── http.rs             # axum 服务器, POST /v1/sandbox/run
│   └── bin/
│       └── syscall_probe.rs    # seccomp 测试辅助二进制：直接调用任意 syscall
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
| `tests/landlock_test.rs` | Landlock 实际行为测试（库 API + CLI 二进制，需要 5.13+） |
| `tests/seccomp_test.rs` | seccomp 黑名单 13 个 syscall 端到端测试（CLI 二进制） |
| `tests/deny_detect_test.rs` | 拒绝检测模式匹配测试 |
| `tests/config_test.rs` | 配置解析测试 |
| `src/bin/syscall_probe.rs` | seccomp 测试辅助二进制：直接调用任意 syscall 编号 |
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
cargo run -- run ls -la
cargo run -- run --policy read-only ls -la /
cargo run -- run --allow-network curl example.com
cargo run -- run --config .sandbox.toml cargo build

# 检查当前系统沙箱能力
cargo run -- check

# 测试
cargo test                          # 跑全部（库单元 + 集成 + 文档）
cargo test --lib                    # 仅库单元测试
cargo test --test <name>            # 指定集成测试文件（见下表）
cargo test <name_fragment>          # 按测试名过滤（如 cargo test allow）
cargo test -- --nocapture           # 显示每个测试的 stdout/stderr
cargo test -- --nocapture --test-threads=1   # 串行 + 输出
cargo test --release                # release 构建后跑测试
cargo test -- --list                # 仅列出所有测试名，不跑

# 单独构建 seccomp 测试依赖的辅助二进制
cargo build --bin syscall_probe

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

### 测试安全

**绝不要**用 shell 外层重定向（`> file`、`>> file`）把 sandbox-runtime 的 stdout/stderr 写入本仓库里的任何工程文件（README、CLAUDE.md、源码、配置等），否则会绕过沙箱直接修改项目文件。

正确的写法：

```bash
# ❌ 危险：直接覆盖工程文件
./sandbox-runtime run -- sh -c "echo x" > README.md

# ✅ 写到 /tmp 或 tempdir
./sandbox-runtime run -- sh -c "echo x" > /tmp/test.out

# ✅ 用变量接住输出
out=$(./sandbox-runtime run -- sh -c "echo x")
echo "$out"
```

如果误改了工程文件，立即 `git checkout <file>` 恢复。

## 工作流约定（编辑批准门控）

Claude 在本仓库工作时**禁止直接编辑任何文件**——必须先列出改动计划、获得开发者明确同意后才能执行。

### 覆盖范围

以下操作**全部**需要事先批准：

- **修改文件**：`Edit`、`Write`、`NotebookEdit`，以及会改写仓库内文件的 Bash 命令（`sed -i`、`mv`、`cp` 目标在仓库路径等）
- **新建文件**：新模板、新示例、新测试、新文档、新配置文件
- **删除文件**：`rm` 或 `git rm`

### 不需要批准

- **只读操作**：`Read`、`Grep`、`Glob`、`LS`、`WebFetch`、`WebSearch`
- **仓库外的写入**：写到 `/tmp`、tempdir 等非仓库路径
- **git 只读操作**：`git status`、`git diff`、`git log`、`git blame`

### 流程

每次准备编辑前：

1. **列计划**：待改文件路径 + 改动性质（新增 / 修改 / 删除）+ 改动摘要
2. **给原因**：一句话说明必要性
3. **明确提问**：例如「我准备修改 X、Y、Z 三个文件，可以开始吗？」
4. **等显式确认**：开发者回复「可以」「yes」「同意」「批准」等明确指令后才动手

### 批量豁免

开发者若在本轮明确说「直接改」「不用问了」「全权处理」之类指令，本次会话内可放宽限制，但仍应在响应里简要说明改了什么。

## 测试

测试结构按"能力维度"分文件，每个集成测试都是独立二进制：

| 文件 | 验证内容 | 前置 |
|---|---|---|
| `tests/config_test.rs` | `SandboxConfig` 的 TOML / Builder / 展开行为 | 无 |
| `tests/deny_detect_test.rs` | `classify_exit()` 在各种 exit_code + stderr 组合下的分类 | Linux |
| `tests/landlock_test.rs` | Landlock 实际 ACL 行为（库 API）+ CLI 二进制（策略→规则→拒绝消息）| Linux 5.13+ |
| `tests/seccomp_test.rs` | 黑名单 13 个 syscall 端到端触发 + CLI 二进制拒绝消息 | Linux 3.5+ |

跳过与预检：
- 内核能力缺失时（无 Landlock / 无 seccomp）测试**自动跳过**（打印
  `Landlock not available, skipping test`），不是 fail。
- 真正会写入主机或触发特权操作的测试在跑前先做**探针**：跑一次已知
  应被拒绝的操作确认机制生效（`verify_seccomp_active` /
  `verify_landlock_active`）。探针结果用 `OnceLock` 缓存，
  整个 session 只跑一次。
- 所有写入主机的目标路径都用 PID 化（`.sandbox_runtime_*_<pid>`），
  测试结束 best-effort 清理。

辅助二进制 `src/bin/syscall_probe.rs`：
- 接受 `syscall_nr [arg0..arg5]`，直接调用 `libc::syscall`。
- 测试用它来逐个触发 seccomp 黑名单的 13 个 syscall，绕过 util-linux
  unshare 改用 `clone3` 等实现差异。
- 通过 `env!("CARGO_BIN_EXE_syscall_probe")` 让集成测试获取路径。

常见组合：
```bash
# 改完代码的最小循环
cargo build --tests && cargo test --lib

# Landlock 二进制层验证
cargo test --test landlock_test -- --nocapture

# 全部 seccomp 测试（含逐 syscall 验证）
cargo test --test seccomp_test

# 跑全部并查看哪些被跳过
cargo test -- --nocapture 2>&1 | grep skipping
```