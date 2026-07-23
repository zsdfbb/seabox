# CLAUDE.md

本文件为 Agent 工具在本仓库工作时提供指引。

## 项目概述

一个**独立**的 Rust 沙箱工具，在 OS 层面强制对任意命令施加文件系统与进程限制，**无需容器运行时**。当前目标平台：Linux（Landlock + seccomp）。

### 动机

Agent 类编程工具（Claude Code、CodeWhale、Cursor……）会代表用户频繁执行 shell 命令、修改文件。仅靠权限弹窗并不够——它会让用户疲劳，最终形成"看见就点允许"的肌肉记忆。**内核级沙箱**以声明式方式强制执行策略：大多数命令无感放行，危险命令直接阻断，仅边缘情况弹窗。

## 当前状态

- ✅ **Phase 1 已完成**：Landlock 文件系统 ACL + seccomp BPF 黑名单（13 syscall）+ CLI + 87 项集成测试
- 🚧 **Phase 2 进行中**：user_namespace + netns + 动态 seccomp 策略

## 文档索引

| 文档 | 内容 |
|---|---|
| [docs/architecture.md](docs/architecture.md) | 系统架构图 + Core trait + 模块职责映射 |
| [docs/linux-sandbox.md](docs/linux-sandbox.md) | Linux 内核能力矩阵 + Landlock ABI + seccomp 黑名单 |
| [docs/macos-sandbox.md](docs/macos-sandbox.md) | macOS Seatbelt 设计（尚未实现） |
| [docs/development-phases.md](docs/development-phases.md) | Phase 1-4 路线 + 依赖关系 + 当前状态 |
| [docs/future-extensions.md](docs/future-extensions.md) | 动态授权 / eBPF / PID ns（路线预留） |
| [docs/adr/0001-seccomp-user-notif-vs-sigsys.md](docs/adr/0001-seccomp-user-notif-vs-sigsys.md) | ADR 001：seccomp USER_NOTIF vs SIGSYS handler |
| [docs/adr/0002-config-landlock-rules.md](docs/adr/0002-config-landlock-rules.md) | ADR 002：SandboxConfig 扁平结构 + Raw Landlock 规则 |
| [docs/learned.md](docs/learned.md) | 跨会话经验教训（踩坑记录） |
| [CONTEXT.md](CONTEXT.md) | 领域词汇表 |

## 目录结构（实际状态）

```
sandbox-runtime-rs/
├── Cargo.toml
├── README.md
├── LICENSE                     # MIT
├── CLAUDE.md                   # 本文件
├── CONTEXT.md                  # 领域词汇表
├── docs/                       # 详细文档
│   ├── architecture.md
│   ├── linux-sandbox.md
│   ├── macos-sandbox.md        # 未实现
│   ├── development-phases.md
│   ├── future-extensions.md
│   ├── learned.md
│   ├── adr/
│   │   ├── 0001-seccomp-user-notif-vs-sigsys.md
│   │   └── 0002-config-landlock-rules.md
│   ├── design-final/
│   │   └── seccomp-deny-message.md
│   ├── design-plans/completed/
│   └── exec-plans/completed/
├── src/
│   ├── main.rs                 # CLI 入口（clap derive enum）
│   ├── lib.rs                  # pub trait Sandbox + 公共类型
│   ├── config.rs               # SandboxConfig serde + Builder
│   ├── linux/
│   │   ├── mod.rs              # LinuxSandbox + execute() + USER_NOTIF worker
│   │   ├── landlock.rs         # Landlock ruleset 构建
│   │   └── seccomp.rs          # BPF filter + USER_NOTIF 安装
│   └── bin/
│       └── syscall_probe.rs    # seccomp 测试辅助二进制
├── tests/
│   ├── config_test.rs          # 配置解析测试
│   ├── deny_detect_test.rs     # ExitReason 分类测试
│   ├── landlock_test.rs        # Landlock ACL 测试（需要 5.13+）
│   └── seccomp_test.rs         # 13 个黑名单 syscall 测试 + 正常退出
├── examples/                   # 当前均为 stub
│   ├── cli_basic.rs
│   ├── cli_from_toml.rs
│   └── crate_api.rs
```

## 常用命令

```bash
# 构建
cargo build
cargo build --release

# 运行沙箱
cargo run -- run --landlock '/:ro' -- cat /etc/passwd
cargo run -- run --landlock '/:ro' --landlock '/tmp:rw' -- cargo build
cargo run -- run --allow-network -- curl example.com       # 网络占位
cargo run -- run -- ls -la                                  # full-access
cargo run -- run --env FOO=bar -- sh -c 'echo $FOO'        # 设置环境变量
cargo run -- run --unsetenv HOME -- sh -c 'echo $HOME'     # 删除环境变量
cargo run -- run --clearenv --env PATH=/usr/bin -- ls       # 白名单模式

# 检查当前系统能力
cargo run -- check

# 测试
cargo test                          # 跑全部（库单元 + 集成 + 文档）
cargo test --lib                    # 仅库单元测试
cargo test --test <name>            # 指定集成测试文件
cargo test <name_fragment>          # 按测试名过滤
cargo test -- --nocapture           # 显示 stdout/stderr
cargo test -- --nocapture --test-threads=1   # 串行 + 输出
cargo test --release                # release 构建后跑

# 单独构建 seccomp 测试依赖的辅助二进制
cargo build --bin syscall_probe

# 代码质量
cargo clippy -- -D warnings
cargo fmt
cargo check
```

## 约定

- 错误处理：`anyhow`（CLI），`thiserror` 在 lib 错误类型中
- CLI 参数：`clap` derive API（`#[derive(Parser)]` enum）
- 配置：`serde` + TOML
- Linux syscall 常量从内核头文件直接翻译，在常量声明处注释内核版本和来源
- 所有 `unsafe` syscall 调用封装在 safe 函数内，附 `// man:landlock_create_ruleset(2)` 格式引用
- `classify_exit()` 以结构化 `blocked: Option<(u32, u32)>` 作为首选判断依据
- 交叉编译目标：`x86_64-unknown-linux-musl`（静态链接），`aarch64-apple-darwin`
- License: MIT（见 `/LICENSE`）
- **CLI + Crate API 对应**：每个 CLI flag 都应有对应的 crate 层 `with_*` 方法。
  沙箱配置（`--unshare-user`、`--landlock` 等）对应 `SandboxConfig::with_*`；
  命令规格（`--env`、`--clearenv`、`--chdir` 等）对应 `CommandSpec::with_*`。
  新增 CLI flag 时先检查对应 struct 上是否存在 `with_*` 方法，没有就一并添加。

## 测试

测试结构按"能力维度"分文件，每个集成测试都是独立二进制：

| 文件 | 验证内容 | 前置 |
|---|---|---|
| `tests/config_test.rs` | `SandboxConfig` 的 TOML / Builder / 展开行为 | 无 |
| `tests/deny_detect_test.rs` | `classify_exit()` 在各种 exit_code + blocked 组合下的分类 | Linux |
| `tests/landlock_test.rs` | Landlock 实际 ACL 行为（库 API + CLI 二进制） | Linux 5.13+ |
| `tests/seccomp_test.rs` | 黑名单 13 个 syscall 端到端触发 + CLI 二进制拒绝消息 | Linux + seccomp |

跳过与预检：
- 内核能力缺失时（无 Landlock / 无 seccomp）测试**自动跳过**（打印 `Landlock not available, skipping test`），不是 fail。
- 真正会写入主机或触发特权操作的测试在跑前先做**探针**：跑一次已知应被拒绝的操作确认机制生效。探针结果用 `OnceLock` 缓存。

辅助二进制 `src/bin/syscall_probe.rs`：
- 接受 `syscall_nr [arg0..arg5]`，直接调用 `libc::syscall`。
- 测试用它来逐个触发 seccomp 黑名单的 13 个 syscall。
- 通过 `env!("CARGO_BIN_EXE_syscall_probe")` 让集成测试获取路径。

常见组合：
```bash
cargo build --tests && cargo test --lib
cargo test --test seccomp_test             # 全部 seccomp 测试（含逐 syscall 验证）
cargo test --test landlock_test            # Landlock 二进制层验证
cargo test -- --nocapture 2>&1 | grep skipping
```

### 测试安全

**绝不要**用 shell 外层重定向（`> file`、`>> file`）把 sandbox-runtime 的 stdout/stderr 写入本仓库里的任何工程文件（README、CLAUDE.md、源码、配置等），否则会绕过沙箱直接修改项目文件。

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

## 经验教训

跨会话累积踩坑记录，详见 [docs/learned.md](docs/learned.md)。
