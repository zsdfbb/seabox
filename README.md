# sandbox-runtime-rs

一个轻量的 Rust 沙箱工具，**无需容器**即可在操作系统层面为任意进程强制施加文件系统与 syscall 限制。Linux 上使用 Landlock + seccomp，macOS 上使用 Seatbelt（计划中）。

## 为什么需要它

Agent 类编程工具（Claude Code、CodeWhale、Cursor……）会代表用户执行 shell 命令、修改文件。仅靠权限弹窗会让用户疲劳，最终形成"看见就点允许"的肌肉记忆。**内核级沙箱**以声明式方式强制执行策略：大多数命令无感放行，危险命令直接阻断，仅边缘情况弹窗。

本项目是 Anthropic `@anthropic-ai/sandbox-runtime` 的 Rust 原生、零外部依赖等价实现——任何 Agent 都可作为 crate 嵌入，也可作为 CLI 直接使用。

## 特性

- 🛡️ **Linux 文件系统 ACL**：基于 Landlock（5.13+），grant-only 模型
- 🚫 **Syscall 黑名单**：基于 seccomp BPF，13 个危险 syscall（mount、ptrace、kexec、reboot、bpf 等）
- 📦 **零外部依赖**：纯 Rust + 直接 syscall，不依赖 `bwrap`、`sandbox-exec`、Docker
- 🔌 **三种集成方式**：CLI 二进制、`pub trait Sandbox` crate API、TOML 配置
- 🎯 **三种预设策略**：`full-access` / `read-only` / `workspace`
- 🧪 **完整测试覆盖**：87 项集成测试，覆盖所有 13 个黑名单 syscall + 所有 Landlock 限制能力

## 平台支持

| 平台 | 状态 | 机制 |
|---|---|---|
| Linux 5.13+ | ✅ 可用 | Landlock + seccomp BPF |
| Linux 3.5 – 5.12 | ⚠️ 部分可用 | 仅 seccomp（无 Landlock 文件系统限制） |
| Linux < 3.5 | ❌ 不可用 | 内核不支持 seccomp |
| macOS | 🚧 计划中 | Seatbelt (`sandbox-exec`) |

## 安装

### 预编译二进制

```bash
# Linux x86_64 静态二进制（musl）
curl -L https://github.com/zsdfbb/sandbox-runtime-rs/releases/latest/download/sandbox-runtime-x86_64-linux-musl.tar.gz | tar xz
sudo mv sandbox-runtime /usr/local/bin/
```

### 从源码编译

```bash
git clone https://github.com/zsdfbb/sandbox-runtime-rs
cd sandbox-runtime-rs
cargo build --release
./target/release/sandbox-runtime --help
```

### 作为库依赖

```toml
[dependencies]
sandbox-runtime = "0.1"
```

## 快速开始

```bash
# 1. 检查当前系统沙箱能力
sandbox-runtime check
# Capability                    Status
# ----------------------------- --------------------
# Landlock                      available (ABI v7)
# Seccomp                       available

# 2. 在只读沙箱里跑一个命令
sandbox-runtime run --policy read-only -- cat /etc/passwd

# 3. 用项目级 TOML 配置
cp templates/workspace-write.toml.example .sandbox.toml
sandbox-runtime run --config .sandbox.toml -- cargo build

# 4. 检查内核版本
uname -r   # 需要 5.13+ 才能完整使用 Landlock
```

## CLI 使用

### 子命令

```
sandbox-runtime run [OPTIONS] <COMMAND>...
sandbox-runtime check
sandbox-runtime serve [--port 7878]
```

| 子命令 | 说明 |
|---|---|
| `run` | 在沙箱中执行命令 |
| `check` | 打印当前系统可用的 Landlock / seccomp 能力 |
| `serve` | 启动 HTTP API 守护进程（Phase 1 stub，尚未实现） |

### `run` 选项

| 选项 | 说明 |
|---|---|
| `-c, --config FILE` | TOML 配置文件路径 |
| `-p, --policy POLICY` | 策略预设：`full-access` / `read-only` / `workspace` |
| `-n, --allow-network` | 放通网络访问（Phase 1 占位） |
| `-w, --allow-write PATH` | 额外的可写路径（可重复） |
| `-d, --debug` | 调试日志（Phase 2 占位） |
| `--` | 分隔符，后续参数原样传给被沙箱化的命令 |

### 退出码约定

| 退出码 | 含义 |
|---|---|
| `0` | 命令成功执行 |
| `1` | CLI 参数错误（如未指定命令） |
| 命令原始退出码 | 命令自行以非零状态退出（与沙箱无关）|
| `125` | 沙箱内部错误 |
| `126` | 沙箱拒绝（Landlock 或 seccomp） |

拒绝时 stderr 会输出形如 `Sandbox denial (Landlock): Landlock blocked access: ...` 或 `Sandbox denial (Seccomp): Blocked by seccomp filter (SIGSYS)` 的诊断消息。

### 常用模式

```bash
# 只读模式（cat 可以，写全部拒绝）
sandbox-runtime run --policy read-only -- cat /etc/passwd

# 工作区模式（cwd + /tmp 可写，其余写拒绝）
sandbox-runtime run --policy workspace -- sh -c 'echo data > out.txt'

# 显式授予额外写路径
sandbox-runtime run --policy workspace --allow-write /var/log/app -- go build

# 使用 TOML 配置
sandbox-runtime run --config .sandbox.toml -- cargo build

# 完全绕过沙箱（危险，仅在确实需要时）
sandbox-runtime run --policy full-access -- rm -rf ./build

# 使用 -- 分隔符避免 clap 解析冲突
sandbox-runtime run -- cargo build --release
```

### ⚠️ 沙箱不会解释 shell 元字符

sandbox-runtime 通过 `execve` **直接执行单个程序**，**不**经过 shell。也就是说 `>`、`>>`、`|`、`*`、`&&` 等 shell 元字符会被当作普通字符传给 `execve`，导致 spawn 以 ENOENT 失败（找不到这个"程序"）。

需要 shell 语法时显式 spawn `sh -c`：

```bash
# ❌ 这样会失败：spawn 找不到叫 "echo 'hello' >> README.md" 的程序
sandbox-runtime run --policy read-only -- "echo 'hello' >> README.md"

# ✅ 这样才对：把整条 shell 命令作为 -c 的参数
sandbox-runtime run --policy read-only -- sh -c "echo 'hello' >> README.md"
```

sandbox-runtime 在 spawn 失败时会主动提示这条修改建议：

```
Error: Failed to spawn sandboxed process 'echo 'hello' >> README.md'.
Note: sandbox-runtime does NOT interpret shell metacharacters
(>, >>, |, *, &&, etc.) — it runs the program directly via execve.
To use shell syntax, invoke 'sh -c' explicitly, e.g.
`-- sh -c "your shell command here"`.
Or split the command into separate args without shell metacharacters.
```

## Crate API 使用

作为库嵌入时，通过 `SandboxConfig` + `LinuxSandbox` + `CommandSpec` 三件套构建并执行命令。

### Builder 构造配置

```rust
use sandbox_runtime::config::SandboxConfig;
use sandbox_runtime::linux::LinuxSandbox;
use sandbox_runtime::{CommandSpec, FsPolicy, Sandbox};
use std::time::Duration;

let config = SandboxConfig::builder()
    .policy(FsPolicy::WorkspaceWrite)
    .allow_write(vec!["/var/log/app".to_string()])
    .network_enabled(false)
    .timeout(60, 600)        // (default_secs, max_secs)
    .build();

let sandbox = LinuxSandbox { config };
```

### TOML 加载配置

```rust
let config = SandboxConfig::from_toml(".sandbox.toml")?;
```

### 执行命令

```rust
use std::collections::HashMap;

let spec = CommandSpec {
    program: "cargo".to_string(),
    args: vec!["build".to_string(), "--release".to_string()],
    cwd: std::env::current_dir()?,
    env: HashMap::new(),
    timeout: Duration::from_secs(60),
    sandbox_policy: FsPolicy::WorkspaceWrite,
};

let output = sandbox.execute(&spec)?;

println!("stdout: {}", output.stdout);
println!("stderr: {}", output.stderr);
println!("exit:   {}", output.exit_code);
```

### `Sandbox` trait

`LinuxSandbox` 实现平台无关的 `Sandbox` trait，未来 macOS 后端会提供 `MacOsSandbox`。集成方可以基于 trait 编写平台无关的代码：

```rust
fn run_on<T: Sandbox>(sandbox: &T, spec: &CommandSpec) -> anyhow::Result<CommandOutput> {
    sandbox.execute(spec)
}
```

完整示例见 `examples/crate_api.rs`。

## 策略配置

### 三种预设策略

| 策略 | 读权限 | 写权限 | 适用场景 |
|---|---|---|---|
| `full-access` | 全部 | 全部 | 不应被沙箱化的命令；紧急绕过 |
| `read-only` | 整个文件系统 | 无（全部拒绝） | 代码审查、grep、cat、analyze |
| `workspace-write` | 整个文件系统 | `/tmp` + cwd + `--allow-write` 路径 | 默认；构建、测试、编译 |

**FullAccess** 不调用 Landlock、不施加任何规则。**ReadOnly** 处理 read+write 访问但只授予 read（实现"全部写被拒"）。**WorkspaceWrite** 在 read on `/` 之上额外授予一组写路径。

### 三种配置方式（同一份定义）

#### 1. TOML 文件（推荐 — 项目级）

`sandbox.toml`：
```toml
[filesystem]
policy = "workspace"
allow_write = [".", "/tmp", "/var/log/app"]

[network]
enabled = false

[timeout]
default_secs = 30
max_secs = 300
```

调用：`sandbox-runtime run --config sandbox.toml -- <command>`

仓库 `templates/` 目录提供三套样板：`workspace-write.toml.example`、`read-only.toml.example`、`full-access.toml.example`。

#### 2. Builder Pattern（Crate API）

```rust
SandboxConfig::builder()
    .policy(FsPolicy::WorkspaceWrite)
    .allow_write(vec![".".to_string(), "/tmp".to_string()])
    .network_enabled(false)
    .timeout(30, 300)
    .build()
```

#### 3. CLI Flags（一次性场景）

```bash
sandbox-runtime \
    --policy workspace \
    --allow-write . \
    --allow-write /tmp \
    --allow-network \
    -- <command>
```

### 配置优先级

CLI flags 总是覆盖 TOML：

- `--policy` 覆盖 `filesystem.policy`
- `--allow-write`（任何非空列表）**完全替换** `filesystem.allow_write`（不追加）
- `--allow-network` 总是设置 `network.enabled`（无论 TOML 是什么）

### 路径展开

`allow_write` 列表支持 `~` 展开为主目录（运行时执行）：

```toml
allow_write = ["~/workspace", "/tmp"]
# 等价于
allow_write = ["/home/<user>/workspace", "/tmp"]
```

绝对路径和不以 `~` 开头的相对路径原样使用。

## 测试

```bash
cargo test                                    # 全部 87 项
cargo test --test landlock_test               # 仅 Landlock（19 项）
cargo test --test seccomp_test                # 仅 seccomp（15 项，逐 syscall 验证）
cargo test --test config_test                 # 仅配置解析（8 项）
cargo test bpf_blocked_by_seccomp             # 单项测试
cargo test -- --nocapture                     # 显示 stdout
```

Landlock / seccomp 测试在内核能力缺失时**自动跳过**（不是 fail）。详见 `CLAUDE.md` 的 "测试" 章节。

## 项目结构

```
src/
├── main.rs                 # CLI 入口
├── lib.rs                  # Sandbox trait + 公共类型
├── config.rs               # SandboxConfig + Builder
├── linux/
│   ├── mod.rs              # LinuxSandbox + pre_exec 编排
│   ├── landlock.rs         # Landlock ruleset 构造
│   └── seccomp.rs          # BPF 黑名单生成与加载
├── bin/
│   └── syscall_probe.rs    # 测试辅助二进制
├── macos/                  # Phase 3（计划中）
├── integration/            # CodeWhale adapter
└── api/                    # HTTP API（Phase 3 stub）

tests/                      # 集成测试
examples/                   # 可运行示例
templates/                  # TOML 配置样板
docs/                       # 详细设计文档
```

## 路线图

| Phase | 内容 | 状态 |
|---|---|---|
| 1 | Core + Linux 文件系统隔离（Landlock + seccomp + CLI） | ✅ |
| 2 | Linux 完整进程隔离（user_ns + netns + setrlimit） | 🚧 |
| 2b | eBPF 云容器后端（aya + cgroup_sock_addr） | 🚧 |
| 3 | macOS 支持（Seatbelt） | 🚧 |
| 4 | CodeWhale 集成 + HTTP API（OpenSandbox v1 兼容）| 🚧 |

## 已知限制（Phase 1）

- **超时未实现**：`CommandSpec::timeout` 被收集但不强制执行。
- **网络未真正隔离**：`--allow-network` / `network.enabled` 是占位，未来通过 netns 或 eBPF 实现。
- **`serve` 子命令未实现**：HTTP API 是 stub。
- **macOS 未实现**：`LinuxSandbox` 之外的平台不支持。
- **`deny_read` 未实现**：Landlock grant-only 模型下，"已 grant 读后再 deny 子路径" 需要 Phase 2 用 bind mount 实现。

## 许可

MIT — 详见 [LICENSE](LICENSE)。

集成方请注意许可证兼容性：MIT 允许商用、修改、私用、再分发，但需要保留版权声明。