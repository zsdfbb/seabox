# sandbox-runtime-rs

一个轻量的 Rust 沙箱工具，**无需容器**即可在操作系统层面为任意进程强制施加文件系统与 syscall 限制。Linux 上使用 Landlock + seccomp，macOS 上使用 Seatbelt（计划中）。

## 为什么需要它

Agent 类编程工具（Claude Code、CodeWhale、Cursor……）会代表用户执行 shell 命令、修改文件。仅靠权限弹窗会让用户疲劳，最终形成"看见就点允许"的肌肉记忆。**内核级沙箱**以声明式方式强制执行策略：大多数命令无感放行，危险命令直接阻断，仅边缘情况弹窗。

## 特性

- 🛡️ **Linux 文件系统 ACL**：基于 Landlock（5.13+），grant-only 模型，支持 ABI v1-v7
- 🚫 **Syscall 黑名单**：基于 seccomp BPF USER_NOTIF，13 个危险 syscall（mount、ptrace、kexec、reboot、bpf 等），拒绝时携带 syscall 名/分类/号/架构的富诊断消息
- 📦 **零外部依赖**：纯 Rust + 直接 syscall，不依赖 `bwrap`、`sandbox-exec`、Docker
- 🔌 **两种集成方式**：CLI 二进制、`pub trait Sandbox` crate API
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
sandbox-runtime run --landlock '/:ro' -- cat /etc/passwd

# 3. 工作区模式（/tmp 可写）
sandbox-runtime run --landlock '/:ro' --landlock '/tmp:rw' -- sh -c 'echo data > /tmp/out.txt'

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
| `serve` | 启动 HTTP API 守护进程（stub，尚未实现） |

### `run` 选项

| 选项 | 说明 |
|---|---|
| `--landlock <PATH:PERM>` | Landlock 路径权限规则，格式 `path:perm1[,perm2...]`（可重复）。支持预设权限组合：`ro`/`rx`(读+执行)、`rw`(读+写)、`rwx`(rw+设备创建)、`all`(全部) |
| `-n, --allow-network` | 放通网络访问（当前占位，未生效） |
| `-d, --debug` | 调试输出（当前占位） |
| `--` | 分隔符，后续参数原样传给被沙箱化的命令 |

### 退出码约定

| 退出码 | 含义 |
|---|---|
| `0` | 命令成功执行 |
| `1` | CLI 参数错误（如未指定命令） |
| 命令原始退出码 | 命令自行以非零状态退出（与沙箱无关）|
| `125` | 沙箱内部错误 |
| `126` | 沙箱拒绝（Landlock 或 seccomp） |

拒绝时 stderr 会输出形如 `Blocked by seccomp filter (SIGSYS): syscall='mount' category='mount' nr=165 arch=0xc000003e reason=blacklist signal=SIGSYS` 的诊断消息。

### 常用模式

```bash
# 只读模式（cat 可以，写全部拒绝）
sandbox-runtime run --landlock '/:ro' -- cat /etc/passwd

# 工作区模式（/tmp 可写，其余写拒绝）
sandbox-runtime run --landlock '/:ro' --landlock '/tmp:rw' -- cargo build

# 完全绕过沙箱（不指定 landlock）
sandbox-runtime run -- ls -la

# 使用 -- 分隔符避免 clap 解析冲突
sandbox-runtime run -- cargo build --release
```

### ⚠️ 沙箱不会解释 shell 元字符

sandbox-runtime 通过 `execve` **直接执行单个程序**，不经过 shell。`>`、`>>`、`|`、`*`、`&&` 等 shell 元字符会被当作普通字符传给 `execve`。

```bash
# ❌ 这样会失败：spawn 找不到叫 "echo 'hello' >> README.md" 的程序
sandbox-runtime run -- "echo 'hello' >> README.md"

# ✅ 这样才对：把整条 shell 命令作为 -c 的参数
sandbox-runtime run -- sh -c "echo 'hello' >> /tmp/test.out"
```

sandbox-runtime 在 spawn 失败时会主动提示这条修改建议。

## Crate API 使用

作为库嵌入时，通过 `SandboxConfig` + `LinuxSandbox` + `CommandSpec` 三件套。

### Builder 构造配置

```rust
use sandbox_runtime::config::SandboxConfig;
use sandbox_runtime::linux::LinuxSandbox;
use sandbox_runtime::{CommandSpec, LandlockPerm, LandlockRule, Sandbox};
use std::time::Duration;

let config = SandboxConfig::builder()
    .landlock(vec![
        LandlockRule {
            path: "/".into(),
            perms: vec![LandlockPerm::Execute, LandlockPerm::ReadFile, LandlockPerm::ReadDir],
        },
        LandlockRule {
            path: "/tmp".into(),
            perms: vec![
                LandlockPerm::Execute, LandlockPerm::ReadFile, LandlockPerm::ReadDir,
                LandlockPerm::WriteFile, LandlockPerm::MakeDir, LandlockPerm::MakeReg,
                LandlockPerm::RemoveDir, LandlockPerm::RemoveFile, LandlockPerm::Truncate,
            ],
        },
    ])
    .network_enabled(false)
    .timeout(60, 600)
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
    program: "cat".to_string(),
    args: vec!["/etc/passwd".to_string()],
    cwd: std::env::current_dir()?,
    env: HashMap::new(),
    timeout: Duration::from_secs(30),
};

let output = sandbox.execute(&spec)?;

match sandbox.classify_exit(output.exit_code, output.blocked_syscall) {
    ExitReason::Ok => println!("Success"),
    ExitReason::Denied { mechanism, message } => {
        eprintln!("Denied ({mechanism:?}): {message}");
    }
    ExitReason::Program(code) => eprintln!("Exit code: {code}"),
    ExitReason::InternalError(msg) => eprintln!("Error: {msg}"),
}
```

### `Sandbox` trait

`LinuxSandbox` 实现平台无关的 `Sandbox` trait：

```rust
fn run_on<T: Sandbox>(sandbox: &T, spec: &CommandSpec) -> anyhow::Result<CommandOutput> {
    sandbox.execute(spec)
}
```

## 配置

`SandboxConfig` 包含三个部分：

```rust
pub struct SandboxConfig {
    pub filesystem: FilesystemConfig,  // landlock: Vec<LandlockRule>
    pub network: NetworkConfig,        // enabled: bool
    pub timeout: TimeoutConfig,        // default_secs, max_secs
}
```

每条 `LandlockRule` 包含路径和一组权限。权限支持预设组合（`ro`/`rx`/`rw`/`rwx`/`all`）和 16 个个体权限。空规则列表 = 不激活 Landlock。

TOML 示例：

```toml
[filesystem]
landlock = [
  { path = "/", perms = ["execute", "read-file", "read-dir"] },
  { path = "/tmp", perms = ["execute", "read-file", "read-dir", "write-file",
    "remove-dir", "remove-file", "make-dir", "make-reg", "make-sym", "truncate"] },
]

[network]
enabled = false

[timeout]
default_secs = 30
max_secs = 300
```

路径中的 `~` 前缀在运行时展开为 `$HOME`。

## Project Structure

```
src/
├── main.rs                 # CLI 入口（clap derive）
├── lib.rs                  # Sandbox trait + 公共类型
├── config.rs               # SandboxConfig + Builder
├── linux/
│   ├── mod.rs              # LinuxSandbox + USER_NOTIF worker
│   ├── landlock.rs         # Landlock ruleset 构建
│   └── seccomp.rs          # BPF 黑名单生成与 USER_NOTIF 安装
├── bin/
│   └── syscall_probe.rs    # 测试辅助二进制

tests/          # 4 个集成测试文件（87 项）
examples/       # 3 个 stub 示例
docs/           # 详细设计文档
```

## 测试

```bash
cargo test                                    # 全部 87 项
cargo test --test landlock_test               # 仅 Landlock
cargo test --test seccomp_test                # 仅 seccomp（含逐 syscall 验证）
cargo test --test config_test                 # 仅配置解析
cargo test --test deny_detect_test            # 仅拒绝检测
cargo test -- --nocapture                     # 显示 stdout
```

Landlock / seccomp 测试在内核能力缺失时**自动跳过**（不是 fail）。

## 路线图

| Phase | 内容 | 状态 |
|---|---|---|
| 1 | Core + Linux 文件系统隔离（Landlock + seccomp + CLI） | ✅ 已完成 |
| 2 | Linux 完整进程隔离（user_ns + netns + 动态 seccomp） | 🚧 进行中 |
| 2b | eBPF 云容器后端（aya + cgroup_sock_addr） | 💡 计划中 |
| 3 | macOS 支持（Seatbelt） | 💡 计划中 |
| 4 | CodeWhale 集成 + HTTP API | 💡 计划中 |

## 已知限制（Phase 1）

- **超时未实现**：`CommandSpec::timeout` 被收集但不强制执行。
- **网络未真正隔离**：`--allow-network` 是占位，未来通过 netns 实现。
- **`serve` 子命令未实现**：HTTP API 是 stub。
- **macOS 未实现**：仅 Linux 后端可用。
- **无高层策略预设**：当前需用户逐条指定 `--landlock` 规则。

## 许可

MIT — 详见 [LICENSE](LICENSE)。
