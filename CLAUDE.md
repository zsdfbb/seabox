# CLAUDE.md

本文件为 Agent 工具在本仓库工作时提供指引。

## 项目概述

一个为 **AI Agent 工具**（Claude Code、CodeWhale、Cursor……）设计的 Rust 沙箱。当 Agent 执行 shell 命令或修改文件时，本工具在 OS 层面强制施加文件系统与进程限制，**无需容器运行时**。目标是 **bubblewrap 的功能超集 + Landlock 文件系统 ACL**。

> 核心理念：Agent 每次执行命令都应默认受限。用户不需要对每个命令弹窗做判断——配置一次策略，Agent 自动遵守。

当前目标平台：Linux（Landlock + seccomp + namespaces）。后续规划：macOS（Seatbelt）。

### 与 bubblewrap 的定位差异

| 维度 | bubblewrap | sandbox-runtime |
|------|-----------|----------------|
| 文件系统 | 手动 bind mount（`--ro-bind` / `--tmpfs`） | **Landlock ACL**（`--landlock /:ro`，声明式、零挂载） |
| seccomp | 仅外部原始 BPF（`--seccomp FD`） | 外部 BPF + **`--seccomp-deny-nr` 精确拦截 + USER_NOTIF 诊断** |
| 超时控制 | 无 | `--timeout` / `--timeout-max` |
| 使用方式 | CLI only | CLI + **Crate API**（`SandboxConfig::with_*`） |
| 能力检查 | 无 | `sandbox-runtime check` |
| 外部网络 | `--share-net`（二选一） | `--allow-network`（与 `--unshare-net` 正交组合） |
| 特权降级 | `--cap-drop ALL` | **user ns 自动降级**（ns 内无特权） |

共同覆盖的 namespace/seccomp/environment 功能保持 CLI flag 级别的兼容。

### 动机

Agent 会代表用户频繁执行 shell 命令、修改文件、运行构建。传统权限弹窗有两个根本缺陷：
1. **疲劳决策**：用户面对连续弹窗，最终形成"看见就点允许"的肌肉记忆
2. **粒度过粗**：要么全允许、要么全拒绝，没有中间态

**内核级沙箱**解决这个问题的方式是**策略驱动**：用户事先声明文件系统权限（`--landlock /:ro --landlock /tmp:rw`）和 syscall 黑名单（`--seccomp-deny-nr 165`），Agent 在策略范围内自动放行，越界时精确拦截。

与面向人类用户的沙箱（bubblewrap、firejail）不同，本工具从 API 层面支持编程集成：`SandboxConfig` 可编程构造、`CommandSpec` 链式配置、结构化退出原因分类——适合嵌入 Agent 框架作为安全层。

## 当前状态

- ✅ **Phase 1**：Landlock 文件系统 ACL + seccomp BPF USER_NOTIF + CLI
- ✅ **Phase 2**：7 种命名空间隔离（User/IPC/Mount/PID/Net/UTS/Cgroup，含 `--unshare-mnt` / `--bind` / `--ro-bind` / `--tmpfs`）+ 动态 seccomp（`--seccomp-deny-nr` / `--seccomp-filter-fd`）+ 网络隔离与 loopback 控制（`--allow-network` / `--share-net`）
- ⏸️ **Phase 2b**：IP 级网络过滤（原计划 eBPF aya，已搁置待 Phase 4 时重新评估）
- 🚧 **Phase 3**：macOS Seatbelt 支持
- 🚧 **Phase 4**：CodeWhale 集成 + HTTP API（2026-08 调研后 HTTP API 暂缓——HTTP sandbox API 是"远程 microVM/容器沙箱"市场的标配，与本项目"本地 OS 沙箱"定位不符，详见 `docs/development-phases.md`）

## 文档索引

| 文档 | 内容 |
|---|---|
| [docs/architecture.md](docs/architecture.md) | 系统架构图 + Core trait + 模块职责映射 |
| [docs/linux-sandbox.md](docs/linux-sandbox.md) | Linux 内核能力矩阵 + Landlock ABI + seccomp 动态策略 + namespaces |
| [docs/macos-sandbox.md](docs/macos-sandbox.md) | macOS Seatbelt 设计（尚未实现） |
| [docs/development-phases.md](docs/development-phases.md) | Phase 1-4 路线 + 依赖关系 + 当前状态 |
| [docs/future-extensions.md](docs/future-extensions.md) | 动态授权 / 网络过滤 / PID ns（路线预留） |
| [docs/adr/0001-seccomp-user-notif-vs-sigsys.md](docs/adr/0001-seccomp-user-notif-vs-sigsys.md) | ADR 001：seccomp USER_NOTIF vs SIGSYS handler |
| [docs/adr/0002-config-landlock-rules.md](docs/adr/0002-config-landlock-rules.md) | ADR 002：SandboxConfig 扁平结构 + Raw Landlock 规则 |
| [docs/adr/0003-fork-after-zero-heap.md](docs/adr/0003-fork-after-zero-heap.md) | ADR 003：fork 后子进程零堆操作（多线程 safe） |
| [docs/arch/phase2-wrapup/](docs/arch/phase2-wrapup/) | Phase 2 收尾设计：`--allow-network` 方案、四方案对比、ADR、review |
| [docs/arch/mount-namespace/](docs/arch/mount-namespace/) | mount ns 设计：`--unshare-mnt` / `--bind` / `--ro-bind` / `--tmpfs`、ADR、review |
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
├── docs/
│   ├── architecture.md
│   ├── linux-sandbox.md
│   ├── macos-sandbox.md        # 未实现
│   ├── development-phases.md
│   ├── future-extensions.md
│   ├── learned.md
│   ├── adr/
│   │   ├── 0001-seccomp-user-notif-vs-sigsys.md
│   │   ├── 0002-config-landlock-rules.md
│   │   └── 0003-fork-after-zero-heap.md
│   ├── arch/
│   │   └── phase2-wrapup/      # --allow-network 设计
│   ├── design-final/
│   │   └── seccomp-deny-message.md
│   ├── design-plans/completed/
│   └── exec-plans/completed/
├── src/
│   ├── main.rs                 # CLI 入口（clap derive enum）
│   ├── lib.rs                  # pub trait Sandbox + 公共类型
│   ├── config.rs               # SandboxConfig + Builder + NamespacesConfig
│   ├── linux/
│   │   ├── mod.rs              # LinuxSandbox + execute() + USER_NOTIF worker
│   │   ├── child_setup.rs      # pre_exec 序列（unshare → mount → seccomp）
│   │   ├── landlock.rs         # Landlock ruleset 构建
│   │   ├── namespaces.rs       # 7 种 namespace unshare + 探测
│   │   ├── mount.rs            # RawMountOp + do_mounts + make_private
│   │   ├── net.rs              # netns + loopback 配置（SIOCSIFADDR）
│   │   └── seccomp.rs          # BPF filter + USER_NOTIF + prctl 安装
│   └── bin/
│       └── syscall_probe.rs    # seccomp 测试辅助二进制
├── tests/
│   ├── config_test.rs          # 配置解析测试
│   ├── concurrent_fork_test.rs # fork 后零堆操作（多线程安全）
│   ├── deny_detect_test.rs     # ExitReason 分类测试
│   ├── landlock_test.rs        # Landlock ACL 测试（需要 5.13+）
│   ├── mount_test.rs           # mount namespace 集成测试
│   ├── namespace_test.rs       # 21 个命名空间端到端测试
│   ├── network_test.rs         # 网络隔离 + loopback 控制测试
│   └── seccomp_test.rs         # seccomp 黑名单 + --seccomp-deny-nr 测试
├── examples/
│   ├── cli_basic.rs            # 基础用法（Landlock + 执行 + 结果处理）
│   ├── cli_from_toml.rs        # TOML 配置 → SandboxConfig → 执行
│   └── crate_api.rs            # crate API 用法
```

## 常用命令

```bash
# 构建
cargo build
cargo build --release

# 运行沙箱
cargo run -- run --landlock '/:ro' -- cat /etc/passwd
cargo run -- run --landlock '/:ro' --landlock '/tmp:rw' -- cargo build
cargo run -- run --unshare-net --allow-network -- curl example.com
cargo run -- run --unshare-all -- ls -la
cargo run -- run --env FOO=bar -- sh -c 'echo $FOO'
cargo run -- run --unsetenv HOME -- sh -c 'echo $HOME'
cargo run -- run --clearenv --env PATH=/usr/bin -- ls
cargo run -- run --seccomp-deny-nr 165 -- ls              # 拦截 mount
cargo run -- run --seccomp-deny-nr 165 --seccomp-deny-nr 97 -- ls

# 检查当前系统能力
cargo run -- check

# 测试
cargo test                          # 全部（库单元 + 集成 + 文档）
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
- **核心安全约束（ADR 0003）**：`fork()` 后到 `execve()` 之间，子进程只能使用 fork 前预分配的内存 + 纯 syscall。禁止任何堆操作，否则多线程 fork 时可能死锁。
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
| `tests/seccomp_test.rs` | 13 个黑名单 syscall + `--seccomp-deny-nr` + 拒绝消息 | Linux + seccomp |
| `tests/namespace_test.rs` | 7 种 namespace 隔离 + uid/gid/hostname + chdir + env | Linux |
| `tests/mount_test.rs` | mount ns（`--unshare-mnt` / `--bind` / `--ro-bind` / `--tmpfs`） | Linux |
| `tests/network_test.rs` | netns 隔离 + `--allow-network` loopback 放通 | Linux |
| `tests/concurrent_fork_test.rs` | fork 后子进程零堆操作（多线程安全） | Linux |

跳过与预检：
- 内核能力缺失时（无 Landlock / 无 seccomp / 无 namespace）测试**自动跳过**（打印 `Landlock not available, skipping test`），不是 fail。
- 真正会写入主机或触发特权操作的测试在跑前先做**探针**：跑一次已知应被拒绝的操作确认机制生效。探针结果用 `OnceLock` 缓存。

辅助二进制 `src/bin/syscall_probe.rs`：
- 接受 `syscall_nr [arg0..arg5]`，直接调用 `libc::syscall`。
- 测试用它来逐个触发 seccomp 黑名单的 13 个 syscall。
- 通过 `env!("CARGO_BIN_EXE_syscall_probe")` 让集成测试获取路径。

常见组合：
```bash
cargo build --tests && cargo test --lib
cargo test --test seccomp_test             # 全部 seccomp 测试（含逐 syscall 验证）
cargo test --test namespace_test           # 命名空间隔离测试
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
