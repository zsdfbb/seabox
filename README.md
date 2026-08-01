# seabox

一个为 **AI Agent** 设计的**跨平台 OS 级沙箱**：在操作系统层面强制施加文件系统与进程限制，**无需容器运行时**。当前支持 **Linux**，macOS（Seatbelt）与更多平台在规划中。

**设计目标**：让 Agent 的命令执行默认受限，用可声明的策略建立安全边界。

- 跨平台：平台无关的 `Sandbox` trait，各平台用原生机制实现（Linux = Landlock + seccomp + namespaces；macOS = Seatbelt 规划中）
- 文件系统：**Landlock ACL**（路径级读/写/执行，声明式、零挂载）
- 进程隔离：**7 种 namespace**（user/ipc/mnt/pid/net/uts/cgroup）
- syscall 过滤：**动态 seccomp**（精确拦截 + USER_NOTIF 结构化诊断）
- 超时控制，防止命令无限挂起
- CLI + Crate API 双集成，结构化退出原因

> 名字取自 CodeWhale（鲸鱼）的栖息地 **sea** + sandbox 的 **box**——装着鲸鱼的那片海。

> 核心理念：Agent 每次执行命令都应默认受限。用户不需要对每个命令弹窗做判断——**配置一次策略，Agent 自动遵守**。

## 为什么需要它

Agent 会代表用户频繁执行 shell 命令、修改文件、运行构建。传统权限弹窗有两个根本缺陷：

1. **疲劳决策**：用户面对连续弹窗，最终形成"看见就点允许"的肌肉记忆
2. **粒度过粗**：要么全允许、要么全拒绝，没有中间态

**内核级沙箱**用**策略驱动**解决：用户事先声明文件系统权限（`--landlock /:ro --landlock /tmp:rw`）和 syscall 黑名单（`--seccomp-deny-nr 165`），Agent 在策略范围内自动放行，越界时精确拦截并给出结构化诊断。

## 特性

- 🛡️ **Landlock 文件系统 ACL**（5.13+，ABI v1-v7）：grant-only 白名单模型，路径级读/写/执行控制
- 🚫 **动态 seccomp**：`--seccomp-deny-nr <NR>` 用 USER_NOTIF 精确拦截指定 syscall（拒绝时携带 syscall 名/分类/号/架构的富诊断消息）；`--seccomp-filter-fd <FD>` 追加外部原始 cBPF
- 🧱 **7 种 namespace 隔离**：User / IPC / Mount / PID / Net / UTS / Cgroup，非 root 下 user ns 自动启用
- 🔗 **网络隔离与 loopback 控制**：`--unshare-net` 完全断网，`--allow-network` 放通 127.0.0.1
- 📦 **mount namespace**：`--bind` / `--ro-bind` / `--tmpfs`，无需 Docker 即可做只读根 + 可写目录
- ⏱️ **超时控制**：`--timeout` / `--timeout-max` 防止命令无限挂起
- 🌐 **环境控制**：`--env` / `--unsetenv` / `--clearenv`
- 🔌 **两种集成方式**：CLI 二进制 + `pub trait Sandbox` crate API（一一对应）
- 🧪 **90 项集成测试**：按能力维度分文件，内核能力缺失时自动跳过（不是 fail）

## 平台支持

| 平台 | 状态 | 机制 |
|---|---|---|
| Linux 5.13+ | ✅ | Landlock + seccomp + namespaces |
| Linux 3.5 – 5.12 | ⚠️ 部分可用 | seccomp（无 Landlock 文件系统限制） |

## 安装

### 从 crates.io

```bash
cargo install seabox
```

### 预编译二进制（musl 静态）

```bash
curl -L https://github.com/zsdfbb/seabox/releases/latest/download/seabox-x86_64-linux-musl.tar.gz | tar xz
sudo mv seabox /usr/local/bin/
```

### 从源码编译

```bash
git clone https://github.com/zsdfbb/seabox
cd seabox
cargo build --release
./target/release/seabox --help
```

### 作为库依赖

```toml
[dependencies]
seabox = "0.1"
```

## 快速开始

```bash
# 1. 检查当前系统沙箱能力
seabox check
# Capability                    Status
# ----------------------------- --------------------
# Landlock                      available (ABI v7)
# Seccomp                       available
# User namespace                available
# ...

# 2. 在只读沙箱里跑一个命令
seabox run --landlock '/:ro' -- cat /etc/passwd

# 3. 工作区模式（/tmp 可写，其余只读）
seabox run --landlock '/:ro' --landlock '/tmp:rw' -- sh -c 'echo data > /tmp/out.txt'

# 4. 完整隔离（所有 namespace + 断网）
seabox run --unshare-all -- ls -la
```

## CLI 使用

### 子命令

| 子命令 | 说明 |
|---|---|
| `run` | 在沙箱中执行命令 |
| `check` | 打印当前系统可用的 Landlock / seccomp / namespace 能力 |
| `serve` | HTTP API 服务器（尚未实现，该方向已暂缓，见路线图） |

### `run` 选项

**文件系统**

| 选项 | 说明 |
|---|---|
| `--landlock <PATH:PERM>` | Landlock 路径权限规则（可重复）。权限预设：`ro`（读+执行）/ `rw`（读写）/ `rwx`（+设备创建）/ `all`。示例：`--landlock '/:ro' --landlock '/tmp:rw'` |

**命名空间**（非 root 下 `--unshare-pid` / `--unshare-net` 自动叠加 user ns）

| 选项 | 说明 |
|---|---|
| `--unshare-all` | 隔离全部 7 种 namespace（user/ipc/mnt/pid/net/uts/cgroup） |
| `--unshare-user` / `--unshare-ipc` / `--unshare-mnt` / `--unshare-pid` / `--unshare-net` / `--unshare-uts` / `--unshare-cgroup` | 逐类隔离 |
| `--unshare-user-try` / `--unshare-cgroup-try` | 软性版本：内核不支持时静默回退 |

**网络**（语义：`--share-net` / `--allow-network` 会抑制 `--unshare-net`）

| 选项 | 说明 |
|---|---|
| `--unshare-net` | 隔离网络 namespace，lo DOWN，子进程无网络访问 |
| `-n, --allow-network` | 与 `--unshare-net` 组合时放通 loopback（127.0.0.1/8）；单独使用时等价于共享宿主机网络 |
| `--share-net` | bwrap 兼容别名，等价于 `--allow-network` |

**mount namespace**（需配合 `--unshare-mnt`，非 root 下还需 `--unshare-user`）

| 选项 | 说明 |
|---|---|
| `--bind <SRC> <DST>` | 可写递归 bind mount |
| `--ro-bind <SRC> <DST>` | 只读递归 bind mount |
| `--tmpfs <DST>` | 在 DST 挂载空的内存文件系统 |

**用户与主机名**

| 选项 | 说明 |
|---|---|
| `--uid <UID>` / `--gid <GID>` | 在 user ns 中映射的 uid/gid（需 `--unshare-user`） |
| `--hostname <NAME>` | 在 UTS ns 中设置主机名（需 `--unshare-uts`） |

**环境变量**

| 选项 | 说明 |
|---|---|
| `--env <KEY=VALUE>` | 设置或覆盖环境变量（可重复） |
| `--unsetenv <KEY>` | 删除环境变量（可重复） |
| `--clearenv` | 清空环境（不从父进程继承） |

**超时**

| 选项 | 说明 |
|---|---|
| `--timeout <SECS>` | 命令超时秒数（默认 30） |
| `--timeout-max <SECS>` | 超时上限秒数（默认 300，影响默认值上限） |

**seccomp**（动态策略，无默认黑名单——显式指定要拦截的 syscall）

| 选项 | 说明 |
|---|---|
| `--seccomp-deny-nr <NR>` | 用 USER_NOTIF 拦截指定 syscall 号（可重复）。常见号（x86_64）：165=mount、97=unshare、173=ptrace |
| `--seccomp-filter-fd <FD>` | 从 fd 读取原始 cBPF 字节码并追加到 filter 链 |

**其他**

| 选项 | 说明 |
|---|---|
| `--chdir <DIR>` | 覆盖工作目录 |
| `-d, --debug` | 调试输出 |
| `-- <COMMAND>...` | 要执行的命令（`--` 分隔选项与命令） |

### 退出码约定

| 退出码 | 含义 |
|---|---|
| `0` | 命令成功执行 |
| `125` | 沙箱内部错误 |
| `126` | 沙箱拒绝（Landlock / seccomp / namespace） |
| 命令原始退出码 | 命令自行以非零状态退出（与沙箱无关） |

拒绝时 stderr 输出结构化诊断，如 `Blocked by seccomp filter (SIGSYS): syscall='mount' category='mount' nr=165 arch=0xc000003e`。

### ⚠️ 沙箱不解释 shell 元字符

seabox 通过 `execve` **直接执行单个程序**，不经过 shell。`>`、`>>`、`|`、`*`、`&&` 等元字符会原样传给 `execve`。

```bash
# ❌ 失败：找不到名为 "echo 'hello' >> /tmp/out" 的程序
seabox run -- "echo 'hello' >> /tmp/out"

# ✅ 正确：整条 shell 命令作为 sh -c 的参数
seabox run -- sh -c "echo 'hello' >> /tmp/out"
```

## Crate API 使用

作为库嵌入时，通过 `SandboxConfig` + `CommandSpec` + `Sandbox` trait 三件套。每个 CLI flag 都有对应的 `with_*` 方法。

```rust
use seabox::config::SandboxConfig;
use seabox::{CommandSpec, ExitReason, Sandbox};
use std::path::PathBuf;
use std::time::Duration;

// ── 构建配置（等价于 CLI: --unshare-all --landlock '/:ro' --landlock '/tmp:rw'）──
let config = SandboxConfig::default()
    .with_unshare_all()
    .with_landlock("/:ro")?
    .with_landlock("/tmp:rw")?
    .with_timeout(10, 60);

// ── 创建沙箱（Linux 上用 Landlock + seccomp + namespace；其他平台返回错误）──
let sandbox = Sandbox::from_config(config)?;

// ── 命令规格 ──
let spec = CommandSpec::default()
    .with_program("sh")
    .with_args(["-c", "echo $MSG"])
    .with_cwd(PathBuf::from("/"))
    .with_clearenv()
    .with_env("MSG", "hello from seabox")
    .with_timeout(Duration::from_secs(5));

// ── 执行并检查结果 ──
let (output, reason) = sandbox.execute(&spec)?;
println!("exit_code: {}", output.exit_code);

match reason {
    ExitReason::Ok => println!("命令成功执行"),
    ExitReason::Denied { mechanism, message } => eprintln!("沙箱拒绝 ({mechanism:?}): {message}"),
    ExitReason::Program(code) => eprintln!("命令以非零退出码 {code} 退出"),
    ExitReason::InternalError(msg) => eprintln!("内部错误: {msg}"),
}
```

更多示例见 `examples/`：

- `cli_basic.rs`：基础用法（Landlock 规则 + 执行 + 结果处理）
- `cli_from_toml.rs`：TOML 配置 → `SandboxConfig` → 执行
- `crate_api.rs`：crate API 用法

## 测试

测试按"能力维度"分文件，共 **90 项集成测试**：

| 文件 | 验证内容 |
|---|---|
| `tests/config_test.rs` | `SandboxConfig` 的 TOML / Builder / 展开行为 |
| `tests/landlock_test.rs` | Landlock 实际 ACL 行为（需要 5.13+） |
| `tests/seccomp_test.rs` | `--seccomp-deny-nr` 逐 syscall 拦截 + 拒绝诊断 |
| `tests/namespace_test.rs` | 7 种 namespace 隔离 + uid/gid/hostname + chdir + env |
| `tests/mount_test.rs` | `--unshare-mnt` / `--bind` / `--ro-bind` / `--tmpfs` |
| `tests/network_test.rs` | netns 隔离 + `--allow-network` loopback 放通 |
| `tests/concurrent_fork_test.rs` | fork 后子进程零堆操作（多线程安全） |
| `tests/deny_detect_test.rs` | `classify_exit()` 退出原因分类 |

```bash
cargo test                          # 全部
cargo test --test namespace_test    # 指定文件
cargo test -- --nocapture           # 显示 stdout
```

内核能力缺失时（无 Landlock / 无 seccomp / 无 namespace）测试**自动跳过**，不是 fail。

## 路线图

| Phase | 内容 | 状态 |
|---|---|---|
| 1 | Core + Linux 文件系统隔离（Landlock + seccomp + CLI） | ✅ 已完成 |
| 2 | Linux 完整进程隔离（7 种 namespace + mount ns + 动态 seccomp + 网络隔离） | ✅ 已完成 |
| 2b | IP 级网络过滤（eBPF / nftables） | ⏸️ 已搁置（待 Phase 4 评估） |
| 3 | macOS 支持（Seatbelt） | 💡 计划中 |
| 4 | CodeWhale 集成 + HTTP API | 💡 计划中（HTTP API 经调研后暂缓，倾向本地 helper / Crate API 接入） |

详见 [docs/development-phases.md](docs/development-phases.md)。

## 已知限制

- **`serve` 子命令未实现**：HTTP API 方向经调研后暂缓——HTTP sandbox API 是"远程 microVM/容器沙箱"市场的标配，与本地 OS 沙箱的定位不符。
- **macOS 未实现**：仅 Linux 后端可用。
- **无高层策略预设**：当前需用户逐条指定 `--landlock` 规则。
- **网络仅 namespace 级隔离**：只有全断 / loopback 二态，无 IP 级过滤（Phase 2b 搁置）。
- **seccomp 无默认黑名单**：需显式用 `--seccomp-deny-nr` 指定要拦截的 syscall。

## 许可

MIT — 详见 [LICENSE](LICENSE)。
