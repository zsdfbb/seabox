# Phase 1: Core + Linux 文件系统隔离

## 1. 架构概要

Phase 1 实现 sandbox-runtime-rs 的核心骨架：一个**零外部二进制依赖**的 Linux 沙箱运行时，通过 Landlock + seccomp 在进程级别实施文件系统和系统调用限制。

系统分为四层：

```
┌───────────── API 层 ─────────────────┐
│                                       │
│  CLI (sandbox-runtime run <cmd>)      │
│  Rust crate (pub trait Sandbox)       │
│                                       │
├────────────── Core ───────────────────┤
│                                       │
│  SandboxConfig → 策略解析             │
│  CommandSpec  → 命令规格              │
│  Sandbox trait → 平台无关抽象         │
│                                       │
├─────────── Linux 后端 ────────────────┤
│                                       │
│  LinuxSandbox:                        │
│    Landlock ruleset (ABI v1/v2)       │
│    seccomp BPF filter                 │
│                                       │
├──────────── Integration ──────────────┤
│                                       │
│  (Phase 1 仅预留, 不做实现)           │
└───────────────────────────────────────┘
```

- **API 层**：提供 CLI (`main.rs`) 和 crate API (`lib.rs`)，共享同一套 `Sandbox` trait。
- **Core**：`SandboxConfig` 负责策略配置（TOML/Builder/CLI flags 三种构造方式），`CommandSpec` 和 `PreparedCommand` 定义命令规格。
- **Linux 后端**：`LinuxSandbox` 实现 `Sandbox` trait，内部由 `landlock.rs`（文件系统 ACL）、`seccomp.rs`（syscall 黑名单）协作完成沙箱环境。
- **Integration**：Phase 1 不做实现，仅为 macos/、api/http.rs、codewhale.rs 建立空模块占位。

## 2. 模块分解

| 文件路径 | 职责 | 实现内容 |
|---|---|---|
| `src/main.rs` | CLI 入口 | clap derive API 定义 `run` / `check` / `serve` 子命令，dispatch 到对应逻辑 |
| `src/lib.rs` | 公共类型 + Sandbox trait | `SandboxType`, `ExitReason`, `DenyMechanism`, `CommandSpec`, `PreparedCommand`, `CommandOutput`, `pub trait Sandbox` |
| `src/config.rs` | 配置解析 | `SandboxConfig`, `FilesystemConfig`, `NetworkConfig`, `TimeoutConfig`, `FsPolicy` 枚举；serde 反序列化 + Builder pattern + expand_tilde |
| `src/linux/mod.rs` | LinuxSandbox 结构体 + dispatch | `execute()` 方法编排 ruleset 构建 + BPF 构建 + Command pre_exec；`prepare()` 返回 PreparedCommand；`classify_exit()` 模式匹配退出码/stderr |
| `src/linux/landlock.rs` | Landlock ruleset | `build_ruleset(policy, allow_write, cwd)` 调用 landlock crate 的 BestEffort builder，路径不存在时静默跳过 |
| `src/linux/seccomp.rs` | seccomp BPF 过滤 | 手写 `sock_filter` 数组（x86_64 + aarch64），`build_blacklist_filter()` 返回过滤规则，`apply_seccomp()` 通过 prctl 加载 |
| `src/macos/mod.rs` | macOS stub | 空模块占位，Phase 2 实现 |
| `src/api/http.rs` | HTTP API stub | 空模块占位，Phase 3 实现 |
| `src/integration/codewhale.rs` | CodeWhale adapter stub | 空模块占位，Phase 4 实现 |
| `tests/config_test.rs` | 配置解析测试 | TOML 解析 ↔ Builder 等效性验证 |
| `tests/deny_detect_test.rs` | 拒绝检测测试 | exit_code/stderr 模式匹配分类 |
| `tests/landlock_test.rs` | Landlock 行为测试 | 真正 Landlock 写入限制验证（需要内核 5.13+） |
| `examples/cli_basic.rs` | CLI flags 用法示例 | 通过 CLI flags 构造 config 并执行命令 |
| `examples/cli_from_toml.rs` | TOML 加载示例 | 从 TOML 文件加载 config（引用 templates/ 样板） |
| `examples/crate_api.rs` | crate API 示例 | 通过 Rust API 直接调用 Sandbox |
| `templates/*.toml.example` | 配置样板 | workspace-write / read-only / full-access 三套预设 |

## 3. 核心数据结构定义

### Sandbox trait

```rust
pub trait Sandbox: Send + Sync {
    fn prepare(&self, spec: &CommandSpec) -> Result<PreparedCommand>;
    fn execute(&self, spec: &CommandSpec) -> Result<CommandOutput>;
    fn classify_exit(&self, exit_code: i32, stderr: &str) -> ExitReason;
}
```

### ExitReason 枚举

```rust
pub enum ExitReason {
    Ok,
    Denied {
        mechanism: DenyMechanism,
        message: String,
    },
    Program(i32),
    InternalError(String),
}

pub enum DenyMechanism {
    Landlock,
    Seccomp,
    Unknown,
}
```

### 命令规格

```rust
pub struct CommandSpec {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub env: Vec<(String, String)>,
    pub timeout: Option<Duration>,
}

pub struct PreparedCommand {
    pub command: Command,
    pub timeout: Option<Duration>,
}

pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}
```

### 配置结构体

```rust
pub struct SandboxConfig {
    pub filesystem: FilesystemConfig,
    pub network: NetworkConfig,
    pub timeout: TimeoutConfig,
}

pub struct FilesystemConfig {
    pub policy: FsPolicy,
    /// 额外可写路径（配置中为 Vec<String>，运行时统一展开 ~）
    pub allow_write: Vec<PathBuf>,
}

pub enum FsPolicy {
    FullAccess,
    ReadOnly,
    WorkspaceWrite,
}

pub struct NetworkConfig {
    pub enabled: bool,
}

pub struct TimeoutConfig {
    pub default_secs: u64,
    pub max_secs: u64,
}
```

## 4. Landlock 策略设计

### 基本原理

Landlock 是 Linux 5.13+ 的 LSM（Linux Security Module），采用 **grant-only** 模型：进程通过 `landlock_restrict_self()` 自限后，只能访问显式授予的路径。未授予的路径默认拒绝。

### 三种策略的文件系统权限

| 策略 | Read | Write | Landlock 是否激活 |
|---|---|---|---|
| FullAccess | 所有路径 | 所有路径 | 否（绕过沙箱） |
| ReadOnly | 整个文件系统 `/` | 无 | 是 |
| WorkspaceWrite | 整个文件系统 `/` | cwd + `/tmp` + allow_write | 是 |

### deny_read 推迟到 Phase 2

Phase 1 不做 `deny_read`。原因是 Landlock 的 grant-only 模型无法在已授予读权限 `/` 后撤回子路径。Phase 2 通过 bind mount（`mount --bind` 到空目录）或白名单路径补集的方式实现。

### ABI 版本兼容

运行时代码通过 `landlock_create_ruleset()` 的 `LANDLOCK_CREATE_RULESET_VERSION` 命令探测可用 ABI 版本，按高到低降级：

- ABI v1 (5.13): `FS_READ_FILE`, `FS_WRITE_FILE`, `FS_READ_DIR`, `FS_EXECUTE`
- ABI v2 (5.19): `FS_TRUNCATE`（阻止截断已授予写权限的文件）
- ABI v3 (6.2): `FS_IOCTL_DEV`, `FS_REFER`（硬链接/重命名限制）

Phase 1 使用 `landlock` crate 0.4 的 `BestEffort` 模式自动处理降级。

### 路径不存在处理

配置中的 allow_write 路径在构建 ruleset 时如果不存在，静默跳过（不报错）。这是为了支持用户在还没有创建某些目录的情况下预先配置权限。

## 5. Seccomp 黑名单设计

### 策略：宽名单（blacklist）

采用黑名单策略，只禁止已知危险的 syscall，其余全部放行。这是最宽松的策略，与 Phase 1 优先保证"不破坏正常程序"的目标一致。

### 禁止的 13 个 syscall

| 编号 | syscall | 风险说明 |
|---|---|---|
| 1 | `mount` | 挂载文件系统，用于逃逸或获取额外权限 |
| 2 | `umount2` | 卸载文件系统 |
| 3 | `pivot_root` | 更改进程的根文件系统 |
| 4 | `chroot` | 更改进程根目录 |
| 5 | `ptrace` | 进程跟踪，可读写任意进程内存 |
| 6 | `kexec_load` | 加载新内核 |
| 7 | `kexec_file_load` | 从文件加载新内核 |
| 8 | `reboot` | 重启系统 |
| 9 | `init_module` | 加载内核模块 |
| 10 | `finit_module` | 从文件描述符加载内核模块 |
| 11 | `delete_module` | 卸载内核模块 |
| 12 | `unshare(CLONE_NEWUSER)` | 创建用户命名空间（用于逃逸） |
| 13 | `bpf` | 加载 BPF 程序（绕过 seccomp） |

### 架构支持

- **x86_64**: 使用 `AUDIT_ARCH_X86_64` 常量，对应 syscall 号
- **aarch64**: 使用 `AUDIT_ARCH_AARCH64` 常量，对应 syscall 号（与 x86_64 不同）
- 通过 `seccomp_data.arch` 字段区分架构，禁止不匹配的架构代码（避免 32 位兼容模式绕过）

### 加载方式

通过 `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)` 加载 BPF 程序。PR_SET_SECCOMP 在新进程中的 `pre_exec` 闭包内调用且不再撤销，保证子进程无法绕过。

### 后续扩展

Phase 2 末允许按策略动态调整黑名单（如放通 `bpf` 给需要 eBPF 的工作负载）。

## 6. 执行流程

### Command 执行时序

```
用户请求 (CLI / crate API)
        │
        ▼
[1] SandboxConfig 解析 / 构造
    ├── TOML 文件 → serde 反序列化
    ├── Builder pattern → 程序化构造
    └── CLI flags → clap 解析
        │
        ▼
[2] LinuxSandbox::new(config)
        │
        ▼
[3] LinuxSandbox::execute(spec)
    │
    ├── 3a. 构建 Landlock ruleset
    │   ├── build_ruleset(policy, allow_write, cwd)
    │   ├── 返回 ruleset_fd (File 句柄，fork 时继承)
    │   └── 跳过 FullAccess（不构建）
    │
    ├── 3b. 构建 seccomp BPF 规则
    │   ├── build_blacklist_filter() → Vec<sock_filter>
    │   └── 跳过 FullAccess（不构建）
    │
    ├── 3c. 创建 std::process::Command
    │   ├── 设置 program / args
    │   ├── 设置 cwd / env
    │   └── 设置 timeout（Option<Duration>）
    │
    ├── 3d. 通过 unsafe pre_exec 执行
    │   ├── landlock_restrict_self(ruleset_fd)
    │   │   └── 只调一次，不可逆
    │   ├── prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &bpf_prog)
    │   │   └── 只调一次，不可逆
    │   └── pre_exec 内仅做零分配系统调用
    │
    ├── 3e. 等待子进程完成
    │   ├── 读取 stdout / stderr
    │   └── 获取 exit_code
    │
    └── 3f. 返回 CommandOutput
        │
        ▼
[4] classify_exit(exit_code, stderr)
    ├── exit_code == 0 → Ok
    ├── stderr 匹配 "denied" / "Permission denied" / "not permitted"
    │   → Denied { mechanism, message }
    ├── exit_code != 0 → Program(exit_code)
    └── 内部错误 → InternalError(String)
        │
        ▼
[5] 返回给调用方
```

### pre_exec 闭包规则

- pre_exec 在 fork 后、exec 前在子进程中执行
- 必须使用 `unsafe`，Landlock 和 seccomp 系统调用均通过 `libc` 直接调用
- pre_exec 内**只允许零分配操作**（不分配堆内存，不 panic，不进行 I/O）
- `ruleset_fd` 通过 `Command::pre_exec` 的闭包捕获，fork 时自动继承 fd

### classify_exit 模式匹配逻辑

| 条件 | 结果 |
|---|---|
| exit_code == 0 | `Ok` |
| stderr 包含 "denied" / "Operation not permitted" / "not permitted" 等特征串 | `Denied`（自动判断 mechanism） |
| exit_code != 0 且无拒绝特征 | `Program(exit_code)` |
| 管道破裂 / 超时杀死信号 | `InternalError` |

Landlock 拒绝通常产生 `EPERM`（Operation not permitted）并伴有文件路径，seccomp 拒绝产生 `SIGSYS`（Bad system call）并伴有 `si_call_addr` 信息。`classify_exit()` 通过 stderr 内容区分。

## 7. 与其他 Phase 的关系

### Phase 1 交付物（本阶段）

- 核心 Sandbox trait + 类型系统
- SandboxConfig 三种构造方式
- LinuxSandbox（Landlock + seccomp）
- CLI `run` / `check` / `serve`（serve 为 stub）
- 测试：config_test, deny_detect_test, landlock_test
- 示例：cli_basic, cli_from_toml, crate_api
- 模板：workspace-write / read-only / full-access

### Phase 1 明确不做

| 特性 | 计划阶段 |
|---|---|
| deny_read / allow_read 路径控制 | Phase 2 |
| user_namespace / PID namespace | Phase 3 |
| netns 网络隔离 | Phase 3 |
| 自定义 seccomp 策略 | Phase 2 |
| macOS backend (Seatbelt) | Phase 2 |
| CodeWhale adapter | Phase 4 |
| HTTP API (axum 服务器) | Phase 3 |
| eBPF / 动态授权 | Phase 4+ |
| Windows 支持 | 未规划 |

### 依赖关系

```
Phase 1 ────────────────────────────────┐
    │  Core types + LinuxSandbox        │
    │  + CLI + Tests                    │
    └───────────────────────────────────┬┘
                                        │
            ┌───────────────────────────┤
            ▼                           ▼
    Phase 2: macOS + deny_read    Phase 3: netns + HTTP API
            + 自定义 seccomp             + PID namespace
            │                           │
            └───────────┬───────────────┘
                        ▼
               Phase 4: CodeWhale adapter
                       + eBPF + 动态授权
```

- **Phase 2** 依赖于 Phase 1 的 `SandboxConfig` 和 `Sandbox` trait 接口，需要扩展 `FsPolicy` 添加 `deny_read` 支持。
- **Phase 3** 依赖于 Phase 1 的 `LinuxSandbox::execute()` 流程，需要扩展 namespace 模块添加 netns 和 PID ns。
- **Phase 4** 依赖于 Phase 1-3 的所有组件，在其基础上添加集成层和 eBPF 能力。
