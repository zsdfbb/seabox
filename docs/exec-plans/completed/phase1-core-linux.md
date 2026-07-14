# Phase 1: Core + Linux 文件系统隔离 — 执行计划

## 任务拆分

```yaml
- id: step-1-cargo-toml
  type: impl
  description: >
    创建 Cargo.toml + 目录骨架 + 所有空文件。Cargo.toml 声明所有依赖（clap, serde, toml,
    anyhow, thiserror, dirs, libc, landlock）。创建 src/ 下所有模块文件和子目录，
    tests/ 下测试文件，templates/ 下配置样板，examples/ 下示例文件。macos/、api/、
    integration/ 模块为空文件或 mod.rs stub。
  files:
    - Cargo.toml
    - src/main.rs (stub — fn main() {})
    - src/lib.rs (stub — empty)
    - src/config.rs (stub — empty struct)
    - src/linux/mod.rs (stub)
    - src/linux/landlock.rs (stub)
    - src/linux/seccomp.rs (stub)
    - src/macos/mod.rs (stub)
    - src/api/http.rs (stub)
    - src/integration/codewhale.rs (stub)
    - tests/config_test.rs (stub)
    - tests/deny_detect_test.rs (stub)
    - tests/landlock_test.rs (stub)
    - examples/cli_basic.rs (stub)
    - examples/cli_from_toml.rs (stub)
    - examples/crate_api.rs (stub)
    - templates/workspace-write.toml.example
    - templates/read-only.toml.example
    - templates/full-access.toml.example
  deps: []

- id: step-2-lib-types
  type: impl
  description: >
    在 src/lib.rs 中定义核心类型和 Sandbox trait。包含：SandboxType 枚举 (None |
    LinuxLandlock)，ExitReason 枚举 (Ok | Denied | Program | InternalError)，
    DenyMechanism 枚举 (Landlock | Seccomp | Unknown)，CommandSpec 结构体，
    PreparedCommand 结构体，CommandOutput 结构体，pub trait Sandbox { prepare,
    execute, classify_exit }。所有类型 pub 导出。Sandbox trait 有 Send + Sync 约束。
  files:
    - src/lib.rs
  deps:
    - step-1-cargo-toml

- id: step-3-config
  type: impl
  description: >
    在 src/config.rs 中实现 SandboxConfig 完整解析。SandboxConfig { filesystem,
    network, timeout }。FilesystemConfig { policy: FsPolicy, allow_write:
    Vec<String> }。FsPolicy 枚举 (FullAccess | ReadOnly | WorkspaceWrite) 带 serde
    tag。NetworkConfig { enabled: bool }。TimeoutConfig { default_secs, max_secs }。
    提供三个关联函数：SandboxConfig::from_toml(path) 解析 TOML 文件，
    SandboxConfig::builder() 返回 Builder，SandboxConfig::from_cli(flags) 从 CLI
    参数构造。Builder 模式构造时统一展开 ~ (expand_tilde)。
  files:
    - src/config.rs
  deps:
    - step-2-lib-types

- id: step-4-landlock
  type: impl
  description: >
    在 src/linux/landlock.rs 中实现 Landlock ruleset 构建。使用 landlock crate
    0.4 的 BestEffort 模式自动探测 ABI 版本并降级。函数
    build_ruleset(policy: FsPolicy, allow_write: &[PathBuf], cwd: &Path) →
    Result<Ruleset>。逻辑：ReadOnly → grant read "/"；WorkspaceWrite → grant read
    "/" + grant write cwd + /tmp + allow_write 列表中的路径；FullAccess → 返回空
    Ruleset（不调用 restrict_self）。路径不存在时静默跳过。所有 landlock crate API
    调用包装在 safe 函数内。
  files:
    - src/linux/landlock.rs
  deps:
    - step-2-lib-types

- id: step-5-seccomp
  type: impl
  description: >
    在 src/linux/seccomp.rs 中实现 seccomp BPF 黑名单。手写 sock_filter 数组定义
    13 条黑名单 syscall 的过滤规则。支持 x86_64 和 aarch64 架构，通过
    seccomp_data.arch 区分。函数 build_blacklist_filter() → Vec<sock_filter> 返回
    预编译 BPF 指令。函数 apply_seccomp(filter: &[sock_filter]) → Result<()> 通过
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER) 加载。使用 unsafe 调用 libc 的
    prctl。每条 syscall 常量声明处注释内核版本来源。
  files:
    - src/linux/seccomp.rs
  deps:
    - step-2-lib-types

- id: step-6-linux-mod
  type: impl
  description: >
    在 src/linux/mod.rs 中实现 LinuxSandbox 结构体 (\#{derive(Debug)}) 和 impl
    Sandbox for LinuxSandbox。结构体字段 config: SandboxConfig。execute() 方法：
    构建 Landlock ruleset → 构建 BPF filter → 创建 std::process::Command → 通过
    unsafe pre_exec 闭包调用 landlock_restrict_self + prctl seccomp → 等待子进程
    → 返回 CommandOutput。prepare() 方法返回 PreparedCommand（不含 pre_exec，供
    CLI 模式使用）。classify_exit() 匹配 exit_code 和 stderr 特征串判定拒绝原因。
  files:
    - src/linux/mod.rs
  deps:
    - step-4-landlock
    - step-5-seccomp

- id: step-7-cli
  type: impl
  description: >
    在 src/main.rs 中实现完整 CLI。使用 clap derive API 定义三个子命令：run (默认，
    执行命令)、check (检查系统沙箱能力—Landlock ABI 版本探测)、serve (HTTP API 启动
    —Phase 1 输出 "not implemented" 并退出非零)。CLI flags：--config/-c FILE,
    --policy/-p POLICY, --allow-network/-n, --allow-write/-w PATH, --debug/-d。
    构建 SandboxConfig → 创建 LinuxSandbox → 执行 execute() 或 prepare() 并打印
    输出。错误处理使用 anyhow。
  files:
    - src/main.rs
  deps:
    - step-6-linux-mod
    - step-3-config

- id: step-8-tests
  type: test
  description: >
    实现三个测试文件。(1) tests/config_test.rs：测试 TOML 解析等价性（Builder 构造
    的 config 与 TOML 反序列化产生的 config 字段一致），测试 FullAccess /
    ReadOnly / WorkspaceWrite 三种策略 roundtrip，测试 expand_tilde 行为。
    (2) tests/deny_detect_test.rs：测试 classify_exit() 对各种 exit_code 和 stderr
    组合的分类正确性（正常退出 0，Landlock 拒绝 EPERM stderr，seccomp 拒绝 SIGSYS
    stderr，程序错误退出码 1/139，内部错误等）。(3) tests/landlock_test.rs：集成测试
    —在真正 5.13+ 内核上验证 Landlock 写入限制（创建临时目录，尝试写入未授权路径应
    失败，写入授权路径应成功），在低版本内核上跳过（#[ignore] 或条件跳过）。
  files:
    - tests/config_test.rs
    - tests/deny_detect_test.rs
    - tests/landlock_test.rs
  deps:
    - step-7-cli

- id: step-9-templates
  type: impl
  description: >
    创建三个 TOML 配置样板文件。(1) templates/workspace-write.toml.example：工作区
    可写模式—filesystem.policy = "workspace"，allow_write = ["."]，network.enabled
    = false，timeout.default = "30s"。(2) templates/read-only.toml.example：只读
    模式—filesystem.policy = "read-only"，network.enabled = false，timeout.default
    = "30s"。(3) templates/full-access.toml.example：完全访问模式—filesystem.policy
    = "full-access"，network.enabled = true。每个文件包含完整注释说明用法。
  files:
    - templates/workspace-write.toml.example
    - templates/read-only.toml.example
    - templates/full-access.toml.example
  deps:
    - step-3-config
```

## 任务依赖 DAG

```
step-1-cargo-toml (impl)
    │
    ├──► step-2-lib-types (impl)
    │       │
    │       ├──► step-3-config (impl)
    │       │       │
    │       │       └──► step-9-templates (impl)
    │       │
    │       ├──► step-4-landlock (impl)
    │       │       │
    │       │       └──► step-6-linux-mod (impl) ◄──┐
    │       │               │                        │
    │       ├──► step-5-seccomp (impl) ──────────────┘
    │               │
    │               └─────────────────────────────────┐
    │                                                 │
    │         step-6-linux-mod ◄──────────────────────┘
    │                 │
    │                 ▼
    │         step-7-cli (impl)
    │                 │
    │                 ▼
    │         step-8-tests (test)
    │
    └──► (所有其他任务间接依赖，通过 Cargo.toml)
```

## 实现顺序建议

1. **step-1-cargo-toml** — 创建骨架，确保 `cargo check` 通过
2. **step-2-lib-types** — 所有下游依赖基础类型
3. **step-3-config** — 配置解析，独立可测
4. **step-4-landlock** — 核心 Landlock 逻辑，与 seccomp 无关
5. **step-5-seccomp** — BPF 黑名单，与 landlock 无关
6. **step-6-linux-mod** — 编排 landlock + seccomp，实现 Sandbox trait
7. **step-7-cli** — 用户入口，连接 config + linux mod
8. **step-8-tests** — 三个测试文件覆盖配置/拒绝检测/Landlock
9. **step-9-templates** — 配置样板（可与 step-3 并行，但依赖其字段设计）

## 验证标准

| 步骤 | 验证方式 |
|---|---|
| step-1 | `cargo check` 编译成功 |
| step-2 | `cargo check` 通过，类型导出可被其他模块 use |
| step-3 | `cargo test config_test` 全部通过 |
| step-4 | 集成测试 `cargo test landlock_test`（需 5.13+）通过 |
| step-5 | 单元验证 BPF 指令可加载（通过 prctl） |
| step-6 | `cargo test deny_detect_test` 全部通过 |
| step-7 | `cargo run -- ls -la` 正常输出 |
| step-8 | `cargo test` 三个测试全部通过 |
| step-9 | 样板 TOML 可被 `--config` 加载 `cargo run -- --config templates/workspace-write.toml.example ls` |
