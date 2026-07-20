# Namespace 支持执行计划

- **创建日期**: 2026-07-20
- **依据设计文档**: [docs/design-plans/namespace-support.md](../design-plans/namespace-support.md)
- **估计工作量**: ~600 lines 实现 + ~400 lines 测试

## 任务列表

```yaml
tasks:
  - id: config
    type: impl
    description: 添加 NamespacesConfig 结构体和 Builder 方法
    files:
      - src/config.rs
      - src/lib.rs
    depends_on: []
    details: |
      1. 在 src/config.rs 中定义 NamespacesConfig 结构体，含 user/ipc/pid/net/uts/cgroup/user_try/cgroup_try 字段
      2. 为 NamespacesConfig 实现 Default trait（全 false，uid/gid/hostname 为 None）
      3. 为 NamespacesConfig 实现 Serialize/Deserialize
      4. 在 SandboxConfig 中新增 namespaces: NamespacesConfig 字段
      5. 在 SandboxConfigBuilder 中新增 builder 方法：
         .unshare_user(bool), .unshare_ipc(bool), .unshare_pid(bool),
         .unshare_net(bool), .unshare_uts(bool), .unshare_cgroup(bool),
         .unshare_all(), .uid(u32), .gid(u32), .hostname(str), .chdir(str), .clearenv()
      6. 在 SandboxConfigBuilder::build() 中填入 namespace 字段的默认值
      7. 在 src/lib.rs 中导出 NamespaceType 枚举：User, Ipc, Pid, Net, Uts, Cgroup
      8. lib.rs 中 NamespaceType 实现 Display、可做 check 命令输出

  - id: config-test
    type: test
    description: NamespacesConfig 的 TOML 序列化/反序列化、默认值、Builder 测试
    files:
      - src/config.rs (模块内 #[cfg(test)])
    depends_on: [config]
    details: |
      1. test_default_values: NamespacesConfig::default() 全为 false，uid/gid/hostname 为 None
      2. test_build_with_namespaces: Builder 设置 unshare_user + unshare_net，build() 后 config.namespaces.user==true，.net==true
      3. test_build_unshare_all: .unshare_all() 后 user/ipc/pid/net/uts/cgroup 全为 true，user_try/cgroup_try 也为 true
      4. test_build_uid_gid: .uid(1000).gid(1000) 后 uid==Some(1000)，gid==Some(1000)
      5. test_build_hostname: .hostname("sandbox") 后 hostname==Some("sandbox")
      6. test_build_clearenv: .clearenv() 后 clearenv==true
      7. test_build_chdir: .chdir("/tmp") 后 chdir==Some(PathBuf::from("/tmp"))
      8. test_serialize_deserialize: TOML 序列化再反序列化，值与原始一致
      9. test_serialize_defaults_dropped: 默认字段在序列化时被 serde(skip_serializing_if) 跳过
      10. test_namespacetype_display: NamespaceType::User 输出 "user"，以此类推

  - id: namespaces-module
    type: impl
    description: 创建 src/linux/namespaces.rs，实现 namespace 核心函数
    files:
      - src/linux/namespaces.rs
    depends_on: [config]
    details: |
      1. 创建模块，声明 NamespaceError 错误枚举（使用 thiserror）：
         - Unavailable(String) — 内核不支持
         - UnshareFailed(std::io::Error) — unshare syscall 失败
         - UidMapFailed(std::io::Error) — uid_map 写入失败
         - GidMapFailed(std::io::Error) — gid_map 写入失败
         - SetgroupsFailed(std::io::Error) — setgroups 写入失败
         - HostnameFailed(std::io::Error) — sethostname 失败
         - ChdirFailed(std::io::Error) — chdir 失败
      2. 实现 libc 常量映射（注释内核版本和来源）：
         - CLONE_NEWUSER = 0x10000000
         - CLONE_NEWIPC = 0x08000000
         - CLONE_NEWPID = 0x20000000
         - CLONE_NEWNET = 0x40000000
         - CLONE_NEWUTS = 0x04000000
         - CLONE_NEWCGROUP = 0x02000000
      3. 实现 unshare_flags(config: &NamespacesConfig) -> i32：
         - 根据 config 字段组合 flags
         - 注意 user_try 不影响 flags 值，只影响错误处理
      4. 实现 user_namespace_available() -> bool：
         - 尝试 clone(CLONE_NEWUSER) 检测，若 ENOSYS/EINVAL 返回 false
         - 使用 OnceLock 缓存结果
      5. 实现 cgroup_namespace_available() -> bool：
         - 检测 /proc/self/cgroup 是否存在且可读，以及内核版本 >= 4.6
         - 使用 OnceLock 缓存结果
      6. 实现 write_uid_map(uid: u32) -> Result<(), NamespaceError>：
         - 以 "uid ${uid} ${uid}\n" 格式写入 /proc/self/uid_map
         - 若写入失败返回 UnshareFailed（因为此时 unshare 已成功但映射失败）
      7. 实现 deny_setgroups() -> Result<(), NamespaceError>：
         - 写入 "deny" 到 /proc/self/setgroups
      8. 实现 write_gid_map(gid: u32) -> Result<(), NamespaceError>：
         - 以 "gid ${gid} ${gid}\n" 格式写入 /proc/self/gid_map
      9. 实现 set_hostname(name: &str) -> Result<(), NamespaceError>：
         - 调用 unsafe { libc::sethostname(name.as_ptr(), name.len()) }
      10. 实现 chdir(dir: &Path) -> Result<(), NamespaceError>：
          - 调用 std::env::set_current_dir
      11. 实现 clearenv()：
          - 调用 std::env::clear (仅清除 Rust 侧 env，不影响子进程)
          - 使用 libc::clearenv (清空进程环境变量)
      12. 实现 setup_user_ns(config: &NamespacesConfig)：
          - 调用 prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) 作为 uid_map 前置条件
          - call deny_setgroups() + write_uid_map() + write_gid_map()
      13. 实现 unshare_and_configure(config: &NamespacesConfig) -> Result<(), NamespaceError>：
          - 计算 flags，若 flags == 0 直接返回 Ok
          - 检查 namespace 可用性，try 模式不支持则跳过（不返回 Err）
          - call unshare(flags)
          - 若 user ns 激活且 config 定义了 uid: setup_user_ns()
          - 若 uts ns 激活且 config 定义了 hostname: set_hostname()

  - id: namespaces-module-test
    type: test
    description: namespaces 模块的单元测试
    files:
      - src/linux/namespaces.rs (模块内 #[cfg(test)])
    depends_on: [namespaces-module]
    details: |
      1. test_unshare_flags_all: 全激活 config 产生正确 flags 值
      2. test_unshare_flags_none: 空 config 产生 flags=0
      3. test_unshare_flags_single: 仅 unshare_net 只包含 NEWNET
      4. test_user_namespace_available_not_panic: 可用性探测不 panic
      5. test_cgroup_namespace_available_not_panic: cgroup 探测不 panic
      6. test_unshare_flags_user_try: user_try 不影响 flags 位

  - id: pre-exec-integration
    type: impl
    description: 修改 src/linux/mod.rs，整合 namespace 到 pre_exec 闭包
    files:
      - src/linux/mod.rs
    depends_on: [namespaces-module, config]
    details: |
      1. 在 mod.rs 中声明 mod namespaces
      2. 修改 execute() 函数，在构建 pre_exec 闭包添加 namespace 步骤：
         - Step 1: unshare_and_configure 先于其他 pre_exec 步骤
         - 注意：构建 flags vector 时 namespace 部分在最前面
      3. 若 user ns 激活，prctl(NO_NEW_PRIVS) 在 unshare 立即进行
      4. 若 uts ns + hostname 设置，sethostname 在 namespace 配置后执行
      5. 调整 seccomp 安装的顺序逻辑 —— 确认 seccomp 在 unshare 之后
      6. 修改 check() 函数，输出 namespace 可用性信息
      7. 处理 chdir 和 clearenv：
         - chdir 在 pre_exec 中执行（或在 exec 前）
         - clearenv 在 pre_exec 中执行
      8. 注意 user_try/cgroup_try 的 fallback：若 namespace 不可用，跳过不报错
      9. 错误传播：pre_exec 闭包返回 io::Result<()>，namespace 错误需转换为 io::Error

  - id: cli-flags
    type: impl
    description: 在 src/main.rs 添加所有 namespace CLI flag
    files:
      - src/main.rs
    depends_on: [config]
    details: |
      1. cmd_run 添加以下 clap 参数：
         --unshare-user, --unshare-user-try, --unshare-ipc, --unshare-pid,
         --unshare-net, --unshare-uts, --unshare-cgroup, --unshare-cgroup-try,
         --unshare-all (action=SetTrue, 与其他互斥), --uid, --gid, --hostname,
         --chdir, --clearenv
      2. cmd_run 逻辑：将 CLI flag 映射到 SandboxConfigBuilder
         - 若 --unshare-all，则逐个设置对应 builder 方法
         - 若 --uid/--gid 设置但未激活 user ns，打印 warning 但仍继续
         - 若 --hostname 设置但未激活 uts ns，打印 warning 但仍继续
      3. cmd_check 输出 namespace 可用性：
         - 遍历 NamespaceType 枚举，逐个探测并打印 yes/no
      4. Args struct 或 CmdRun struct 新增命名空间字段
      5. 注意 --unshare-all 覆盖其他单个 --unshare-* 参数
      6. 确保 --uid/--gid 默认值不覆盖用户显式传递的 None

  - id: cli-test
    type: test
    description: 创建 tests/namespace_test.rs，14 个集成测试
    files:
      - tests/namespace_test.rs
    depends_on: [cli-flags, pre-exec-integration]
    details: |
      每个测试使用 `assert_cmd::Command` 调用二进制。

      1. test_unshare_uts_hostname:
         - 命令: sandbox-runtime run --unshare-uts --hostname foo -- hostname
         - 验证: stdout == "foo\n"
         - 跳过条件: UTS namespace 不可用

      2. test_unshare_pid:
         - 命令: sandbox-runtime run --unshare-pid -- sh -c "echo $$"
         - 验证: stdout == "1\n"
         - 跳过条件: PID namespace 不可用

      3. test_unshare_net_no_network:
         - 命令: sandbox-runtime run --unshare-net -- ping -c 1 8.8.8.8
         - 验证: 返回非零状态（网络不可达）
         - 跳过条件: NET namespace 不可用

      4. test_unshare_net_loopback:
         - 命令: sandbox-runtime run --unshare-net -- ping -c 1 127.0.0.1
         - 验证: 返回 0（回环可用）
         - 跳过条件: NET namespace 不可用

      5. test_unshare_ipc:
         - 命令: sandbox-runtime run --unshare-ipc -- ipcs -q
         - 验证: stdout 显示无消息队列 (或 ipcs 命令成功)
         - 跳过条件: IPC namespace 不可用

      6. test_unshare_uid_gid:
         - 命令: sandbox-runtime run --unshare-user --uid 1000 --gid 1000 -- id -u
         - 验证: stdout == "1000\n"
         - 跳过条件: USER namespace 不可用

      7. test_unshare_user_gid:
         - 与 6 类似，验证 id -g

      8. test_unshare_all:
         - 命令: sandbox-runtime run --unshare-all -- hostname
         - 验证: 执行成功（仅验证不 panic）
         - 跳过条件: 任意 namespace 不可用（user_try/cgroup_try 已处理回退）

      9. test_unshare_all_with_landlock:
         - 命令: sandbox-runtime run --unshare-all --landlock '/:ro' -- cat /etc/passwd
         - 验证: 执行成功（namespace + landlock 组合不冲突）
         - 跳过条件: Landlock 或 namespace 不可用

      10. test_chdir_before_exec:
          - 命令: sandbox-runtime run --chdir /tmp -- pwd
          - 验证: stdout == "/tmp\n"

      11. test_clearenv:
          - 命令: sandbox-runtime run --clearenv -- env
          - 验证: stdout 为空（或只有少量的必需变量）

      12. test_hostname_isolated:
          - 命令: 先设置 hostname 在容器内，再在宿主机验证未改变
          - shell: sandbox-runtime run --unshare-uts --hostname container -- hostname
          - 验: 宿主机 hostname 不变
          - 跳过条件: UTS namespace 不可用

      13. test_unshare_user_try_fallback:
          - 在 user ns 不可用环境下运行 --unshare-user-try
          - 验证: 不报错，正常执行
          - 注: 需要模拟环境，或用条件编译跳过

      14. test_pid_ns_init_process:
          - 命令: sandbox-runtime run --unshare-pid -- sh -c "echo $$"
          - 验证: stdout == "1\n"
          - 跳过条件: PID namespace 不可用

  - id: docs-update
    type: impl
    description: 更新 docs/linux-sandbox.md 的执行流程和 namespace 表格
    files:
      - docs/linux-sandbox.md
    depends_on: [config]
    details: |
      1. 在 linux-sandbox.md 的内核能力矩阵中添加 namespace 一行
      2. 在 pre_exec 执行流程图中添加 namespace 步骤
      3. 添加 namespace 的简要说明（到 UTS 隔离程度）

  - id: regression
    type: test
    description: 全量回归检查
    depends_on:
      - cli-test
      - config-test
      - namespaces-module-test
    details: |
      1. cargo clippy -- -D warnings
      2. cargo fmt --check
      3. cargo test --lib
      4. cargo test --test config_test
      5. cargo test --test namespace_test
      6. cargo test --test landlock_test -- --skip probe
      7. cargo build --release
```

## 执行顺序

```
config ──┬──> config-test ──────┐
         │                       │
         ├──> namespaces-module ─┤
         │        │              │
         │        └──> namespaces-module-test
         │                       │
         ├──> pre-exec-integration ─┐
         │                          │
         └──> cli-flags ────────────┤
                                     │
             docs-update ────────────┤
                                     │
                          ┌──────────┘
                          v
                      cli-test ──> regression
```

## 启动方式

```bash
# Step 1: config
cargo test --lib  # 确认构建通过

# Step 2: config-test
cargo test --lib -- config::test

# Step 3: namespaces-module
cargo check

# Step 4: namespaces-module-test
cargo test --lib -- namespaces::test

# Step 5: pre-exec-integration
cargo test --test landlock_test  # 确认不破坏现有测试

# Step 6: cli-flags
cargo build

# Step 7: cli-test
cargo test --test namespace_test

# Step 8: docs-update
# 手动验证

# Step 9: regression
cargo clippy -- -D warnings && cargo fmt --check && cargo test
```
