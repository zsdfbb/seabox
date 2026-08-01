# Linux Namespace 支持设计

- **创建日期**: 2026-07-20
- **涉及领域**: linux, namespace, user-ns, pid-ns, net-ns, ipc-ns, uts-ns, cgroup-ns
- **关联 ADR**: [0001-seccomp-user-notif-vs-sigsys.md](../adr/0001-seccomp-user-notif-vs-sigsys.md), [0002-config-landlock-rules.md](../adr/0002-config-landlock-rules.md)

## 动机

seabox 目前有 Landlock (文件系统 ACL) 和 seccomp (13 黑名单 syscall) 两层防护。Landlock 限制文件访问，seccomp 阻止危险 syscall。但仍有不足：

- **进程可见性**: 子进程仍能看到宿主机上所有进程 (`/proc/[pid]`)，可能泄漏信息
- **网络访问**: 没有网络隔离，所有命令默认可访问网络（未来 `--allow-network` 是显式放行）
- **SysV IPC**: 未隔离的 System V IPC 可能跨容器泄漏
- **主机名/UTS**: 命令可读取和修改主机名
- **cgroup**: 资源使用不受限
- **UID/GID**: 命令可能以不可预测的 uid/gid 运行（但若有 Landlock 限制，文件写入风险有限）

User namespace 能解决这些限制：为进程创建独立的 UID/GID 映射，使容器内 root (0) 映射到容器外普通用户 (1000)，同时配合其他 namespace 提供完整的进程/网络/IPC/主机名隔离。

## 设计目标

1. **可组合 Namespace 标志**: 每个 namespace 独立启用，类似 bwrap 的 `--unshare-*` 风格
2. **user namespace 优先**: 写入 uid_map/gid_map 使容器内 root 能执行需特权的操作
3. **回退语义**: `--unshare-user-try` 和 `--unshare-cgroup-try` 在能力不支持时不报错
4. **与现有机制兼容**: namespace 层与 Landlock + seccomp 层正交，同时加固
5. **check 命令可探测**: `seabox check` 报告哪些 namespace 可用

## Namespace 矩阵

| Namespace | 常量 | 隔离资源 | 内核要求 | CLI flag |
|---|---|---|---|---|
| User | `CLONE_NEWUSER` | UID/GID 映射、能力集合 | 3.8+ | `--unshare-user[=true/false]` |
| IPC | `CLONE_NEWIPC` | System V IPC、POSIX mq | 2.6.19+ | `--unshare-ipc` |
| PID | `CLONE_NEWPID` | 进程编号空间（子 namespace 内 pid=1） | 2.6.24+ | `--unshare-pid` |
| Network | `CLONE_NEWNET` | 网络设备、IP 地址、路由表（新 ns 仅有 lo） | 2.6.29+ | `--unshare-net` |
| UTS | `CLONE_NEWUTS` | 主机名、NIS 域名 | 2.6.19+ | `--unshare-uts` |
| Cgroup | `CLONE_NEWCGROUP` | cgroup 层级 | 4.6+ | `--unshare-cgroup[=true/false]` |

> **未纳入**: Time namespace `CLONE_NEWTIME` (5.6+) — 用例较窄（容器内时钟偏移），暂不实现。

## CLI 参数

所有 flag 均选填，默认不激活任何 namespace。

```
--unshare-user           创建 user namespace (默认隐含 `--unshare-user-try`)
--unshare-user-try       尝试创建 user ns，不支持则静默跳过
--unshare-ipc            创建 IPC namespace
--unshare-pid            创建 PID namespace
--unshare-net            创建 network namespace (仅 loopback)
--unshare-uts            创建 UTS namespace
--unshare-cgroup         创建 cgroup namespace (默认隐含 `--unshare-cgroup-try`)
--unshare-cgroup-try     尝试创建 cgroup ns，不支持则静默跳过
--unshare-all            激活所有 namespace（user-try, ipc, pid, net, uts, cgroup-try）
--uid <uid>              容器内 UID (仅当 user ns 激活)
--gid <gid>              容器内 GID (仅当 user ns 激活)
--hostname <name>        设置容器主机名 (仅当 uts ns 激活)
--chdir <dir>            执行前切换工作目录
--clearenv               清空环境变量
```

`--uid` / `--gid` 仅当 `--unshare-user` 和 `--unshare-user-try` 有效时才起作用。默认 uid=0, gid=0 (容器内 root，映射到进程实际 uid/gid)。

## 配置结构

`src/config.rs` 新增：

```rust
/// Namespace 隔离配置
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct NamespacesConfig {
    pub user: bool,
    pub ipc: bool,
    pub pid: bool,
    pub net: bool,
    pub uts: bool,
    pub cgroup: bool,

    /// 失败时静默回退（不报错）的 namespace
    pub user_try: bool,
    pub cgroup_try: bool,

    /// User namespace 映射（仅 user ns 激活时生效）
    pub uid: Option<u32>,
    pub gid: Option<u32>,

    /// 容器主机名（仅 uts ns 激活时生效）
    pub hostname: Option<String>,
}
```

`SandboxConfig` 新增字段：

```rust
pub struct SandboxConfig {
    // ... 现有字段
    pub namespaces: NamespacesConfig,
}
```

构建器方法：

```rust
impl SandboxConfigBuilder {
    pub fn unshare_user(mut self, enabled: bool) -> Self;
    pub fn unshare_ipc(mut self, enabled: bool) -> Self;
    pub fn unshare_pid(mut self, enabled: bool) -> Self;
    pub fn unshare_net(mut self, enabled: bool) -> Self;
    pub fn unshare_uts(mut self, enabled: bool) -> Self;
    pub fn unshare_cgroup(mut self, enabled: bool) -> Self;
    pub fn unshare_all(mut self) -> Self;
    pub fn uid(mut self, uid: u32) -> Self;
    pub fn gid(mut self, gid: u32) -> Self;
    pub fn hostname(mut self, name: impl Into<String>) -> Self;
    pub fn chdir(mut self, dir: impl Into<PathBuf>) -> Self;
    pub fn clearenv(mut self) -> Self;
}
```

## 执行流程

`pre_exec` 闭包（`src/linux/mod.rs`）中的执行顺序调整为：

```
顺序 | 步骤                            | 条件                | 说明
------|---------------------------------|---------------------|------
1    | unshare(flags)                  | namespaces 非空     | 先 unshare 再 seccomp
2    | prctl(NO_NEW_PRIVS)             | user ns 激活        | uid_map 写入前置条件
3    | write(/proc/self/uid_map)       | user ns 激活        | 容器内 UID 到容器外 UID
4    | write(/proc/self/setgroups)     | user ns 激活        | 写入 deny
5    | write(/proc/self/gid_map)       | user ns 激活        | 容器内 GID 到容器外 GID
6    | sethostname(name)               | uts ns + hostname   | 设置容器主机名
7    | landlock_restrict_self()        | landlock 规则非空   | 现有 Landlock 限制
8    | install_seccomp_filter()        | seccomp 激活        | 现有 seccomp 限制
9    | sendmsg(SCM_RIGHTS, socketpair) | 信号通道激活        | 现有信号通道
10   | execve                          | -                   | 执行目标命令
```

### 关键顺序决策

**unshare 在 seccomp 之前**：当前 seccomp BPF 将 `unshare` 列入黑名单。若先装 seccomp 再 unshare，unshare 会被拦截。因此**必须先 unshare，再装 seccomp** 以及对 execve 无害的后续操作。

**prctl(NO_NEW_PRIVS) 在 uid_map 之前**：内核要求写入 uid_map 的进程已设置 `NO_NEW_PRIVS` 或拥有 `CAP_SETUID`。由于我们 unshare 后容器内是 root，用 NO_NEW_PRIVS 更安全。

**Landlock + seccomp 在 user ns 配置之后**：这两个是限制性操作，配置完 namespace 映射后再进行限制，确保不会拦截 namespace 设置过程。

## 模块设计

### 新文件: `src/linux/namespaces.rs`

```rust
//! Linux namespace 支持模块
//!
//! 提供 namespace unshare、uid/gid map 写入、hostname 设置等功能。
//! 所有函数在编译时均可用，但执行时若内核不支持会返回 Err。

use crate::config::NamespacesConfig;

/// Namespace 类型枚举（用于 check 命令报告）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceType {
    User,
    Ipc,
    Pid,
    Net,
    Uts,
    Cgroup,
}

/// 根据 config 计算 unshare flags
pub fn unshare_flags(config: &NamespacesConfig) -> Result<u32, NamespaceError>;

/// 可用性探测
pub fn namespace_available(ns: NamespaceType) -> bool;
pub fn user_namespace_available() -> bool;
pub fn cgroup_namespace_available() -> bool;

/// 写入 /proc/self/uid_map（用户 namespace 内）
pub fn write_uid_map(uid: u32) -> Result<(), NamespaceError>;

/// 写入 /proc/self/gid_map（用户 namespace 内）
pub fn write_gid_map(gid: u32) -> Result<(), NamespaceError>;

/// 写入 /proc/self/setgroups 为 "deny"
pub fn deny_setgroups() -> Result<(), NamespaceError>;

/// 设置主机名（UTS namespace 内）
pub fn set_hostname(name: &str) -> Result<(), NamespaceError>;

/// 错误类型
#[derive(Debug, thiserror::Error)]
pub enum NamespaceError {
    #[error("namespace 不可用: {0}")]
    Unavailable(String),
    #[error("unshare(2) 失败: {0}")]
    UnshareFailed(std::io::Error),
    #[error("uid_map 写入失败: {0}")]
    UidMapFailed(std::io::Error),
    #[error("gid_map 写入失败: {0}")]
    GidMapFailed(std::io::Error),
    #[error("setgroups 设置失败: {0}")]
    SetgroupsFailed(std::io::Error),
    #[error("sethostname(2) 失败: {0}")]
    HostnameFailed(std::io::Error),
}
```

### `src/linux/mod.rs` 变更

`pre_exec` 闭包中按上述执行流程插入 namespace 步骤：

```rust
// pre_exec 闭包内
let namespaces_enabled = config.namespaces.has_any();

let pre_exec: Vec<Box<dyn Fn()>> = vec![
    // Step 1: 先 unshare（必须在 seccomp 之前）
    Box::new(move || {
        if namespaces_enabled {
            namespaces::unshare_and_configure(&config.namespaces)?;
        }
        Ok(())
    }),
    // Steps 7-10: 现有 flow（Landlock → seccomp → signal → execve）
    // ...原有代码...
];
```

`check` 函数增加 namespace 可用性输出：

```
Sandbox capabilities:
  landlock:    v2 (path_beneath, net)     ✓
  seccomp:     filter + user_notif        ✓
  namespaces:
    user:      yes
    ipc:       yes
    pid:       yes
    net:       yes
    uts:       yes
    cgroup:    yes
```

### `src/lib.rs` 变更

新增 `NamespaceType` 公共枚举供外部使用。

### `src/main.rs` 变更

CLI flag 定义：

```rust
#[arg(long, default_value_t = false)]
unshare_user: bool,
#[arg(long, default_value_t = false)]
unshare_user_try: bool,
#[arg(long, default_value_t = false)]
unshare_ipc: bool,
#[arg(long, default_value_t = false)]
unshare_pid: bool,
#[arg(long, default_value_t = false)]
unshare_net: bool,
#[arg(long, default_value_t = false)]
unshare_uts: bool,
#[arg(long, default_value_t = false)]
unshare_cgroup: bool,
#[arg(long, default_value_t = false)]
unshare_cgroup_try: bool,
#[arg(long)]
unshare_all: bool,
#[arg(long)]
uid: Option<u32>,
#[arg(long)]
gid: Option<u32>,
#[arg(long)]
hostname: Option<String>,
#[arg(long)]
chdir: Option<String>,
#[arg(long)]
clearenv: bool,
```

`cmd_run` 对 `--uid`/`--gid` 校验：若设置但未激活 user ns，给出 warning 或 error。

## 测试策略

新增 `tests/namespace_test.rs`，覆盖以下场景（14 个集成测试）：

| # | 测试名 | 验证内容 |
|---|---|---|
| 1 | `unshare_uts_hostname` | `--unshare-uts --hostname foo` 后 `hostname` 命令返回 `foo` |
| 2 | `unshare_pid` | `--unshare-pid` 后 `echo $$` 返回 1 |
| 3 | `unshare_net_no_network` | `--unshare-net` 后 `ping 8.8.8.8` 失败（仅有 lo） |
| 4 | `unshare_net_loopback` | `--unshare-net` 后 localhost 可达 |
| 5 | `unshare_ipc` | `--unshare-ipc` 后 `ipcs` 显示空白 |
| 6 | `unshare_uid_gid` | `--unshare-user --uid 1000 --gid 1000` 后 `id -u` 返回 1000 |
| 7 | `unshare_all` | `--unshare-all` 组合多个 namespace |
| 8 | `unshare_user_try_fallback` | 若 user ns 不可用，`--unshare-user-try` 不报错 |
| 9 | `unshare_cgroup_try_fallback` | 若 cgroup ns 不可用，`--unshare-cgroup-try` 不报错 |
| 10 | `chdir_before_exec` | `--chdir /tmp` 后 `pwd` 返回 `/tmp` |
| 11 | `clearenv` | `--clearenv` 后 `env` 为空 |
| 12 | `unshare_all_with_landlock` | namespace + Landlock 组合不冲突 |
| 13 | `hostname_isolated` | `--unshare-uts` 设置 hostname 不影响宿主机 |
| 14 | `pid_namespace_init` | `--unshare-pid` 后进程 pid 为 1 |

### 预检探针

所有 namespace 集成测试在跑前先用可用性探针检测。若内核不支持某 namespace（如老内核无 cgroup ns），对应测试自动跳过并打印理由。

### 组合安全

namespace + seccomp + Landlock 的完整组合验证确保：
1. unshare 先于 seccomp 安装（否则 seccomp 拦 unshare）
2. uid_map 写入在 user namespace 内成功
3. Landlock 限制后无法逃逸

## 边界情况

1. **`--unshare-user` 与 uid=0 映射**: 容器内 uid=0 默认映射到进程实际 uid。若用户同时 `--uid 0`，容器内外都是 root，隔离性下降但不出错。

2. **`--unshare-all` 语义**: 等同于 `--unshare-user-try --unshare-ipc --unshare-pid --unshare-net --unshare-uts --unshare-cgroup-try`，即 user 和 cgroup 是 try 模式。

3. **`--uid`/`--gid` 无 user ns**: 打印 warning 并忽略，不报错。为了兼容脚本编写时先配 uid 后加 `--unshare-user` 的场景。

4. **`--hostname` 无 uts ns**: 打印 warning 并忽略。

5. **User namespace 下的 root 能力**: 容器内 uid=0 拥有 `CAP_NET_ADMIN` 等能力，但被 seccomp 和 Landlock 限制。实际效果是 root 在容器内看起来是 root，但无法执行被 seccomp 禁止的 syscall 或写入被 Landlock 限制的文件。

6. **`--chdir` 失败**: chdir 若失败（目标目录不存在），pre_exec 返回错误，进程以非零状态退出。这与 `cd` 在 shell 中的行为一致。

7. **`--clearenv` 与 path 解析**: clearenv 后 PATH 被清除，执行的命令需为绝对路径。若用户用相对路径 + clearenv，会因 PATH 为空导致 execvp 失败。这是预期行为，类似 `env -i`。

## 未实现

- **User namespace 无 --uid 时自动映射**: 当前默认 uid=0/gid=0，不自动计算当前 uid 映射。用户需显式 `--uid $(id -u)`。

- **`--share-net`**: 当前 net ns 只有 loopback。若需要共享宿主机网络栈，直接不设 `--unshare-net` 即可。

- **`--cap-add`/`--cap-drop`**: 不像 Docker 那样精细管理 capabilities。User namespace 本身已移除大部分宿主机能力，容器内 root 有完整能力集，但与 seccomp 组合使用。

- **`--mount` / new mount ns**: Mount namespace 需要更多内核知识且风险较高（bind mounts, pivot_root），留待 Phase 3。

## 相关讨论

- User namespace 中 uid_map 的限制细节: `/proc/self/uid_map` 最多可写入 5 行映射。我们使用标准 1:1 映射：容器 uid X -> 实际 uid Y。
- Cgroup v1 vs v2: write /proc/self/cgroup 在 v2 中行为不同，我们的 `cgroup_namespace_available()` 会识别两种版本。
