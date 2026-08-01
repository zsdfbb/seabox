# Phase 2 收尾 — 架构上下文

## 概述

Phase 2（Linux 完整进程隔离）的两个核心功能——命名空间隔离（6 种）和动态 seccomp 策略——均已实现、提交并测试。本计划完成剩余约 10% 的收尾工作：`--allow-network` 真实行为、外部 BPF 测试覆盖、文档状态更新。

---

## 现有架构

### 模块边界

```
src/
├── linux/
│   ├── mod.rs          ← LinuxSandbox::execute() — fork + pre_exec 序列
│   ├── namespaces.rs   ← 命名空间 unshare + 探测
│   └── seccomp.rs      ← BPF 构建 + USER_NOTIF + prctl 安装
├── config.rs           ← SandboxConfig + NamespacesConfig + Builder
├── main.rs             ← CLI 解析 + cmd_run + cmd_check
tests/
├── namespace_test.rs   ← 21 个命名空间端到端测试（N1-N21）
└── seccomp_test.rs     ← seccomp 黑名单 + --seccomp-deny-nr 测试
```

### 核心数据流（pre_exec 序列）

`LinuxSandbox::execute()` 的子进程序列（`src/linux/mod.rs:186-388`）：

```
1. unshare(flags)         — 创建 user/ipc/net/uts/cgroup 命名空间
2. unshare(CLONE_NEWPID)  — PID 命名空间 + double-fork reaper
3. clearenv + setenv      — 环境变量
4. chdir                  — 工作目录
5. prctl(NO_NEW_PRIVS)    — 禁止提升权限
6. uid/gid map            — user ns UID/GID 映射（/proc/self/uid_map）
7. sethostname            — UTS 主机名
8. landlock_restrict_self — Landlock ACL
9. seccomp (USER_NOTIF)   — 加载 deny filter + sendmsg SCM_RIGHTS
10. seccomp (prctl)       — 安装外部 BPF（如有）
11. execvp                — 执行目标程序
```

`--allow-network` 应在步骤 1 之后（netns 已创建）、步骤 9 之前插入：当 `ns.net && config.network_enabled` 时将 lo 设 UP。

### 约束

| 维度 | 详情 |
|------|------|
| **技术** | `pre_exec` 闭包运行在 fork 后的子进程，仅能调用 async-signal-safe 函数（`libc` 直调，无堆分配、无 `std::fs` / `std::io` 高级 API） |
| **技术** | `libc::socket` + `libc::ioctl` 是 async-signal-safe 的（POSIX 安全列表涵盖所有 syscall 包装） |
| **技术** | netns 中的 lo 接口默认 DOWN，`IFF_UP` 值为 0x1，跨架构一致 |
| **性能** | 无额外约束——`ioctl` 原子操作，微秒级耗时 |
| **演进** | `network_enabled` 已是 `SandboxConfig` 字段，无需改配置层 |
| **演进** | 外部 BPF 测试需要保持与 x86_64 架构匹配（BPF 字节硬编码）；若需跨架构需兼容模式 |

---

## 需求范围

### 范围内

1. **`--allow-network` 真实行为**：当 `--allow-network` + `--unshare-net` 启用时，在 netns 中将 lo 设 UP
2. **外部 BPF 集成测试**：用 `--seccomp-filter-fd` 传递 ALLOW-all filter，验证命令正常执行
3. **`install_plain_filter_smoke` 单元测试**：在 `seccomp.rs` 中新增 prctl 安装路径测试
4. **文档状态更新**：标记 seccomp-dynamic.md、development-phases.md 为已完成
5. **CONTEXT.md 术语清理**：去除"blacklist"旧术语
6. **`--allow-network` 集成测试**：验证 lo UP/DOWN 状态

### 范围外

- macOS 支持（Phase 3）不涉及
- eBPF 网络过滤（Phase 2b）不涉及
- CodeWhale 集成（Phase 4）不涉及
- 添加新的 CLI flag

### 关键场景

#### 场景 1：`--unshare-net --allow-network` → lo UP

```
cargo run -- run --unshare-net --allow-network -- cat /sys/class/net/lo/operstate
→ "up"
```

子进程内：`unshare(CLONE_NEWNET)` 创建隔离 netns（仅有 lo，DOWN），
然后 `socket(AF_INET, SOCK_DGRAM)` → `ioctl(SIOCGIFFLAGS)` 读 flags →
设 `IFF_UP` → `ioctl(SIOCSIFFLAGS)` 写回 → lo 变为 UP。

#### 场景 2：`--unshare-net` 不加 `--allow-network` → lo DOWN

```
cargo run -- run --unshare-net -- ip link show lo
→ "state DOWN ..."
```

保持当前行为，不调用 ioctl，lo 维持 DOWN 状态。

#### 场景 3：外部 BPF 测试

```
# 准备 ALLOW-all BPF 字节 → fd → seabox --seccomp-filter-fd <fd>
→ /bin/true 正常退出 0
```

验证 `install_plain_filter()` prctl 路径工作正常。

### 异常/边界场景

| 场景 | 行为 |
|------|------|
| `--allow-network` 但无 `--unshare-net` | 无操作（主机网络已可用） |
| netns 创建失败 | pre_exec 已处理，不会到达 lo UP 代码 |
| `socket(AF_INET)` 在极端 netns 下失败 | 理论上不应发生（socket 创建不需要网络访问），如发生则 ioctl 报错，子进程 `_exit(127)` |
| 外部 BPF 文件内容无效 | 内核在 prctl 阶段返回 EINVAL，子进程 `_exit(127)` |
| 测试运行在 aarch64 上 | BPF 字节编码需按架构调整 |

---

## 未澄清问题

- [x] lo UP 操作是否真的 async-signal-safe？→ 是的，`socket` + `ioctl` 均在 POSIX async-signal-safe 列表中
- [x] netns 中 socket 创建是否受限？→ 不受限，网络隔离仅影响网络通信，不阻止 socket 系统调用本身
- [x] BPF 硬编码字节是否跨架构？→ 否，当前面向 x86_64；测试用 `cfg!(target_arch = ...)` 或直接硬编码 x86_64

---

## 后续建议

1. 用 `arch-design` 做 `--allow-network` 方案设计（但已很简单，可直接编码）
2. 实现顺序：`--allow-network` → 测试 → 文档清理
