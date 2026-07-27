# Phase 2 收尾 — `--allow-network` 设计方案（修订版）

> 设计时间：2026-07-26
> 状态：**草案（修订版）**
> 上一版：`docs/arch/phase2-wrapup/design.md`（已废弃）

---

## 1. 背景与修订原因

第一版设计选择了 **ioctl** 配置 lo，核心理由是 async-signal-safe 约束。该约束源于 `Command::spawn() + pre_exec` 闭包的异步信号安全限制。

经讨论后纠正：

1. **async-signal-safe 不是硬约束**。commit `34bc861` 已重构为 raw `libc::fork()`，子进程内可以安全使用堆分配和 libc 函数。
2. **项目定位是 bubblewrap 超集**。CLI flag 语义须与 bwrap 兼容。
3. **ioctl 是旧 API**，NETLINK 是 Linux 网络配置的标准做法，bwrap 也用 NETLINK。

需要重新设计。

---

## 2. 调研：bwrap 的 network.c

bwrap 的 `network.c`（~200 行 C）：
- 直接使用 RTNETLINK（不依赖 libnl）
- 1024 字节栈缓冲区
- `if_nametoindex("lo")` → `RTM_NEWADDR` (127.0.0.1/8) → `RTM_NEWLINK` (IFF_UP)
- 同步 `sendmsg` / `recvmsg` 模式
- 失败时 `die_with_error()`（fatal）
- **仅配置 lo，不做 veth 或 NAT**

---

## 3. 三方案对比

### 方案 A：正交语义 + NETLINK（Agent 1 / 最小复杂度）

`--allow-network` 与 `--unshare-net` 正交：
- `--unshare-net` = 隔离（lo DOWN）
- `--allow-network` = 在已隔离的 netns 中配 lo UP + 127.0.0.1/8
- NETLINK 实现
- ~260 行

| 优点 | 缺点 |
|------|------|
| 语义清晰，两轴独立 | `--unshare-net` 行为与 bwrap 不同（bwrap 自动配 lo） |
| 当前行为不变（不 break） | bwrap 用户迁入需额外 `--allow-network` |

### 方案 B：NetworkMode 枚举 + 模块体系（Agent 2 / 可扩展优先）

完整的网络配置体系：
- `NetworkMode::None | Localhost | Nat | Raw`
- `NetworkConfig` 预留 veth / eBPF / DNS / 端口转发字段
- 三级模块：`net/mod.rs` → `net/netlink.rs` → `net/lo.rs`
- 三阶段废弃 `network_enabled: bool`
- ~450 行

| 优点 | 缺点 |
|------|------|
| 扩展路径完整清晰 | 过度设计（当前仅需 lo 配置） |
| Crate API 演进策略明确 | 代码量翻倍 |
| 未来 veth/eBPF 接入路线图 | `NetworkMode` 枚举的 `Nat` / `Raw` 变体短期内无用 |

### 方案 C：bwrap 兼容优先 + 安全默认值（Agent 3）

- `--unshare-net` 自动配 lo UP（bwrap 100% 兼容）
- 默认隐含 `--unshare-net`（Agent 场景安全优先）
- 新增 `--share-net` flag（bwrap 兼容别名）
- `--allow-network` 保留为 `--share-net` 的直观同义词
- 冲突解析：最后 flag 获胜
- NETLINK 实现
- ~300 行

| 优点 | 缺点 |
|------|------|
| bwrap 用户零迁移成本 | 改变 `--unshare-net` 当前行为（lo DOWN → UP） |
| 安全默认值适合 Agent | 需要更新现有测试 |
| 统一的网络语义模型 | |

### 对比矩阵

| 维度 | A: 正交+NETLINK | B: NetworkMode | C: bwrap 兼容 |
|------|:---:|:---:|:---:|
| bwrap CLI 兼容度 | ⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| 实现复杂度 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| 未来扩展准备 | ⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ |
| 当前行为不变 | ✅ | ✅ | ❌ |
| Agent 安全默认值 | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| 代码量 | ~260 | ~450 | ~300 |

---

## 4. 推荐方案：混合 C→A（bwrap 兼容 + 正交保留）

### 核心决策

| # | 决策 | 选择 | 理由 |
|---|---|---|---|
| D1 | `--unshare-net` 行为 | **保持当前行为（lo DOWN）** | 不引入破坏性变更 |
| D2 | `--share-net` | **新增** | bwrap 兼容别名 |
| D3 | `--allow-network` 语义 | **等价于 `--share-net`**（不隔离 netns） | 直观写法 |
| D4 | 默认值 | **保持当前行为**（不隐含隔离） | 不引入静默行为变化 |
| D5 | 实现方式 | **NETLINK** | bwrap 一致、可扩展 |
| D6 | `NetworkConfig` 结构 | **简化版**（当前只加 `loopback: bool`，未来再升枚举） | 不提前抽象 |

### 语义表

| CLI flags | netns? | lo 状态 | 说明 |
|---|---|---|---|
| (无) | 否 | N/A | 主机网络（当前行为） |
| `--unshare-net` | 是 | DOWN | 网络隔离 |
| `--unshare-net --allow-network` | 是 | UP + 127.0.0.1/8 | 隔离 + 本地回环 |
| `--allow-network` | 否 | N/A | 等价于 `--share-net` |
| `--share-net` | 否 | N/A | bwrap 兼容写法 |

### 为什么没有采用 Agent 3 的安全默认值？

Agent 3 提议"默认隐含 `--unshare-net` + lo DOWN"是一个合理的安全方向，但属于另一个决策范畴（Phase 2b 或 3 的安全默认值策略），不应该混在这个 Phase 2 收尾中。Phase 2 收尾目标是**补完已定义的 flag 行为**，而不是改变默认语义。

---

## 5. 模块设计

```
src/linux/net.rs          ← [NEW] NETLINK 网络配置模块
  ├── NetworkConfig       ← { loopback: bool }
  ├── configure_loopback()   ← 主入口：lo UP + 127.0.0.1/8
  ├── netlink_send_recv()    ← 内部：NETLINK 消息发送 + 响应确认
  └── ifaddrmsg / nlmsghdr  ← 手写 #[repr(C)] 结构体（libc 不提供）
```

### `SandboxConfig` 整合

```rust
pub struct SandboxConfig {
    // ... 其他字段不变
    pub network: NetworkConfig,          // 替换 network_enabled: bool
}

// 兼容：with_network(bool) 适配旧 API
impl SandboxConfig {
    pub fn with_network(mut self, enabled: bool) -> Self {
        self.network.loopback = enabled;
        self
    }
}
```

### CLI flag 整合（`main.rs`）

新增 `--share-net` 并调整 `resolve_network_config()`：

```rust
fn resolve_network_config(
    unshare_net: bool,
    share_net: bool,
    allow_network: bool,
    unshare_all: bool,
) -> (bool /* effective_net */, bool /* effective_network */) {
    // --share-net 或 --allow-network → 不隔离
    if share_net || allow_network {
        (false, true)
    } else if unshare_net || unshare_all {
        (true, false)
    } else {
        (false, false)
    }
}
```

### 执行序列

```
pre_exec 序列（改动部分）：
...
3. clearenv + setenv
4. chdir
5. prctl(NO_NEW_PRIVS)
6. uid/gid map
7. [NEW] if ns.net && config.network.loopback {
       net::configure_loopback()
   }
8. sethostname
9. landlock
10. seccomp
11. execve
```

### NETLINK 实现要点

```rust
// libc 不提供 ifaddrmsg，需手动定义
#[repr(C)]
struct ifaddrmsg {
    ifa_family: u8,
    ifa_prefixlen: u8,
    ifa_flags: u8,
    ifa_scope: u8,
    ifa_index: u32,
}

// 对齐宏（C 宏的 Rust 等价）
const NLMSG_ALIGNTO: usize = 4;
const fn nlmsg_align(len: usize) -> usize {
    (len + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
}
```

---

## 6. 代码量估算

| 文件 | 内容 | 行数 |
|---|---|---|
| `src/linux/net.rs` | `NetworkConfig` + `configure_loopback()` + NETLINK 辅助 | ~130 |
| `src/linux/mod.rs` | `pub mod net;` + pre_exec 调用 ~5 行 | ~5 |
| `src/config.rs` | `NetworkConfig` 替代 `network_enabled` + `with_network()` 适配 | ~15 |
| `src/main.rs` | 新增 `--share-net` + `resolve_network_config()` | ~20 |
| `tests/network_test.rs` | 集成测试 | ~90 |
| **总计** | | **~260** |

---

## 7. 边界场景

| 场景 | 行为 |
|------|------|
| `--share-net --unshare-net` | 最后 flag 获胜 → `--share-net` 优先 |
| `--unshare-all --share-net` | 仅网络不隔离，其余 5 个 ns 隔离 |
| `--allow-network` 不带 `--unshare-net` | 无操作（宿主机网络已可用） |
| `configure_loopback()` 失败 | 写 stderr 警告 + 继续 exec（降级策略） |
| 内核不支持 NETLINK | `socket(AF_NETLINK, ...)` 失败 → 写警告 + 继续 |

---

## 8. 测试计划

| 测试 | CLI | 验证点 |
|---|---|---|
| N22: lo UP | `--unshare-net --allow-network -- cat /sys/class/net/lo/operstate` | `"up"` |
| N23: lo DOWN | `--unshare-net -- cat /sys/class/net/lo/operstate` | `"down"` |
| N24: share-net | `--share-net -- true` | exit 0 |
| N25: 127.0.0.1 可达 | `--unshare-net --allow-network -- ping -c 1 127.0.0.1` | exit 0（需要 ping） |
| N26: 与 seccomp 共存 | `--unshare-net --allow-network --seccomp-deny-nr 97 -- true` | exit 0 |

---

## 9. 与第一版的差异总结

| 维度 | 第一版（ioctl） | 本版（NETLINK） |
|------|:---:|:---:|
| 网络配置方式 | `SIOCSIFADDR` + `SIOCSIFNETMASK` + `SIOCSIFFLAGS` | `RTM_NEWADDR` + `RTM_NEWLINK` |
| async-signal-safe | ✅（当时认为需要） | ❌ 但不再约束 |
| bwrap 实现一致 | ❌ | ✅ |
| `--share-net` flag | 不存在 | **新增** |
| `NetworkConfig` | `{ network_enabled: bool }` | `{ loopback: bool }` 结构体 |
| 未来扩展 | ioctl 做不了 veth | NETLINK 可复用 |
| 额外代码 | ~110 行 | ~260 行 |
