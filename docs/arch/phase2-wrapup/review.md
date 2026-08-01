# Phase 2 Wrap-Up — 架构质量分析报告

> 分析时间：2026-07-26
> 分析对象：`docs/arch/phase2-wrapup/design.md`（设计方案）
> 分析维度：可行性 / 可维护性 / 可理解性 / 性能与可靠性

---

## 总体评价

| 维度 | 评级 | 摘要 |
|------|:----:|------|
| 可行性 | 🟢 | ioctl 是成熟且行为稳定的 Linux API，实现风险极低 |
| 可维护性 | 🟡 | 新模块边界清晰，但 `ifreq union` 的字段访问跨 libc 版本有差异；fd 泄漏路径需注意 |
| 可理解性 | 🟢 | 概念简单（3 个 ioctl），归档位置明确 |
| 性能与可靠性 | 🟡 | 微秒级开销，但错误处理可改进（fd 泄漏 + 静默降级） |

---

## 1. 可行性 🟢

### 技术可实现性

`ioctl(SIOCSIFADDR)` + `SIOCSIFNETMASK` + `SIOCSIFFLAGS` 是 Linux 最基础、最稳定的网络接口配置方式，自 2.0 内核就存在。实现路径清晰。

### 依赖检查

| 依赖 | libc 0.2 支持 | 风险 |
|------|:------------:|------|
| `libc::ifreq` | ✅ `#[repr(C)]` 结构体 | 低。`ifr_name` 字段类型在 libc 0.2.x 各小版本间有细微差异（`[c_char; 16]` vs `[u8; 16]`），需在编译时确认 |
| `libc::SIOCSIFADDR` | ✅ 常量 | 零风险，三十年未变 (0x8916) |
| `libc::SIOCSIFNETMASK` | ✅ 常量 | 零风险 (0x891c) |
| `libc::SIOCSIFFLAGS` | ✅ 常量 | 零风险 (0x8914) |
| `libc::IFF_UP` | ✅ 常量 | 零风险 (0x1) |
| `libc::AF_INET` | ✅ | 零风险 |
| `struct sockaddr_in` | ✅ | 通用，确定可用 |

### 实现周期评估

约 50 行代码、1 个新文件 + 3 行调用点改动。单人半天内完成编码 + 基本测试。

**主要风险**：`ifreq` 的 union 字段访问。`ifr_addr` 是一个 `struct sockaddr`，需要以 `sockaddr_in` 的视角写入 `sin_addr.s_addr = htonl(0x7f000001)`。`libc` 中 `ifreq` 的 `ifr_addr` 字段暴露方式在不同版本间有差异：

```rust
// libc 0.2.x Linux
// ifreq.ifr_ifru.ifru_addr 类型是 libc::sockaddr
// 需要 from_raw_parts 或 transmute 到 sockaddr_in
```

**建议**：实现时用一个 `sockaddr_in` 本地构造后通过 `std::ptr::write` 写入 `ifr.ifr_addr` 的地址。避免依赖 `ifr_ifru` 的字段名（各 libc 版本不一致）。

---

## 2. 可维护性 🟡

### ✅ 模块边界

新函数 `setup_loopback()` 放在 `src/linux/net.rs` 中，与现有 `landlock.rs`、`namespaces.rs`、`seccomp.rs` 平级。职责单一（只配 lo），调用点只有 pre_exec 一处。→ **好**

### ✅ 接口设计

```rust
pub unsafe fn setup_loopback() -> bool
```

- `unsafe` 正确（调用了 libc syscall）
- `bool` 返回值：成功/失败二元信号。在 pre_exec 中够用（失败日志由调用方决定是 `_exit` 还是继续）

### ⚠️ `ifreq` union 访问

不同 libc 版本的 `ifreq` 字段名有差异。这是 "C union → Rust" 的固有问题。

**缓解方案**：
- 直接用 `std::ptr::write` + 偏移量写入 `sockaddr_in` 到 `ifr` 中 `ifr_addr` 的位置，而不是依赖 `ifr_ifru.ifru_addr` 字段名
- 或者在 linux 平台直接使用 `libc::sockaddr_in` 的 `#[repr(C)]` 保证，用安全转换

### ⚠️ 测试维护

`--allow-network` 的集成测试需要内核支持 netns + user ns。现有 skip 守卫机制可以复用，但测试代码量约 +60 行。

### 测试充分性建议

| 测试 | 必须？ | 原因 |
|------|:-----:|------|
| lo UP + 127.0.0.1 可 ping | ✅ | 验证核心功能 |
| lo DOWN 默认状态 | ✅ | 回归保护 |
| `--allow-network` 不带 `--unshare-net` 生效 | ✅ | 验证语义正交 |
| lo UP 后 `/etc/hosts` 等不受影响 | 可选 | 基础假设 |
| 内核无 user ns 时 `--allow-network` | 可选 | skip guard 已覆盖 |

---

## 3. 可理解性 🟢

### 概念一致性

"网络命名空间隔离 → 配 lo → 可用的本地网络"是 Linux 网络虚拟化的标准模式，bbpwrap/firejail/Docker 都在用这条路。项目内没有与之矛盾的设计。

### 文档完整度

- `context.md` ✅ 记录了约束和边界场景
- `design.md` ✅ 四方案对比 + 推荐的决策树清晰
- `adr.md` ✅ 决策理由记录完整

### 新人上手成本

- `ioctl` 代码模式与现有 `seccomp.rs` 中的 `ioctl(SECCOMP_IOCTL_NOTIF_RECV)` 一致。
- 唯一的新概念是 `struct ifreq` 的 union 操作——在 `README.md` 或代码注释中补充一句即可。

---

## 4. 性能与可靠性 🟡

### 性能模型

```
setup_loopback() 开销：
  socket(AF_INET, SOCK_DGRAM)  → ~0.5 µs
  ioctl(SIOCSIFADDR)           → ~1 µs
  ioctl(SIOCSIFNETMASK)        → ~1 µs
  ioctl(SIOCSIFFLAGS)          → ~1 µs
  close(sock)                  → ~0.5 µs
                               ≈ 4 µs total
```

在 pre_exec 中增加 4 µs 对总执行时间（通常 10-100ms 级 fork+exec）可忽略不计。

### ⚠️ 资源泄漏路径（需要修复）

当前 `design.md` 中的伪代码有 fd 泄漏：

```rust
pub unsafe fn setup_loopback() -> bool {
    let sock = libc::socket(...);     // 1. 打开
    if sock < 0 { return false; }
    // ... ioctl 1 ...
    // ... ioctl 2 ← 如果此处失败，sock 永远不会 close
    // ... ioctl 3
    libc::close(sock);                // 只在全成功时关闭
    true
}
```

如果 ioctl#2 失败，`sock` fd 泄漏。在短生命周期进程中单次泄漏影响小，但如果父进程是常驻服务（HTTP API server），泄漏会累积。

**修复建议**：使用 goto-like pattern（用 `match` + 提前 return 时 close）或 RAII wrapper：

```rust
pub unsafe fn setup_loopback() -> bool {
    let sock = libc::socket(...);
    if sock < 0 { return false; }

    let mut ok = true;
    // ioctl 1
    if libc::ioctl(...) < 0 { ok = false; }
    // ioctl 2
    if libc::ioctl(...) < 0 { ok = false; }
    // ioctl 3
    if libc::ioctl(...) < 0 { ok = false; }

    libc::close(sock);
    ok
}
```

### ⚠️ 降级策略：失败后怎么办？

`setup_loopback()` 返回 `false` 有两种选择：

| 策略 | 行为 | 场景 |
|------|------|------|
| **静默继续** | 不阻止 exec，子进程在 netns 中但 lo 不可用 | 用户要外部网络，没 lo 反正也用不了 |
| **_exit(1)** | 阻止 sandbox 启动 | 用户明确要 --allow-network 但配置失败 |

**建议**：静默继续。理由：
- lo 配置失败 ≠ 沙箱机制故障（可能内核不支持某些 ioctl）
- 用户如果真需要 127.0.0.1，程序会报 `bind: Cannot assign requested address`，错误信息清晰
- 与项目风格一致（`sethostname()` 失败也是静默继续）

### 可观测性

当前无日志。建议：在 pre_exec 中固定 stderr 写一行：

```rust
// 仅失败时输出
let _ = libc::write(libc::STDERR_FILENO,
    b"[seabox] warning: failed to set up loopback\n");
```

项目风格已用 `_exit(1)` 报错，`write(STDERR_FILENO)` 是 async-signal-safe 的。

---

## 5. 风险排序

| # | 风险 | 影响 | 可能性 | 等级 |
|---|------|------|--------|:----:|
| 1 | `ifreq` union 字段跨 libc 版本不兼容 | 编译失败 | 低 | 🟡 |
| 2 | ioctl 失败路径 fd 泄漏 | fd 泄漏 | 中 | 🟡 |
| 3 | `setup_loopback()` 失败但静默继续，用户以为 `--allow-network` 生效 | 用户困惑 | 低 | 🟢 |
| 4 | 非 x86_64 架构的 `struct ifreq` 布局不同 | 行为异常 | 极低 | 🟢 |

---

## 6. 改进建议

### 易修复（在实现时直接处理）

1. **fd 泄漏防护**：使用提前 return 时 always-close 模式（section 4 的建议）
2. **添加失败时的 stderr 日志**：一行 `write(STDERR_FILENO, ...)` 即可
3. **在 `setup_loopback()` 注释中注明 `sockaddr_in` 写入方式**：避免后续维护者踩 libc union 字段的坑

### 需讨论

4. **降级策略确认**：失败后静默继续是否是可接受的行为？
5. **测试命名**：N22/N23 是否归入 `namespace_test.rs` 还是单独 `network_test.rs`？

### 架构级

无（当前设计范围小，不存在架构级问题）。
