# eBPF 网络过滤 — 架构上下文

## 概述

本文件分析 sandbox-runtime 是否需要 eBPF 网络过滤（Phase 2b），以及在当前架构中的定位。

核心问题：**在 netns（二进制阻断）+ Landlock ABI 5（TCP bind/connect）+ seccomp（syscall 拦截）已经覆盖主要隔离场景的前提下，是否有必要引入 aya + cgroup_sock_addr eBPF 来实现 IP 级访问控制？**

---

## 现有架构

### 当前网络隔离手段（Phase 2，已实现）

| 手段 | 能力 | 粒度 | 内核要求 |
|------|------|------|---------|
| `unshare(CLONE_NEWNET)` + lo DOWN | 完全阻断网络 | 二进制 | 2.6.24+ |
| `--unshare-net --allow-network`（Phase 2 收尾） | 放通 loopback 127.0.0.1/8 | 二进制 | 2.6.24+ |
| （无） | 共享宿主机网络 | 无限制 | — |

关键特性：这三种模式都是**二态开关**——要么全通（包括外部网络），要么仅限于 loopback，要么全断。

### 正在设计的 Phase 2 收尾

`docs/arch/phase2-wrapup/` 中设计的 `--allow-network` 使用 NETLINK 将 lo 设为 UP，效果是：

| CLI | netns? | lo 状态 | 网络能力 |
|-----|--------|---------|---------|
| （默认） | 否 | N/A | 宿主机网络 |
| `--unshare-net` | 是 | DOWN | 完全隔离 |
| `--unshare-net --allow-network` | 是 | UP + 127.0.0.1/8 | 仅本地通信 |
| `--allow-network` / `--share-net` | 否 | N/A | 宿主机网络（抑制 netns） |

### Phase 2b 原规划（eBPF 云容器后端）

从 `docs/development-phases.md` 和 `docs/architecture.md` 中提取的原始描述：

```
LinuxEbpfSandbox (云容器, 未来):
  aya + cgroup_sock_addr eBPF
  cgroup v2 进程绑定
  for Cloud/CI/容器环境
```

具体组件：
- `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` — 在 `connect()` / `bind()` 系统调用时触发，可决定放行或拒绝
- `BPF_MAP_TYPE_LPM_TRIE` — 最长前缀匹配 trie，存储 IP 白名单
- 用户态 DNS 解析 + IP 集同步 — 将域名（如 `api.github.com`）解析为 IP，写入 LPM trie
- 自动探测 Landlock → eBPF 降级 — 在容器内 Landlock 不可用时回退到 eBPF

### Landlock ABI 5（Linux 6.10+）的 TCP 限制

Landlock ABI 5 已引入 `LANDLOCK_ACCESS_NET_BIND_TCP` 和 `LANDLOCK_ACCESS_NET_CONNECT_TCP`，可限制 TCP bind/connect 的目标地址和端口。但 Landlock 网络限制目前有局限：

- Landlock 5 仅在 Linux 6.10+ 可用（截至 2026 年，普及度仍有限）
- 限制规则基于文件描述符级别的 allowed-access，粒度比 eBPF LPM trie 粗
- Landlock 无法做 DNS 解析拦截（connect 之前的域名到 IP 转换不受 Landlock 控制）

---

## 约束

| 维度 | 详情 |
|------|------|
| **技术** | 当前 `Cargo.toml` 中零 eBPF 依赖。引入 `aya` 会增加编译复杂性（需要 `bpf-link`、`aya-ebpf`、`aya-log-ebpf` 等，且 eBPF 程序需要编译为独立的 `.o` 文件并用 `aya` 加载） |
| **技术** | eBPF 需要 cgroup v2（大部分现代 Linux 发行版已支持，但 Docker 容器内可能需要额外配置） |
| **技术** | eBPF 程序需要 root 或 `CAP_BPF` + `CAP_NET_ADMIN`，而非特权 user 命名空间内可能无法加载 |
| **性能** | eBPF 每次 connect/bind 都有钩子调用开销（微秒级，通常可忽略）|
| **演进** | 现有 `SandboxConfig` 没有 `network_whitelist`/`network_blacklist` 字段，新增字段需要一并调整 `Builder`、CLI 解析、序列化 |
| **组织** | Phase 2b 标注为"与 Phase 3、4 并行"开发，当前 Phase 2 收尾尚未完成 |

### 与 seccomp 的 bpf 系统调用冲突

当前 `seccomp.rs` 的黑名单中 **包含 `bpf(2)` 系统调用**（x86_64 nr 357），这意味着沙箱子进程**自身**不能加载 eBPF 程序。这是正确的——eBPF 程序应由**父进程（sandbox-runtime 主进程）**在 fork 之前加载并 attach 到 cgroup，然后子进程加入 cgroup 自动受限制。如果未来 Phase 2b 实现，需要：

1. 父进程使用 `aya` 加载 eBPF 程序到合适的位置（cgroup 层级）
2. 子进程通过 `pre_exec` 序列加入该 cgroup
3. 子进程的 seccomp 白名单需要**不拦截**与 eBPF 相关的系统调用（避免干扰 eBPF 运行）

---

## 需求分析：是否需要 eBPF 网络过滤？

### 不做 eBPF 时的替代方案

| 方案 | 能力 | 不足 |
|------|------|-----|
| **netns（现状）** | 全有/全无 | 没有中间态 |
| **netns + lo UP（Phase 2 收尾）** | 仅本地通信 + 完整外部网络 | 没有精细的"只允许某些 IP" |
| **Landlock ABI 5 TCP** | 限制 TCP connect/bind 的目标 | 内核要求高（6.10+），粒度粗，不支持域名级/端口级白名单 |
| **iptables/nftables（netns 内）** | 在 netns 内做精细过滤 | 需要 `CAP_NET_ADMIN`，与 user ns 互斥 |
| **应用层代理** | 可做精细控制 | 引入依赖，需要配置 |

### 原始 Phase 2b 设计的前提假设

Phase 2b 的 eBPF 方案基于两个前提：

1. **云/容器场景下 Landlock 不可用**：部分 Docker/K8s 容器在旧内核上无法使用 Landlock，需要替代方案来做文件系统和网络限制
2. **IP 级访问控制**：在云场景中，多租户环境需要精确控制某个进程可以连接哪些外部服务（如仅限 `api.github.com`）

### 当前项目目标是否仍然需要这两个前提？

- **目标平台**：本地 Linux 开发机（开发者运行 Agent 工具的场景）。此场景下 Landlock 5.13+ 通常可用，且**二进制网络隔离已经足够**：Agent 要么需要网络访问来执行 `git push` / `cargo build` / `npm install`，要么完全不需要（运行本地脚本）
- **云/容器场景**：目前标注为 Phase 4（CodeWhale 集成 + HTTP API），离实际开发较远

### 判断

| 场景 | 当前 | eBPF 必要性 |
|------|------|------------|
| 本地开发（CLI） | netns + lo DP | **不需要** — netns 二进制阻断已覆盖威胁模型 |
| 本地开发（需外部网络） | 不设 netns | **不需要** — 连接到宿主机网络，用户信任应用 |
| 本地开发（受限外部网络） | 无方案 | **可能有需求** — 但目前没有具体场景驱动 |
| 云/容器（Phase 4） | Landlock 不可用 | **需要** — eBPF 是 Landlock 的替代品，但 Phase 4 尚未开始 |

---

## 需求范围

### 范围内（当前应该做的）

1. **完成 Phase 2 收尾**：`--allow-network` 真实行为（NETLINK lo UP）
2. **保持 eBPF 在路线图上**：不删除 Phase 2b，但明确标注为"云容器场景预留"
3. **`NetworkConfig` 预留**：在 `SandboxConfig` 中保留扩展字段，避免未来大改

### 范围外（明确不做的）

- 在当前 Phase（2 收尾）中实现 eBPF
- 在 CLI 中添加 IP 白名单/黑名单标志
- 引入 aya 依赖
- 实现 cgroup v2 管理

### 关键场景

#### 场景 1（当前）：本地 Agent 开发 → 二进制网络隔离

```
# 完全隔离
sandbox-runtime run --unshare-net -- ./dangerous_script.sh

# 允许本地通信
sandbox-runtime run --unshare-net --allow-network -- ./test_with_localhost.sh

# 允许完整外部网络
sandbox-runtime run -- curl https://crates.io
```

#### 场景 2（未来，Phase 4）：云容器中限制仅能访问指定 API

```
# 假设 Phase 2b 已实现
sandbox-runtime run \
  --allow-network \
  --allow-connect api.github.com:443 \
  --allow-connect crates.io:443 \
  -- cargo build
```

### 异常/边界场景

| 场景 | 处理方式 |
|------|---------|
| 内核不支持 Landlock | fallback 到 seccomp-only（当前行为） |
| 内核不支持 eBPF cgroup_sock_addr | 应该检测并报错，fallback 到 netns-only |
| 容器内缺少 CAP_BPF | 无法加载 eBPF，需要降级 |
| DNS 解析返回多个 IP | LPM trie 需要包含所有可能 IP |

---

## 未澄清问题

- [ ] **有没有具体需求方**想要 Phase 2b？还是仅为架构完整性预留？
- [ ] 如果需要 IP 级过滤，是否有更轻量的替代（如 `nftables` 规则注入 netns）比 eBPF 更简单且不需要 `CAP_BPF`？
- [ ] Landlock ABI 5+ 的 TCP 限制能不能覆盖未来大部分网络需求？如果能，eBPF 的必要性进一步降低。
- [ ] 容器场景（Docker/K8s）中 Landlock 的实际可用率如何？

---

## 结论

**当前阶段（Phase 2 收尾）不需要 eBPF 网络过滤。**

理由：
1. **威胁模型匹配**：本地 Agent 开发场景的隔离需求是二态的（全有/全无），netns 已覆盖
2. **内核门槛高**：`aya` + cgroup v2 + `CAP_BPF` 的组合在普通 Linux 桌面/服务器上并非常态
3. **维护成本**：引入 `aya` 意味着构建时需编译 eBPF 程序（`bpf-link`）、运行时需加载器和映射管理
4. **Landlock ABI 5** 已提供一定程度的 TCP 限制，且与当前架构无缝集成
5. **Phase 4（云/容器集成）尚未开始**：届时再引入 eBPF 可以有更明确的需求驱动

**保留 Phase 2b 在路线图上**，但建议：
- 降低优先级为"当 Phase 4 启动时重新评估"
- 在 `NetworkConfig` 中预留 `ip_whitelist: Vec<String>` 等字段
- 如果未来需要，可以考虑先用 `nftables` 在 netns 内做过滤（更简单、无需 `CAP_BPF`）

---

## 后续建议

1. 用 `arch-validate` review 这个分析，特别是对 Landlock ABI 5 替代能力的评估
2. 用 `arch-design` 设计 `NetworkConfig` 的预留字段结构
3. 完成 Phase 2 收尾后再评估 eBPF 路线图
