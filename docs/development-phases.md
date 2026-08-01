# Development Phases

## Phase 1 — Core + Linux 文件系统隔离（✅ 已完成）

- ✅ `Sandbox` trait + `SandboxConfig` + `CommandSpec`
- ✅ `CommandOutput { exit_code, blocked_syscall }` + `ExitReason` 四值枚举
- ✅ Linux: Landlock ruleset 实现（ABI v1-v7，`ro`/`rw`/`rwx`/`all` 预设）
- ✅ Linux: seccomp BPF USER_NOTIF，13 个黑名单 syscall，EPERM 响应，富诊断消息
- ✅ CLI: `sandbox-runtime run [--landlock path:perm...]` + `check`
- ✅ 87 项集成测试（Landlock ACL + 13 个 syscall 逐项 + 拒绝检测 + 配置解析）

**验证状态**：`cargo test` 全通过，`cargo clippy -- -D warnings` 零警告，`cargo fmt` 合规。

## Phase 2 — Linux 完整进程隔离（✅ 已完成）

- ✅ user namespace + uid/gid 映射（非 root 自动启用，ns 内无特权）
- ✅ netns 网络阻断（`unshare(CLONE_NEWNET)` + lo DOWN）+ `--allow-network` 放通 loopback（NETLINK `SIOCSIFADDR` + lo UP）
- ✅ PID namespace（非 root 下自动叠加 user ns，子进程为 PID 1/reaper）
- ✅ UTS / IPC / Cgroup namespace
- ✅ mount namespace（`--unshare-mnt`）+ `--bind` / `--ro-bind` / `--tmpfs`
- ✅ 动态 seccomp（`--seccomp-deny-nr` / `--seccomp-filter-fd`）
- ✅ fork 后子进程零堆操作（ADR 0003，多线程安全）
- ✅ 21+ 项 namespace 端到端测试 + mount / network / concurrent-fork 专项测试

**关键顺序**：`pre_exec` 中**先** `unshare`、**后**加载 seccomp filter——否则 `unshare(CLONE_NEWUSER)` 会被自身黑名单拦截。

**收尾**（已完成，设计见 `docs/arch/phase2-wrapup/` 与 `docs/arch/mount-namespace/`）：
- `--allow-network` 真实实现（NETLINK lo UP），`--share-net` bwrap 兼容别名
- mount ns 设计 + ADR + review

## Phase 2b — IP 级网络过滤（⏸️ 已搁置，待 Phase 4 时重新评估）

> **搁置决策**（参考 `docs/arch/ebpf-network-filtering/context.md`）：
> 本地 Agent 开发场景的网络隔离需求为二态（全有/全无），`unshare(CLONE_NEWNET)` + lo UP/DOWN 已覆盖威胁模型。
> eBPF 网络过滤的维护成本（aya 依赖 + cgroup v2 + CAP_BPF）当前没有对应的场景驱动。
> 如果 Phase 4（CodeWhale 云/容器集成）产生"仅允许特定 IP"的精确需求时再评估。

选项：
- **eBPF 路线**（原计划）：aya + `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` connect 拦截 + `BPF_MAP_TYPE_LPM_TRIE` 白名单 IP 前缀
- **nftables 路线**（轻量替代）：在 netns 内注入 nftables 规则做 IP 过滤，无需 CAP_BPF

Phase 2b 原与 Phase 3、4 并行，现明确降级为 Phase 4 的前置依赖。

## Phase 3 — macOS 支持（💡 计划中）

- Seatbelt profile 动态生成
- `sandbox-exec` 包装
- 拒绝检测
- 跨平台 `Sandbox` enum（`Linux | MacOs | None`）

## Phase 4 — CodeWhale 集成（💡 计划中）

- adapter → `codewhale::sandbox::SandboxExecutor`
- HTTP API serve 模式（OpenSandbox 兼容，axum）
- TOML 配置模板

> **2026-08 决策：HTTP API 暂缓。** 调研结论：
> HTTP sandbox API（OpenSandbox、E2B、Daytona……）是"远程 microVM/容器沙箱"市场的标配，
> 与本项目"本地 OS 沙箱（Landlock + seccomp + ns）"的威胁模型不匹配——加入该生态需要容器/K8s + 注入 daemon，
> 现有消费者不会连本地 daemon。若日后做"嵌入 Agent 框架"的接入，优先考虑 **MCP tool server** 而非 HTTP。

## 阶段依赖关系

```
Phase 1 (✅) ──→ Phase 2 (✅) ──→ Phase 3 ──→ Phase 4
                     │
                     └── 收尾（已完成）：mount ns + NETLINK lo UP
```

Phase 2b 从"独立并行分支"改为"Phase 4 的前置依赖"：只有当 Phase 4 云/容器集成启动且有 IP 级过滤的具体需求时，才重新评估 eBPF 或 nftables 方案。
