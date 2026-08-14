# Development Phases

## Phase 1 — Core + Linux 文件系统隔离（✅ 已完成）

- ✅ `Sandbox` trait + `SandboxConfig` + `CommandSpec`
- ✅ `CommandOutput { exit_code, blocked_syscall }` + `ExitReason` 四值枚举
- ✅ Linux: Landlock ruleset 实现（ABI v1-v7，`ro`/`rw`/`rwx`/`all` 预设）
- ✅ Linux: seccomp BPF USER_NOTIF，13 个黑名单 syscall，EPERM 响应，富诊断消息
- ✅ CLI: `seabox run [--landlock path:perm...]` + `check`
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

## Phase 4 — CodeWhale 集成（🚧 进行中）

以 **crate 依赖（库级）** 方式集成进 CodeWhale，替换并删除 Linux bwrap 后端，
覆盖前台同步 / 前台交互 / 后台非 tty / 后台 tty **四条**执行路径（stage1-context 修正 design.md 的"三条"）。设计见 `docs/arch/codewhale-integration/`。

- [x] **阶段 0（seabox 库扩展）✅ 已完成（2026-08-14）**：`CommandOutput` 补 stdout/stderr/timed_out；
      `CommandSpec::with_stdin` + timeout→`Option`；`Sandbox::spawn` + `SandboxChild`
      （try_wait/wait/wait_timeout/kill/id/take_*）+ `StdioConfig`（Inherit/Piped/Fd）；
      `child_setup` 加 `setpgid(0,0)` + stdio dup2 + **business-pid 经 SCM_CREDENTIALS 回传**
      （ADR 006，实测 `id()==宿主 pid`，非 SCM_RIGHTS）；超时强制（默认 None）；`cmd_run` 改
      spawn(Inherit) 流式 + SIGINT/SIGTERM 转发；feature 门控 `cli`。221 测试全绿，
      详见 `docs/design-final/codewhale-stage0-spawn-api.md`
- [ ] **阶段 1（CodeWhale 同步路径）【下一步】**：`seabox.rs` 后端 + `SandboxType::Seabox`（Linux 默认）；
      `map_safety_level_to_behavior` 接线（`Safe` 去网络）；拒绝检测结构化；删除 `bwrap.rs` / `seccomp.rs`；
      移除 `prefer_bwrap`。范围覆盖前台两条路径（同步 + 交互 `execute_interactive_sandboxed`）。
      **开工前置决策**（探索见 `docs/arch/codewhale-integration/stage1-context.md`）：
      Q1 后端集成模型（`ExecEnv` 包装 vs `SandboxExecutor` 接线 vs 内联）；Q2 bwrap 删除时机
      （建议保留到阶段 2，消除后台安全空窗）
- [ ] **阶段 2（CodeWhale 后台/tty，覆盖路径 3/4）**：`ShellChild::Seabox` 变体；后台非 tty
      `Sandbox::spawn(Piped)` + job table；后台 tty openpty + `StdioConfig::Fd`；persist 保持
      DangerFullAccess 无沙箱
- [ ] **阶段 3（测试与文档）**：spawn / pid 回传 / Fd 注入 / 超时测试（阶段 0 已覆盖大部分）；scm_creds
      容器化探针；同步与后台/tty parity 测试

> **2026-08-14 决策：HTTP API 暂缓（维持）。** 调研结论：
> HTTP sandbox API（OpenSandbox、E2B、Daytona……）是"远程 microVM/容器沙箱"市场的标配，
> 与本项目"本地 OS 沙箱（Landlock + seccomp + ns）"的威胁模型不匹配——加入该生态需要容器/K8s + 注入 daemon，
> 现有消费者不会连本地 daemon。若日后做"嵌入 Agent 框架"的接入，优先考虑 **MCP tool server** 而非 HTTP。
> Phase 4 现聚焦 **CodeWhale 库级集成**（`docs/arch/codewhale-integration/`），HTTP API 不在本期范围。

## 阶段依赖关系

```
Phase 1 (✅) ──→ Phase 2 (✅) ──→ Phase 3 ──→ Phase 4
                     │
                     └── 收尾（已完成）：mount ns + NETLINK lo UP
```

Phase 2b 从"独立并行分支"改为"Phase 4 的前置依赖"：只有当 Phase 4 云/容器集成启动且有 IP 级过滤的具体需求时，才重新评估 eBPF 或 nftables 方案。
