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

## Phase 4 — CodeWhale 集成（✅ 库级后端集成已完成；HTTP API 仍暂缓）

以 **crate 依赖（库级）** 方式集成进 CodeWhale，替换并删除 Linux bwrap 后端，
覆盖后台非 tty / 后台 tty / 前台（经 job table）**三条** seabox 化执行路径。
**阶段 1+2 已于 2026-08-22 在个人 fork（`/home/zs/Develop/CodeWhale_seabox`）实施完成**：
`SandboxType::Seabox` Linux 默认 + `ExecEnv.seabox` 载体 + `ShellChild::Seabox`；
非 tty `StdioConfig::Piped` / tty `StdioConfig::Fd` + openpty；
结构化拒绝（`blocked()` + stderr 兜底）；`map_safety_level_to_behavior` 接线（D5 `Safe`→no-network）；
删除 `bwrap.rs` / `seccomp.rs`，`prefer_bwrap` 全仓移除。
设计见 `docs/arch/codewhale-integration/design.md`（§9 实施状态），执行计划见
`docs/exec-plans/2026-08-22-codewhale-seabox.md`。

- [x] **阶段 0（seabox 库扩展）✅ 已完成（2026-08-14）**：`CommandOutput` 补 stdout/stderr/timed_out；
      `CommandSpec::with_stdin` + timeout→`Option`；`Sandbox::spawn` + `SandboxChild`
      （try_wait/wait/wait_timeout/kill/id/take_*）+ `StdioConfig`（Inherit/Piped/Fd）；
      `child_setup` 加 `setpgid(0,0)` + stdio dup2 + **business-pid 经 SCM_CREDENTIALS 回传**
      （ADR 006，实测 `id()==宿主 pid`，非 SCM_RIGHTS）；超时强制（默认 None）；`cmd_run` 改
      spawn(Inherit) 流式 + SIGINT/SIGTERM 转发；feature 门控 `cli`。221 测试全绿，
      详见 `docs/design-final/codewhale-stage0-spawn-api.md`
- [x] **阶段 1（CodeWhale 后端替换 + 三路径 seabox 化）✅ 已完成（2026-08-22）**：
      `seabox.rs` 映射后端 + `SandboxType::Seabox`（Linux 默认）+ `ExecEnv.seabox` 载体；
      `map_safety_level_to_behavior` 接线（`Safe` 去网络）；拒绝检测结构化（`blocked()`）+ stderr 兜底；
      删除 `bwrap.rs` / `seccomp.rs`；`prefer_bwrap` 全仓移除。
      **fork 现实修正**：生产 Bash 前台经 `execute_foreground_via_background` → job table（`background=true`），
      `execute_sync_sandboxed`（`shell.rs:1752`）生产零调用——阶段 1 同步语义落于 `spawn_background_sandboxed`，tty 一并纳入。
- [x] **阶段 2（CodeWhale 后台/tty）✅ 已完成（2026-08-22）**：`ShellChild::Seabox` 变体；后台非 tty
      `Sandbox::spawn(Piped)` + job table；后台 tty openpty + `StdioConfig::Fd`；persist 保持
      DangerFullAccess 无沙箱
- [x] **阶段 3（测试与文档）✅ 已完成（2026-08-22）**：spawn / pid 回传 / Fd 注入 / 超时测试（阶段 0 已覆盖大部分）；
      sandbox/seabox/shell 新增用例全绿；tui lib 基线 9 失败（reasoning-effort 8 + unicode 1，fork 现状）保留；
      integration/pty 各有 1 个与 HEAD 基线相同的环境挂；`rg -n 'bwrap|prefer_bwrap' crates/tui` 为空

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
