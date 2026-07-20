# Development Phases

## Phase 1 — Core + Linux 文件系统隔离（✅ 已完成）

- ✅ `Sandbox` trait + `SandboxConfig` + `CommandSpec`
- ✅ `CommandOutput { exit_code, blocked_syscall }` + `ExitReason` 四值枚举
- ✅ Linux: Landlock ruleset 实现（ABI v1-v7，`ro`/`rw`/`rwx`/`all` 预设）
- ✅ Linux: seccomp BPF USER_NOTIF，13 个黑名单 syscall，EPERM 响应，富诊断消息
- ✅ CLI: `sandbox-runtime run [--landlock path:perm...]` + `check`
- ✅ 87 项集成测试（Landlock ACL + 13 个 syscall 逐项 + 拒绝检测 + 配置解析）

**验证状态**：`cargo test` 全通过，`cargo clippy -- -D warnings` 零警告，`cargo fmt` 合规。

## Phase 2 — Linux 完整进程隔离（🚧 进行中）

- **user_namespace（netns 依赖）**：`unshare(CLONE_NEWUSER)` 让非特权进程能创建新的网络命名空间。这是 netns 的前置条件
- **netns 网络阻断**：`unshare(CLONE_NEWNET)` + lo down，阻断子进程的网络访问能力
  - 可选：放通 loopback（`ip link set lo up`）以允许本地通信
- **新增 `--allow-network` 真实实现**：当前为占位 flag，Phase 2 接入 netns 后生效
- **动态 seccomp 策略**：允许按分类在 `SandboxConfig` 中增删黑名单 syscall（如放行 ptrace、额外拦截 `clone3`）

**依赖**：当前 seccomp 黑名单已拦截 `unshare(CLONE_NEWUSER)` ——
Phase 2 需在 `pre_exec` 中**先** `unshare`，**后**加载 seccomp filter，
否则 unshare 会被自身拦截。

## Phase 2b — eBPF 云容器后端（💡 未来扩展）

- aya eBPF 库集成
- `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` connect 拦截
- `BPF_MAP_TYPE_LPM_TRIE` 白名单 IP 前缀
- 用户态 DNS 解析 + IP 集同步
- 自动探测 Landlock → eBPF 降级
- K8s/Docker 内验证

Phase 2b 与 Phase 3、4 并行，不阻塞主线。

## Phase 3 — macOS 支持（💡 计划中）

- Seatbelt profile 动态生成
- `sandbox-exec` 包装
- 拒绝检测
- 跨平台 `Sandbox` enum（`Linux | MacOs | None`）

## Phase 4 — CodeWhale 集成（💡 计划中）

- adapter → `codewhale::sandbox::SandboxExecutor`
- HTTP API serve 模式（OpenSandbox 兼容，axum）
- TOML 配置模板

## 阶段依赖关系

```
Phase 1 (✅) ──→ Phase 2 (🚧) ──→ Phase 3 ──→ Phase 4
                     │
                     └─→ Phase 2b（独立分支，云场景）
```
