# Future Extensions

暂不实现，路线预留。每个扩展都标注了"什么时候该做"。

## 1. 动态授权：Violation Hook + SECCOMP_RET_USER_NOTIF

当前策略是**静态配置 + 明确拒绝**。未来需要 Agent 在沙箱拒绝时**主动询问用户**或根据运行时上下文调整策略，可考虑以下机制。

### Violation Hook（轻量）

```rust
pub trait Sandbox: Send + Sync {
    fn on_violation(&self, event: &ViolationEvent) -> ViolationDecision {
        ViolationDecision::Deny
    }
}

pub enum ViolationDecision {
    AllowOnce,
    AllowPersist,
    Deny,
}
```

实现方式：
- `execute()` 前预判可能的 violation，统一询问
- 用户返回决策 → 动态调整 Landlock ruleset → re-exec

### SECCOMP_RET_USER_NOTIF（已实现，但仅用于日志）

本项目已采用 `SECCOMP_RET_USER_NOTIF` 获取 seccomp 拦截详情。现有实现仅记录 `(nr, arch)` 并回复 `EPERM`。**扩展方向**：对特定 syscall 返回 `SECCOMP_RET_ALLOW` 以实现运行时放行（而非通过修改 BPF filter）。

## 2. 自定义 seccomp 策略（Phase 2 目标）

允许用户通过 `SandboxConfig` 配置黑名单 syscall 的增删，在构建 BPF filter 时动态生成。数据模型的分类标签（`mount`/`debug`/`boot`/`module`/`namespace`/`bpf`）已预留。

## 3. IP 级网络过滤

**已搁置**（`docs/arch/ebpf-network-filtering/context.md`），待 Phase 4 云/容器集成时有具体需求时重新评估。

备选方案：
- **eBPF 路线**：aya + `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` connect 拦截 + `BPF_MAP_TYPE_LPM_TRIE` 白名单 IP 前缀。需要 cgroup v2 + CAP_BPF。
- **nftables 路线**：在隔离的 netns 内注入 nftables 规则，无需 CAP_BPF，但需要 `nsenter` 或父进程有 `CAP_NET_ADMIN`。

详见 `development-phases.md` 的 Phase 2b。

## 4. PID namespace

防御深度特性，Phase 2 末评估后再决定是否纳入。当前 seccomp 黑名单已拦截 `unshare(CLONE_NEWUSER)`，PID ns 的拦截会自然生效。

## 5. Windows 支持

当前不做。仅 Linux + macOS。

## 评估标准

新扩展**不**应轻易启动如果：
- 现有机制能解决问题（即使不那么优雅）
- 增加使用者的认知负担
- 引入新的外部依赖

新扩展**应该**启动如果：
- 真实用户场景明确出现该需求
- 现有机制在某些环境不可用（不可绕过）
- 价值显著大于维护成本
