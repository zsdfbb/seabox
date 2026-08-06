# Future Extensions

暂不实现，路线预留。每个扩展都标注了"什么时候该做"。

## 1. 动态授权：Violation Hook + SECCOMP_RET_USER_NOTIF

当前策略是**静态配置 + 明确拒绝**。未来需要 Agent 在沙箱拒绝时**主动询问用户**或根据运行时上下文调整策略，可考虑以下机制。

> **2026-08-06 评估结论：动态授权暂缓，先做 coding-agent profile。**
> 讨论"base 权限（agent 不可修改）+ agent 动态叠加"后得出的结论：
> - coding agent 真实权限需求约 95% 静态（工作区 rw + /tmp rw + loopback + 默认零 cap），打包现有 flag 成 TOML profile 即覆盖，无需新机制。
> - 动态叠加唯一实值是 **per-command 最小权限**（缩小单条命令爆炸半径），属防御纵深优化而非功能需求。
> - 权限 UX（allow/ask/deny）是 agent 框架的职责；seabox 若做运行时请求通道，会重复框架 UX 并引入"不可信 agent → 可信 host"的 IPC 攻击面。
> - 若日后重评，最小形态是 `seabox::policy` 模块（`BasePolicy + PermissionRequest + merge()`），作为给 host 框架的校验 helper，而非运行时通道。信任边界必须在 host 进程（agent 不可直接配置 seabox）；安全性靠单调性：Landlock grant-only / seccomp deny-only / caps 上限。**"base 不可修改"要同时表达 floor（强制基线，不可削弱）与 ceiling（允许扩张菜单，菜单法避免路径解析）**。

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
