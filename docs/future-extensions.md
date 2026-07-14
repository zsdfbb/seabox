# Future Extensions

暂不实现，路线预留。每个扩展都标注了"什么时候该做"。

## 1. 动态授权：Violation Hook + SECCOMP_RET_USER_NOTIF

当前 Phase 1-4 的策略都是**静态配置 + 明确拒绝**。未来需要 Agent 在沙箱拒绝时**主动询问用户**或根据运行时上下文调整策略，可考虑以下机制。

### Violation Hook（轻量）

```rust
pub trait Sandbox: Send + Sync {
    /// 沙箱拒绝前回调，让上层决定如何处理
    /// 默认 = 直接拒绝
    fn on_violation(&self, event: &ViolationEvent) -> ViolationDecision {
        ViolationDecision::Deny
    }
}

pub enum ViolationDecision {
    AllowOnce,    // 这次放行
    AllowPersist, // 加入 allowlist
    Deny,
}
```

实现方式：
- `execute()` 前预判可能的 violation，统一询问
- 用户返回决策 → 动态调整 Landlock ruleset → re-exec

### SECCOMP_RET_USER_NOTIF（重量，5.0+ 内核）

```
沙箱进程 syscall 被 BPF 拦截
  ↓
内核挂起 syscall，挂到 notify fd
  ↓
policy manager 进程通过 ioctl 读 syscall 详情
  ↓
决策后返回 SECCOMP_RET_ALLOW / SECCOMP_RET_ERRNO
```

适用场景：
- 文件访问的细粒度运行时决策（不仅是路径白名单）
- 网络连接的运行时决策（域名级而非 IP 级）
- 需要"暂时提升权限"的安全模式（如一次性 token）

实现复杂度：需要 supervisor 进程管理 notify fd，比单进程方案复杂。**只在前述场景明确出现时再实现**。

## 2. eBPF 云容器后端

详见 `linux-sandbox.md` 的"环境适配策略"和 `development-phases.md` 的 Phase 2b。

## 3. 网络代理（macOS / 兜底）

代理模式仅在 Landlock/eBPF 不可用时作为 fallback。需要时再引入。

## 4. PID namespace

防御深度特性，不是必需。Phase 2 末评估后再决定是否纳入。

## 5. Windows 支持

当前不做。仅 Linux + macOS。

## 评估标准

新扩展**不**应在以下情况轻易启动：
- 现有机制能解决问题（即使不那么优雅）
- 增加使用者的认知负担
- 引入新的外部依赖

新扩展**应该**启动的情况：
- 真实用户场景明确出现该需求
- 现有机制在某些环境不可用（不可绕过）
- 价值显著大于维护成本