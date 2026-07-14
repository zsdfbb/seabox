# Development Phases

```
Phase 1 ─── Core + Linux 文件系统隔离
 ├── Sandbox trait + Config + CommandSpec
 ├── Linux: Landlock ruleset 实现
 ├── Linux: seccomp 基础过滤（禁用 mount, ptrace, kexec 等）
 ├── CLI: sandbox-runtime <command>
 └── cargo test 验证允许/拒绝路径

Phase 2 ─── Linux 完整进程隔离
 ├── user_namespace（必需，netns 依赖）
 ├── netns 网络阻断
 ├── setrlimit 资源限制
 └── 自定义 seccomp 策略

Phase 2b ─── eBPF 云容器后端（未来扩展）
 ├── aya eBPF 库集成
 ├── BPF_PROG_TYPE_CGROUP_SOCK_ADDR connect 拦截
 ├── BPF_MAP_TYPE_LPM_TRIE 白名单 IP 前缀
 ├── 用户态 DNS 解析 + IP 集同步
 ├── 自动探测 Landlock → eBPF 降级
 └── K8s/Docker 内验证

Phase 3 ─── macOS 支持
 ├── Seatbelt profile 动态生成
 ├── sandbox-exec 包装
 ├── 拒绝检测
 └── 跨平台 Sandbox enum（Linux | MacOs | None）

Phase 4 ─── CodeWhale 集成
 ├── adapter → codewhale::sandbox::SandboxExecutor
 ├── CodeWhale 的 SandboxManager 改用本 crate
 └── HTTP API serve 模式（OpenSandbox 兼容）
```

## 阶段依赖关系

```
Phase 1 ──→ Phase 2 ──→ Phase 3 ──→ Phase 4
                │
                └─→ Phase 2b（独立分支，云场景）
```

Phase 2b 与 Phase 3、4 并行，不阻塞主线。