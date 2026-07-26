# 动态 seccomp 策略设计

> 讨论时间：2026-07-24 ~ 2026-07-25
> 参与人：Zhang Shuai + Claude

---

## CLI 接口

```
# syscall 号拦截（USER_NOTIF，精确诊断）
sandbox-runtime run --seccomp-deny-nr 165 -- ls

# 外部 cBPF 堆叠（prctl 直装，无诊断）
sandbox-runtime run --seccomp-filter-fd 3 -- ls 3< block.bpf

# 混合：内部 deny 兜底 + 外部 BPF 收紧
sandbox-runtime run \
  --seccomp-deny-nr 165 \
  --seccomp-filter-fd 3 \
  -- ls 3< extra.bpf

# 不传 seccomp 参数 → 不装任何 filter
```

## 默认行为

- 不传任何 `--seccomp-deny-nr` 或 `--seccomp-filter-fd` → 不装任何 seccomp filter
- 没有默认黑名单（移除了原有的 13 个 syscall 默认拦截）
- 没有内置分类（移除了 SyscallCategory 和 `--deny mount` 等分类接口）

## 拦截方式

| 参数 | 安装方式 | 拦截行为 | 诊断 |
|---|---|---|---|
| `--seccomp-deny-nr` | NEW_LISTENER + USER_NOTIF | 返回 EPERM（子进程继续运行） | ✅ 精确到 nr/arch |
| `--seccomp-filter-fd` | prctl 直装 | 由外部 BPF 决定 | ❌ 无（同 bwrap）|

## 多 filter 堆叠

多个 `--seccomp-filter-fd` 按顺序安装，内核按逆序评估（后装先查）。

安装顺序（子进程内）：
1. `prctl(PR_SET_NO_NEW_PRIVS)`
2. 内部 deny-nr filter（NEW_LISTENER）← 返回 listener fd
3. 外部 BPF #1（prctl，无 NEW_LISTENER）
4. 外部 BPF #2（prctl，无 NEW_LISTENER）
5. ...

内核评估顺序（逆序）：
- 外部 BPF #2 → 外部 BPF #1 → 内部 deny-nr filter
- 外部 BPF 只能进一步收紧，不能放行内部 deny 拦掉的 syscall
- 外部 BPF 作者需确保前 n-1 个 filter 放行 `PR_SET_SECCOMP`

## 为什么不用分类/名字接口

参考 bwrap：bwrap 不内置策略、不提供分类或名字解析，全部从外部 fd 读原始 BPF。

我们的思路一致——不预制策略、不替用户做安全判断。只提供原始接口：
- `--seccomp-deny-nr`：精确到 syscall 号，用户自己知道要拦什么
- `--seccomp-filter-fd`：完全自定义 BPF，堆叠任意复杂策略

放弃原有的：
- `SyscallCategory` 枚举（6 个分类）
- `--deny mount` 等分类级 CLI flag
- 13 个 syscall 的默认黑名单
- 架构号→名字映射表的维护负担（仅保留诊断用的 SYSCALLS 表）

## 设计参考

bwrap 的 seccomp 实现（`/home/zs/OpenSrc/bubblewrap/bubblewrap.c`）：
- 接受预编译的原始 cBPF 二进制，来自文件描述符
- 不做任何 BPF 解释、不内置策略、不依赖 libseccomp
- `--seccomp FD`（单次）和 `--add-seccomp-fd FD`（可重复堆叠）
- 使用 fd 而非文件路径：避免了 setuid 程序的 TOCTOU 问题，也避免了命名空间变化后路径含义改变的歧义
- 我们不需要 setuid，但出于安全一致性选择了同样的 fd 接口

## 配置层

```rust
pub struct SandboxConfig {
    // ... 已有字段 ...
    pub seccomp_deny_nrs: Vec<u32>,         // 来自 --seccomp-deny-nr
    pub seccomp_filter_bytes: Vec<Vec<u8>>, // 来自 --seccomp-filter-fd
}
```

`seccomp_filter_bytes` 在 `cmd_run()` 中从 fd 读出原始字节，传给 config。

## 执行流

```
                        ┌─ deny-nr 非空？
                        ├─ 有：创建 socketpair → fork →
                        │     子进程：install deny filter (NEW_LISTENER) → sendmsg listener fd
                        │     子进程：install 外部 BPF (prctl 直装)
                        │     子进程：exec
                        │   父进程：spawn USER_NOTIF worker → recv → waitpid
                        │
                        └─ 无 → filter_bytes 非空？
                            ├─ 有：fork →
                            │     子进程：install 外部 BPF (prctl 直装)
                            │     子进程：exec
                            │   父进程：waitpid（无 worker）
                            │
                            └─ 无：fork → exec → waitpid（纯 Landlock/namespace，无 seccomp）
```

## 涉及文件

| 文件 | 改动 |
|---|---|
| `src/linux/seccomp.rs` | 删 SyscallCategory/BLACKLIST/target_arch_config/build_blacklist_filter；新增 build_deny_filter() + install_plain_filter()；简化 Syscall struct；保留 SYSCALLS 表（诊断用）|
| `src/config.rs` | SandboxConfig 加 seccomp_deny_nrs + seccomp_filter_bytes 字段；加 with_seccomp_deny_nr() + with_seccomp_filter() |
| `src/linux/mod.rs` | build_bpf_filter() 返回 Option；execute() 三条路径（deny/external/none）；子进程外部 BPF 安装循环 |
| `src/main.rs` | 加 --seccomp-deny-nr 和 --seccomp-filter-fd CLI flag；cmd_run 中从 fd 读原始字节 |
| `tests/seccomp_test.rs` | 适配 build_deny_filter 新签名；新增 --seccomp-deny-nr 端到端测试 |
| `tests/deny_detect_test.rs` | 更新 classify_exit 富消息断言（去掉 category/reason 字段）|
| `docs/linux-sandbox.md` | 更新 seccomp 黑名单章节 |
| `CONTEXT.md` | 更新 Seccomp Blacklist 和 SyscallCategory 相关词汇 |
