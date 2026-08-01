# 动态 seccomp 策略

> 设计时间：2026-07-25
> 状态：**待实现**
> 来源：`tmp/seccomp-design.md`（讨论稿）

---

## 1. 目标

将 seccomp 从"内置 13 syscall 默认黑名单"改为**完全用户驱动**：
- 不传 seccomp 参数 → 不装任何 filter
- `--seccomp-deny-nr N` → USER_NOTIF 拦截指定 syscall（精确诊断）
- `--seccomp-filter-fd FD` → 堆叠外部原始 cBPF（无诊断）

## 2. CLI 接口

```
seabox run --seccomp-deny-nr 165 -- ls          # 拦截 mount
seabox run --seccomp-filter-fd 3 -- ls 3< x.bpf # 外部 BPF
seabox run --seccomp-deny-nr 165 --seccomp-filter-fd 3 -- ls 3< x.bpf  # 混合
```

- `--seccomp-deny-nr`：可重复，每个指定一个 syscall 号
- `--seccomp-filter-fd`：可重复，每个从 fd 读取原始 cBPF 字节
- 不传任何 seccomp 参数 → 不装 filter

## 3. 三条执行路径

```
                ┌─ deny-nr 非空？
                ├─ YES → 路径 A
                └─ NO  → filter_bytes 非空？
                    ├─ YES → 路径 B
                    └─ NO  → 路径 C
```

**路径 A**（deny-nr，有诊断）：
- socketpair → fork
- 子进程：install deny filter (NEW_LISTENER) → sendmsg listener fd → install 外部 BPF (prctl) → exec
- 父进程：spawn USER_NOTIF worker → recv → waitpid

**路径 B**（仅外部 BPF，无诊断）：
- fork → 子进程：install 外部 BPF (prctl) → exec → 父进程：waitpid

**路径 C**（无 seccomp）：
- fork → exec → waitpid

## 4. 涉及文件

| 文件 | 改动 |
|---|---|
| `src/linux/seccomp.rs` | 删 SyscallCategory/BLACKLIST/target_arch_config/build_blacklist_filter；新增 `build_deny_filter()` + `install_plain_filter()`；简化 Syscall struct（移除 category）；保留 SYSCALLS 表 |
| `src/config.rs` | SandboxConfig 加 `seccomp_deny_nrs` + `seccomp_filter_bytes`；加 `with_seccomp_deny_nr()` + `with_seccomp_filter()` |
| `src/linux/mod.rs` | `build_bpf_filter()` 返回 `Option`；execute() 三条路径；子进程外部 BPF 安装循环 |
| `src/main.rs` | 加 `--seccomp-deny-nr` 和 `--seccomp-filter-fd` CLI flag；cmd_run 中从 fd 读原始字节 |
| `tests/seccomp_test.rs` | 适配新 API；新增 --seccomp-deny-nr 端到端测试 |
| `tests/deny_detect_test.rs` | 更新 classify_exit 富消息断言（去掉 category） |
| `docs/linux-sandbox.md` | 更新 seccomp 章节 |
| `CONTEXT.md` | 更新 Seccomp Blacklist 和 SyscallCategory 词汇 |

## 5. 测试合同

### 5.1 单元测试（seccomp.rs）

| 测试 | 验证 |
|---|---|
| `build_deny_filter_length` | n 个 nr → n+6 条指令 |
| `build_deny_filter_arch_check` | 指令 0-2 正确加载 arch 并在不匹配时 KILL |
| `build_deny_filter_jumps` | 每个 JEQ 跳转指向 die_insn (RET USER_NOTIF) |
| `install_plain_filter_smoke` | prctl 直装不崩溃（/bin/true 可执行） |
| `syscall_name_retained` | SYSCALLS 表仍可按 nr 查名 |

### 5.2 集成测试（seccomp_test.rs）

| 测试 | 验证 |
|---|---|
| `deny_nr_blocks_mount` | `--seccomp-deny-nr 165` 拦截 mount syscall → exit 126 |
| `deny_nr_multiple` | `--seccomp-deny-nr 165 --seccomp-deny-nr 97` 两个都拦 |
| `no_seccomp_args_passes_through` | 无 seccomp 参数 → mount 不被拦（exit 非 126） |
| `external_bpf_passes_through` | 测试外部 BPF 的基本功能 |
| `normal_exit_no_hang` | 无 seccomp 参数下 /bin/true 正常退出 |

### 5.3 集成测试（deny_detect_test.rs）

| 测试 | 验证 |
|---|---|
| `exit_159_with_block_returns_rich_message` | 富消息含 `syscall='mount'` + `nr=165` + `arch=...`（无 category） |
| `exit_31_seccomp_direct` | 保持不变 |
| `exit_159_seccomp_shell` | 保持不变 |

## 6. 设计决策

- **不保留默认黑名单**：用户自己决定拦什么，工具不做安全判断
- **不保留 SyscallCategory**：移除分类接口，仅保留 SYSCALLS 表用于诊断查名
- **fd 接口**：与 bwrap 一致，避免 TOCTOU 和路径歧义
- **堆叠顺序**：deny-nr 先装（NEW_LISTENER），外部 BPF 后装（prctl），内核逆序评估
