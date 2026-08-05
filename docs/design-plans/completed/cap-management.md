# Capability 权限管理

> 设计时间：2026-08-04
> 状态：**待实现**
> 来源：`docs/arch/cap-management/design.md` + `docs/adr/0004-capability-management.md`（已定稿）

---

## 1. 目标

为 Linux 后端实现 capability 权限管理，bwrap flag 级兼容：

1. **默认零 cap（含 host-root）**：关闭"root 无 `--unshare-user` 时子进程保留宿主全部 caps"的安全缺口。
2. **`--cap-add` / `--cap-drop`**（含 `ALL`，可重复，按命令行顺序应用）：bwrap 兼容 pair。
3. **`--cap-inherit`**：bwrap root 语义的 opt-in 逃生门（起点继承当前进程 caps）。
4. **`--cap-add` 自动叠加 userns**：防 cap 回灌宿主命名空间。

## 2. CLI 接口

```
seabox run --cap-drop ALL -- ls                 # 收零（root 无 userns 时必用）
seabox run --cap-drop ALL --cap-add CHOWN -- ... # 只保留 CHOWN
seabox run --cap-add NET_RAW -- ...              # 自动叠加 userns，NET_RAW 只在 ns 内有效
seabox run --cap-inherit --cap-drop MKNOD -- ... # bwrap root 语义：继承后选择性收
```

- `--cap-add` / `--cap-drop`：可重复，名称或 `ALL`，按命令行顺序应用（`indices_of` 保序，仿 `collect_mount_actions`）
- `--cap-inherit`：bool，起点位图继承当前进程 effective caps（否则从空集开始）

## 3. 核心决策（ADR 0004 D1-D5）

| 决策 | 内容 |
|---|---|
| D1 | 默认零 cap（含 host-root），对齐 bwrap man 页 "By default no caps are left" |
| D2 | `--cap-add` 自动叠加 userns（root 也触发） |
| D3 | 三条 raw syscall 原语：`capset(V3)` + `prctl(PR_CAPBSET_DROP)` + `prctl(PR_CAP_AMBIENT_RAISE)`，零 libcap、零堆（ADR 0003） |
| D4 | 插入点：所有需要 cap 的 setup 之后、seccomp 之前 |
| D5 | 按需执行：非 root 零 cap 整块跳过；非 root 跳过 bounding；只遍历置位 bit |

## 4. 模块划分

| 文件 | 改动 | 职责 |
|---|---|---|
| `src/config.rs` | 改 | `Capability(u16)` + 41 ABI 常量 + `from_name`（不 import libc）；`CapOp`；`CapabilityConfig { ops, inherit_base }`；`SandboxConfig.capabilities` + `with_cap_*` 方法 |
| `src/linux/caps.rs` | **新** | `apply_caps`（child，零堆）+ `resolve_caps`（父进程）+ `read_bounding_set`（父进程） |
| `src/linux/child_setup.rs` | 改 | `enter_child` 加 `caps_requested: u64, caps_flags: u8`；landlock 后、seccomp 前插入 `apply_caps` |
| `src/linux/mod.rs` | 改 | fork 前 `resolve_caps`；`enter_child` 追加实参；`effective_user` 加 `\|\| has_cap_add` |
| `src/lib.rs` | 改 | `from_config` 的 `effective_user` 扩展；re-export `Capability`/`CapabilityConfig`/`CapOp` |
| `src/main.rs` | 改 | `--cap-add`/`--cap-drop`/`--cap-inherit` + `collect_cap_actions` 保序；三处接线 |
| `tests/capability_test.rs` | **新** | 探针 + 集成测试（首个断言 CapEff 的测试文件） |
| `examples/crate_api.rs` | 改 | 示范 `.with_cap_drop_all()` |

`effective_user` 逻辑有 **3 处副本**，cap-add 自动叠加 userns 必须三处同步扩展：
- `main.rs:573-577`（build_config，CLI 路径）
- `lib.rs:404`（from_config，crate API 路径）
- `linux/mod.rs:156-160`（execute()，最终安全网）

## 5. 数据流与插入点

```
父进程 execute()（fork 前，堆可用）:
  resolve_caps(cfg, is_root, userns_active)
    base = inherit_base ? capget(effective) : 0
    按序 apply ops → requested (u64)
    natural = (userns_active || is_root) ? FULL : 0
    flags: requested≠natural → NEED_CAPSET
           requested≠0 → NEED_AMBIENT
           !userns_active && is_root && requested≠FULL → NEED_BOUNDING
  产出 { requested: u64, flags: u8 } 按值传 enter_child

子进程 enter_child（零堆）:
  unshare → mounts → pid reaper → chdir → no_new_privs → uid_map
  → loopback → sethostname → landlock_restrict_self
  → ★ apply_caps(requested, flags)          [插入点：landlock 后、seccomp 前]
      NEED_BOUNDING: capset(requested|SETPCAP) → 逐 PR_CAPBSET_DROP(cap∉requested)
      NEED_CAPSET:   capset(e=p=i=requested)
      NEED_AMBIENT:  逐 PR_CAP_AMBIENT_RAISE(cap∈requested)
  → seccomp USER_NOTIF → ext filters → execve
```

## 6. 测试合同（Test Contract）

### 探针（`OnceLock` 缓存，失败 skip 而非 fail）

| # | 探针 | 判定 | 失败处理 |
|---|---|---|---|
| P1 (F2) | userns 内 `capset` 清零后尝试重提应 EPERM | 确认"零 cap + 非 root 不可重提"机制生效 | skip |
| P2 (F5) | 写非零 uid_map 后 permitted 是否保留 | 决定非 root `--cap-add` 是否可测 | 不成立 → 相关测试 skip |

### 集成测试（断言 CapEff/CapBnd，首个解析 `/proc/self/status` 的测试文件）

| # | 场景 | 断言 |
|---|---|---|
| T1 | root 无 userns 默认收零 | `CapEff=0x0`（`geteuid()!=0` 时 skip） |
| T2 | `--cap-drop ALL --cap-add CHOWN` | 终态只含 CHOWN（`CapEff` 只 bit 0） |
| T3 | `--uid 0 --cap-add ALL` | ns-root 全量 ns caps（容器式能力） |
| T4 | 非 root 默认路径 | `CapEff=0`，且无额外 cap syscall（可选 strace） |
| T5 | 未知 cap 名 | CLI 报错（exit 非零） |
| T6 | `--cap-add` 自动叠加 userns | 非 root 下无 `--unshare-user` 也进入 userns（uid 映射生效） |

### 验证命令

- `cargo test`（全量，含新 `capability_test.rs`）
- `cargo clippy --all-targets -- -D warnings`
- `cargo fmt --check`
- 手动（unsandboxed）：root 无 userns 收零后 `CapEff=0`；`--cap-drop ALL --cap-add CHOWN` 终态只含 CHOWN
