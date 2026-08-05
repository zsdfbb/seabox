# Capability 权限管理

> 状态：**已实现**
> 日期：2026-08-05
> 来源：`docs/design-plans/cap-management.md` + `docs/adr/0004-capability-management.md` + `docs/arch/cap-management/design.md`
> 模块：`src/config.rs` / `src/linux/caps.rs` / `src/linux/child_setup.rs` / `src/linux/mod.rs` / `src/lib.rs` / `src/main.rs`
> 测试：`tests/capability_test.rs`

---

## 1. 目标（D1-D5）

为 Linux 后端实现 capability 权限管理，bwrap flag 级兼容：

| # | 目标 |
|---|---|
| D1 | **默认零 cap（含 host-root）**：关闭"root 无 `--unshare-user` 时子进程保留宿主全部 caps"的安全缺口 |
| D2 | **`--cap-add` 自动叠加 userns**（root 与非 root 均触发）：防 cap 回灌宿主命名空间 |
| D3 | **三条 raw syscall 原语**：`capset(V3)` + `prctl(PR_CAPBSET_DROP)` + `prctl(PR_CAP_AMBIENT_RAISE)`，零 libcap、零堆（ADR 0003） |
| D4 | **插入点**：所有需要 cap 的 setup（unshare/mount/loopback/sethostname/landlock）之后、seccomp 之前 |
| D5 | **按需执行**：非 root 零 cap 整块跳过；非 root 跳过 bounding；只遍历置位 bit；cap 名→编号解析在父进程 fork 前完成 |

`--cap-inherit` 作为 D1 的 bwrap root 语义 opt-in 逃生门：起点位图继承当前进程 effective caps，否则从空集开始。

## 2. 实现结果

### 2.1 CLI 与 crate API

- `--cap-add <CAP>` / `--cap-drop <CAP>`：可重复，可 `ALL`（大小写不敏感），**按命令行顺序应用**。
  `collect_cap_actions`（`src/main.rs`）用 `matches.indices_of` 恢复 clap derive 丢失的跨 flag 全局顺序（仿 `collect_mount_actions`），排序后交给 `with_cap_add` / `with_cap_drop` / `with_cap_add_all` / `with_cap_drop_all`。
- `--cap-inherit`：bool，`config.with_cap_inherit(true)`，起点位图 = `capget(effective)`。
- crate API：`SandboxConfig::with_cap_add` / `with_cap_drop`（返回 `anyhow::Result<Self>`，未知 cap 名 `bail!`）、`with_cap_add_all` / `with_cap_drop_all` / `with_cap_inherit`（返回 `Self`）。
- `Capability(u16)` 新类型：41 个 ABI 常量（`CHOWN=0` … `CHECKPOINT_RESTORE=40`，来源 `uapi/linux/capability.h`），`from_name` 接受 `CHOWN` / `cap_chown` / `cap.CHOWN` 等变体，config 层**不依赖 libc**。

### 2.2 三条原语（`src/linux/caps.rs`）

- `apply_caps(requested, flags)`：fork 后、exec 前，零堆、async-signal-safe（ADR 0003）。按序执行：
  1. **bounding**（`CAP_F_NEED_BOUNDING`）：先 `capset` 临时保留 `CAP_SETPCAP`，再对不在 `requested` 里的 cap 逐个 `PR_CAPBSET_DROP`（EINVAL/EPERM 忽略，bwrap 语义）。
  2. **capset**（`CAP_F_NEED_CAPSET`）：`capset(V3)` 把 effective/permitted/inheritable 全部设为 `requested`（失败非 EPERM → `_exit(1)`）。
  3. **ambient**（`CAP_F_NEED_AMBIENT`）：对每个 `requested` 中的 cap `PR_CAP_AMBIENT_RAISE`（EPERM 忽略）。
- `resolve_caps(cfg, is_root, userns_active, ns_root)`：父进程 fork 前解析，纯逻辑可单测（产出 `{requested, flags}`）。
- `current_effective()` / `read_bounding_set()`：父进程侧状态读取（capget / `/proc/self/status` 的 `CapBnd` 行）。

### 2.3 effective_user 三处副本同步扩展

`effective_user`（是否需要 userns）有 3 处副本，cap-add 自动叠加 userns 必须三处同步扩展，均已落地：

| 文件 | 位置 | 扩展 |
|---|---|---|
| `src/main.rs` | `build_config` | `need_user_for_cap_add = !cap_add.is_empty()` → `effective_user` |
| `src/lib.rs` | `from_config` | `\|\| config.capabilities.has_add()` |
| `src/linux/mod.rs` | `execute()`（最终安全网） | `\|\| has_cap_add(&ops)`（仅认 `Add(_) \| AddAll`） |

`linux/mod.rs` 的 `execute()` 是 crate API 与 CLI 两条路径的共同安全网，保证无论从哪条路径进入都正确叠加 userns。

### 2.4 插入点

`child_setup::enter_child` 的步骤 9（landlock 步骤 8 之后、seccomp 步骤 10 之前）插入 `apply_caps`（`caps_flags != 0` 才进）。模块 doc 步骤清单同步更新为 12 步，capability 收窄排在 seccomp 安装之前。

### 2.5 Review 修复的关键 bug（三处）

实现经历 3 个 review 轮次，修复的关键 bug 均有回归测试：

1. **Bug 1 — `has_cap_add` 只认 Add/AddAll**：`--cap-drop ALL --cap-add CHOWN` 这类"先收零再加"的组合，若按 `!ops.is_empty()` 判定则 `--cap-drop` 单独使用也会错误叠加 userns。改为仅 `CapOp::Add(_) | CapOp::AddAll` 触发。回归测试：`linux/mod.rs::tests::has_cap_add_only_for_add_ops`。
2. **Bug 2 — `NEED_AMBIENT` 强制连带 `NEED_CAPSET`**：`PR_CAP_AMBIENT_RAISE`（F3）要求 cap 同时在 permitted 与 inheritable，而只有 capset 会填 inheritable。非 root + userns + `--cap-add ALL` 时 `requested == natural`、capset 原本不触发 → ambient 全 EPERM-ignored → exec 后丢光 caps。修复：ambient 必然连带 capset。回归测试：`caps::tests::non_root_userns_cap_add_all_forces_capset`。
3. **Bug 3 — `ns_root` 按 sandbox uid 判定**：决定跨 exec 是否需 ambient 的 `ns_root` 必须用 sandbox uid（`ns.uid.unwrap_or(real_uid) == 0`），而不是宿主 euid。host-root 显式 `--uid <非0>` 时子进程在 ns 内是非 root，宿主 root 状态不改变这一点（此时必须走 ambient 保留 cap）。`is_root` 只表示宿主 euid，不能单独用于判定 ns 内 uid。见 `ns_root_active` 与 `resolve_caps` 调用处注释。

## 3. 实测结论（关键）

本环境：非 root（uid 1000），内核 **7.0.0-28-generic**。以下均手动实证：

| 场景 | CapEff | 说明 |
|---|---|---|
| `--unshare-user --cap-add CHOWN` | `0x1` | **F5 不确定性已解决**：内核 7.0 上非 root `--cap-add` **生效**（写非零 uid_map 后 permitted 保留）。原设计"best-effort + skip"策略在本内核上**无需触发 skip** |
| `--unshare-user --uid 0 --cap-add ALL` | `0x1ffffffffff` | 41 位全置，ns-root 容器式能力 |
| `--unshare-user --cap-drop ALL --cap-add CHOWN` | `0x1` | 只含 CHOWN（bit0） |
| `--unshare-user`（非 root 默认） | `0x0` | 默认零 cap |
| `--cap-add CHOWN`（无 `--unshare-user`） | 自动叠加 userns | host `user:[4026531837]` → sandbox `user:[4026533617]`（inode 变化验证 D2） |

## 4. 测试

`tests/capability_test.rs`（首个断言 `/proc/self/status` 的 CapEff/CapBnd 的测试文件）：

| # | 场景 | 结果 |
|---|---|---|
| P1 探针（F2） | 默认 userns 下 CapEff=0 | 通过 |
| P2 探针（F5） | 非 root `--cap-add CHOWN` 生效 | 通过（本内核） |
| T1 | root 无 userns 默认收零 `CapEff=0` | 非 root 环境 **skip** |
| T2 | `--cap-drop ALL --cap-add CHOWN` → `CapEff=0x1` | 通过 |
| T3 | `--uid 0 --cap-add ALL` → ns-root 全量 | 通过 |
| T4 | 非 root 默认 → `CapEff=0` | 通过 |
| T5 | 未知 cap 名 → CLI 报错（exit 非零） | 通过 |
| T6 | `--cap-add` 自动叠加 userns | 通过 |

探针失败时相关测试 **skip 而非 fail**（P1/P2 `OnceLock` 缓存）。`resolve_caps` 10 个纯逻辑单测覆盖各 flags 判定场景。

全量 `cargo test` 通过（64 lib + 10 main + 6 capability + 24 landlock + 21 namespace + 23 seccomp + 其余），既有测试无回归。

## 5. 遗留

- **T1（root 无 userns 收零）**：依赖 `geteuid()==0`，仅在 root 环境可实证；本环境（非 root）自动 skip。
- **`--cap-inherit` 端到端**：未做集成单测（`resolve_caps` 单测 `inherit_base_uses_current_effective` 覆盖起点继承逻辑）。
- **R3 bounding 在 userns 内 no-op**（ADR 0004 已知）：`PR_CAPBSET_DROP` 需 init-ns 的 `CAP_SETPCAP`，ns 内恒 EPERM。对 ns-root 无收紧效果，可接受（ns-scoping 已隔离宿主）。

## 6. 验证命令

```bash
cargo test                    # 全量
cargo test --test capability_test   # capability 集成测试
cargo test --lib caps         # resolve_caps 纯逻辑单测
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```
