# Capability 权限管理 — 设计方案

> 设计时间：2026-08-02
> 状态：**草案**
> 前置文档：`context.md`（本文档 §1 内含调研摘要）
> 目标文件：`docs/adr/0004-capability-management.md`

---

## 1. 调研摘要

### 1.1 动机与安全缺口

seabox 现有安全边界（Landlock + seccomp + namespaces）对 **capability 门控的 syscall** 基本不设防：

| 调用方式 | 子进程 cap 状态 | 宿主是否安全 |
|---|---|---|
| **root 无 `--unshare-user`**（如 `seabox run --landlock '/:ro' -- …`） | 保留**宿主全部 caps** | ❌ ptrace/setns/mount/mknod 全放行 |
| root + `--unshare-user`（默认 `0→0` 映射） | ns 内 root，全量 ns-scoped caps | ✅ ns-scoping 保护宿主，但进程是"受限 root" |
| 非 root + `--unshare-user`（默认同 uid 映射） | exec 后 ns 内零 cap（实测 `CapEff=0`） | ✅ 理想状态 |

**首要缺口**：root 无 userns 时，子进程保留宿主 caps。这是 `--cap-drop ALL` 存在的根本理由。

### 1.2 bubblewrap 的实现（本地源码 `/home/zs/OpenSrc/bubblewrap/bubblewrap.c`，已通读）

- 数据模型：全局 `requested_caps[2]`（两个 u32，V3 布局），`--cap-add`/`--cap-drop` 按**命令行顺序**对位图累加/清除，`ALL` 特判。
- 默认值来源 `acquire_privs()`（解析参数前）：root → `capget()` 继承当前全部 effective；非 root → `{0,0}`；setuid/setcap 二进制 → `die`。
- 三条 raw syscall 原语（不依赖 libcap）：
  1. `capset(V3)` 收窄 effective/permitted/inheritable = requested
  2. `prctl(PR_CAPBSET_DROP, cap)` 逐位收缩 bounding set（`0..CAP_LAST_CAP`，EINVAL/EPERM 静默忽略）
  3. `prctl(PR_CAP_AMBIENT_RAISE, cap)` exec 前抬升 ambient —— **非 root 进程 exec 后保留 cap 的唯一机制**
- 时序：`PR_SET_NO_NEW_PRIVS`（最早）→ `unshare(CLONE_NEWUSER)` → `write_uid_gid_map` → 收 bounding → capset → ambient → seccomp → execve。
- 优化：root 且未传 cap flag 时**跳过 capset**（systemd-nspawn 会给子进程装拒绝 `capset` 的 seccomp 策略）。
- man 页："By default no caps are left in the sandboxed process"；`--cap-add`/`--cap-drop` "when running as privileged user"。
- **代码行为与 man 页语义不一致**：bwrap 对 root 默认保留全部 caps（代码），man 页却写"默认无 cap"。本设计对齐 **man 页语义**。

### 1.3 本环境实测（探针复跑，`/tmp/cap_probe*.py`）

| # | 实测结果 | 验证状态 |
|---|---|---|
| F1 | 非 root `unshare(CLONE_NEWUSER)` 后 creator 持 ns 内全量 caps，`inheritable=0` | ✅ 多次复现 |
| F2 | 非 root creator `capset` 清零后**无法重提 cap**（EPERM），全 bounding 无害 | ✅ cap_probe2 |
| F3 | `PR_CAP_AMBIENT_RAISE` 需要 cap 同时在 permitted **和 inheritable**；否则 EPERM | ✅ ambient_probe |
| F4 | 写 `/proc/self/uid_map` 在此环境**恒 EPERM**（root 映射、自映射均失败） | ✅ 复现（环境限制） |
| F5 | 写 map 后 permitted 是否保留（决定非 root `--cap-add` 可行性） | ❌ **未能实测**（F4 阻塞） |

> **关键未决点（F5）**：bwrap 的 `--cap-add` 之所以能跨 exec 存活，依赖"写非零 uid_map 后、exec 前 permitted 仍保留"（capset 才能收窄到 requested + ambient 抬升）。util-linux `--keep-caps` 文档声称 map 写入时 **effective** 会被清；permitted 是否保留各 agent 探针均未能验证。**本设计将非 root 默认路径的 `--cap-add` 视为 best-effort，可靠性由探针测试兜底，文档明示"仅在 `--uid 0` / root / file-cap 场景可靠"。**

---

## 2. 三方案对比

三份候选方案由三个独立架构 agent 生成，分别代表**最小复杂度**（A）、**可扩展优先**（B）、**性能/资源优先**（C）。

### 2.1 对比矩阵

| 维度 | 方案 A：最小复杂度 | 方案 B：可扩展优先 | 方案 C：性能优先 |
|------|:---:|:---:|:---:|
| **CLI** | `--cap-add` / `--cap-drop` | 同 + `--cap-inherit` | `--cap-add` / `--cap-drop` |
| **默认起点** | root 无 userns 全丢；非 root 不干预 | 全量默认零 cap + `--cap-inherit` opt-in | 全量默认零 cap |
| **顺序语义** | 位图按序累加（弱） | `indices_of` 保序（忠实 bwrap） | 位图 add/drop 掩码（弱） |
| **建模** | `Option<u64>` 单字段 | `Capability(u16)` + `Vec<CapOp>` | `CapsConfig { add: u64, drop: u64 }` |
| **cap-add 限定 userns** | 报错要求 | 自动叠加 userns | 未明确 |
| **三条原语** | ✅ | ✅ | ✅ |
| **bounding 跳过（非 root）** | ❌ 恒 41 循环 | ❌ 未优化 | ✅ 跳过（F2 依据） |
| **热路径 syscall（非 root 默认）** | 0 | 0 | 0 |
| **root 默认收零 syscall** | ~42 | ~42 | ~42 |
| **代码量** | ~350 | ~500 | ~500 |
| **bwrap 兼容度** | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| **安全默认（root 收零）** | ✅ | ✅ | ✅ |

### 2.2 关键分歧点

1. **默认起点**：三者都同意 root 默认收零（安全修复本体），分歧在 B 是否提供 `--cap-inherit` 逃生门。
2. **cap-add 与 userns 关系**：A 直接报错，B 自动叠加 userns（与现有 pid/net 自动叠加模式一致），C 未明确 —— 这是安全语义的分水岭（防 host-root + cap-add 把 cap 回灌宿主 ns）。
3. **bounding 循环**：C 依 F2 实测（非 root 清零后不可重提）跳过非 root 的 bounding 收缩，A/B 无此优化。三者在 root 路径都需 ~41 次 `PR_CAPBSET_DROP`（内核无批量原语，这是物理下限）。
4. **插入点**：A/B 放在 loopback/hostname/landlock 之后、seccomp 之前（不破坏 `--allow-network`/`--hostname`/`--bind`）；C 放在 uid_map 后、loopback 前（会与 loopback 抢 CAP_NET_ADMIN，属设计缺陷，除非 loopback 配置前移）。

### 2.3 性能估算（back-of-envelope）

模型：prctl/capset ≈ 1μs/次；fork ≈ 50-100μs；seabox 基线 fork→exec ≈ 150-300μs。

| 调用 | 额外 syscall | 延迟增量 |
|---|---|---|
| 非 root 默认（Agent 热路径，无 cap flag） | **0**（整块跳过） | +0μs |
| host-root 默认（收零） | ~42（1 capset + 41 bounding） | +40-80μs（仅此罕见分支） |
| 非 root `--uid 0` | 0（natural==requested==full） | +0μs |
| 非 root `--cap-add X` | ≤2（capset + ambient，best-effort） | +2μs |

---

## 3. 推荐方案（融合 A/B/C）

以 **B 的可扩展结构** 为骨架，采纳 **C 的性能优化**（F2 依据），去除 **A 指出的不必要复杂度**。

### 3.1 核心决策（详见 ADR 0004）

| 决策 | 内容 |
|---|---|
| D1 | **默认零 cap（含 host-root）**，对齐 bwrap man 页语义；提供 `--cap-inherit` 作为 bwrap root 语义 opt-in 逃生门 |
| D2 | **cap-add 限定 userns**：`--cap-add` 自动叠加 userns（root 与非 root 均触发），防 cap 回灌宿主命名空间 |
| D3 | 三条原语齐备：`capset(V3)` + `PR_CAPBSET_DROP` + `PR_CAP_AMBIENT_RAISE`，全部 raw syscall、零堆、async-signal-safe |
| D4 | 插入点：**所有需要 cap 的 setup（mount/loopback/hostname）之后、seccomp 之前** |
| D5 | **按需执行**：整块无操作时跳过；非 root 终态零 cap 时跳过 bounding 收缩（F2）；只遍历置位 bit |

### 3.2 模块划分

| 文件 | 改动 | 职责 |
|---|---|---|
| `src/config.rs` | 增 | `Capability(u16)` 新类型 + 41 个 ABI 常量表 + `from_name`；`CapOp` 枚举（Add/Drop/AddAll/DropAll）；`CapabilityConfig { ops, inherit_base }`；`SandboxConfig.capabilities` 字段；`with_cap_add/drop/add_all/drop_all/inherit`。**本层不 import libc**（cap 编号是稳定 ABI 常量，类比现有 `MS_BIND`） |
| `src/linux/caps.rs` | **新增** | 三条原语 raw 封装 + `apply_caps`（child，零堆）+ `resolve_caps`（父进程，解析 ops→位图+flags，含 skip 决策）+ `read_bounding_set`（父进程） |
| `src/linux/child_setup.rs` | 增 | `enter_child` 增加 `caps_requested: u64, caps_flags: u8` 两参；在 landlock 之后、seccomp 之前插入 `apply_caps` |
| `src/linux/mod.rs` | 增 | `execute()` 中 fork 前调 `resolve_caps`；`effective_user` 扩展 `\|\| has_cap_add`（cap-add 自动叠加 userns，root 也触发） |
| `src/main.rs` | 增 | `--cap-add` / `--cap-drop` / `--cap-inherit`；`get_matches` + `indices_of` 保序合并 |
| `src/lib.rs` | 增 | `from_config` 的 effective_user 扩展；re-export `CapabilityConfig`/`CapOp`/`Capability`。`SandboxImpl` trait 零改动 |
| `tests/capability_test.rs` | **新增** | 探针 + 集成测试 |
| `README.md` / `docs/linux-sandbox.md` | 增 | cap 语义 + 与 bwrap 的偏差说明 |

### 3.3 关键数据流

**父进程（fork 前，堆可用）**：
1. CLI/`with_*` 累积 `CapabilityConfig.ops`（保序）。
2. `resolve_caps(cfg, is_root, userns_active)`：
   - `base` = `inherit_base ? capget(当前 effective) : 0`
   - 按序 apply ops → `requested`（u64）
   - `natural` = (userns_active ∥ is_root) ? FULL : 0
   - flags：`requested != natural → NEED_CAPSET`；`requested != 0 → NEED_AMBIENT`；`!userns_active && is_root && requested != FULL → NEED_BOUNDING`
3. 产出 POD `ResolvedCaps { requested: u64, flags: u8 }`，按值传入 `enter_child`。

**子进程（enter_child 插入，零堆）**：
```
unshare → mounts → pid reaper → chdir
→ prctl(PR_SET_NO_NEW_PRIVS)
→ write uid_map/gid_map
→ loopback / sethostname / landlock_restrict_self      [需要 cap 的 setup 全部在此之前]
→ ★ apply_caps(requested, flags)                         [新增]
     NEED_BOUNDING: capset(requested|SETPCAP) → 逐 PR_CAPBSET_DROP(cap ∉ requested)
     NEED_CAPSET:   capset(e=p=i=requested)（V3 双字）
     NEED_AMBIENT:  逐 PR_CAP_AMBIENT_RAISE(cap ∈ requested)
→ seccomp USER_NOTIF + sendmsg(SCM_RIGHTS)
→ ext filters
→ execve
```

### 3.4 核心接口

```rust
// CLI（main.rs）
#[arg(long, value_name = "CAP")] cap_add: Vec<String>,    // 可重复，可 ALL，按序应用
#[arg(long, value_name = "CAP")] cap_drop: Vec<String>,   // 可重复，可 ALL，按序应用
#[arg(long)] cap_inherit: bool,                            // bwrap root 语义 opt-in

// config.rs
pub struct Capability(u16);                              // CAP_* 稳定 ABI 编号
pub enum CapOp { Add(Capability), Drop(Capability), AddAll, DropAll }
pub struct CapabilityConfig { pub ops: Vec<CapOp>, pub inherit_base: bool }

impl SandboxConfig {
    pub fn with_cap_add(self, name: &str) -> anyhow::Result<Self>;      // --cap-add
    pub fn with_cap_drop(self, name: &str) -> anyhow::Result<Self>;     // --cap-drop
    pub fn with_cap_add_all(self) -> Self;                              // --cap-add ALL
    pub fn with_cap_drop_all(self) -> Self;                             // --cap-drop ALL
    pub fn with_cap_inherit(self, inherit: bool) -> Self;               // --cap-inherit
}

// linux/caps.rs（child，零堆）
pub unsafe fn apply_caps(requested: u64, flags: u8);  // 失败 _exit(1)；EPERM best-effort
```

### 3.5 测试策略

- `tests/capability_test.rs`，探针 `OnceLock` 缓存。
- **探针 1（F2 依据）**：userns 内 `capset` 清零 → 尝试重提应 EPERM → 确认"零 cap + 非 root 不可重提"成立，机制生效。
- **探针 2（F5 未决点）**：探测"写非零 uid_map 后 permitted 是否保留"；不成立时非 root `--cap-add` 集成测试 **skip**（不是 fail），文档明示该限制。
- 集成测试：root 无 userns 收零后 `CapEff=0`（`geteuid()!=0` 时 skip）；`--cap-drop ALL --cap-add CHOWN` 终态只含 CHOWN；`--uid 0 --cap-add ALL` ns-root 容器式能力。
- 热路径回归：非 root 默认路径 `strace -c` 断言零额外 cap syscall（可选）。

### 3.6 风险与未决

- **R1（行为变更）**：root 默认从"保留全 caps"变"零 cap"。属安全目标本意；`--cap-inherit`/`--cap-add ALL` 是逃生门。现有测试只断言 `id -u` 不断言 CapEff，无需改旧测试。
- **R2（F5 未验证）**：非 root `--cap-add` 可靠性依赖内核行为，本环境无法实测。探针 2 兜底；文档明示仅在 `--uid 0`/root/file-cap 场景可靠。
- **R3（bounding 仅 host-root 生效）**：`PR_CAPBSET_DROP` 在 userns 内需 init-ns 的 CAP_SETPCAP，ns 内恒 EPERM → 对 ns-root 是 no-op。可接受：ns-scoping 已隔离宿主，且 F2 保证零 cap + 非 root 不可重提。
- **R4（loopback 既有 bug）**：`configure_loopback` 在 uid_map 写后执行，非 root 下无 CAP_NET_ADMIN 静默失败（N22 靠新内核自动配 lo 才过）。与 cap 管理正交，建议单独修复（loopback 配置前移到 uid_map 之前）。本设计插入点在其后，不受影响。
- **R5（systemd-nspawn 类 seccomp 拒 capset）**：外部 filter 若拒绝 `capset` 会误杀 root 收零路径。bwrap 有 skip 优化，本设计以 `requested == natural` 泛化之。

---

## 4. 未选方案及否决理由

| 方案 | 否决理由 |
|---|---|
| 仅 `--cap-drop`（不含 add） | 能关闭安全缺口，但违背 CLAUDE.md 定位表"bwrap flag 级兼容"承诺；`--cap-drop ALL --cap-add CHOWN` 是 bwrap 文档化核心用法，drop-only 无法表达；容器式 `--uid 0 --cap-add ALL` 无法表达 |
| root 无 userns 自动叠加 userns（代替 cap-drop） | 技术上能封住泄漏，但把 root 整体丢进 userns（mount 可见性/设备访问/uid 语义/proc 权限全变）是远超 cap 的破坏性变更；cap-drop 是外科手术式修复 |
| cap-add 要求 `--unshare-user` 否则报错（方案 A 立场） | 破坏本仓已有的 pid/net 自动叠加 userns 模式；自动叠加更符合"配置一次、默认受限"理念 |
| `capset-to-zero + seccomp 黑名单 capset`（约 2 syscall 替代 bounding 41 次） | 子进程内任何合法 capset 都被 EPERM（行为变更），安全边界从 capability 泄漏进 seccomp；仅作文档化可选杠杆 |

---

## 5. 落地清单（估 ~500 行 + 测试）

1. `config.rs`：`Capability` 表 + `CapOp` + `CapabilityConfig` + `with_*`（~100 行）
2. `linux/caps.rs`：原语 + `resolve_caps` + `apply_caps` + `read_bounding_set`（~180 行）
3. `child_setup.rs` / `linux/mod.rs` / `lib.rs`：接线 + effective_user 扩展（~50 行）
4. `main.rs`：flags + `indices_of` 保序（~60 行）
5. `tests/capability_test.rs`：探针 + 集成（~200 行）
6. 文档：README / linux-sandbox.md / ADR
