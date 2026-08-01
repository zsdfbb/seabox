# Mount Namespace + 文件系统重排 — 质量分析报告

> Review 对象：`docs/arch/mount-namespace/design.md`
> Review 日期：2026-07-28
> 范围：全量维度

---

## 各维度评分

| 维度 | 评分 | 说明 |
|------|:----:|------|
| **可行性** | 🟡 **黄** | 存在技术风险，需原型验证。详见下方 |
| **可维护性** | 🟢 **绿** | 模块边界清晰，模式与现有代码一致 |
| **可理解性** | 🟢 **绿** | 概念简洁，文档完整 |
| **性能与可靠性** | 🟡 **黄** | 性能达标，但存在降级路径和故障模式缺失 |

---

## 一、可行性分析

### 🟢 通过项

| 检查项 | 状态 | 理由 |
|--------|------|------|
| `CLONE_NEWNS` unshare | ✅ 可行 | 与 `CLONE_NEWUSER` 同体系，user ns 内授权 |
| `mount(2)` 调用的 async-signal-safe 性 | ✅ 安全 | `mount(2)` 是纯 syscall，无堆分配 |
| Raw pointer 预计算模式 | ✅ 已验证 | `NsOp` / `ExtFilterDesc` 同模式在生产中运行 |
| ADR 0003 零堆约束 | ✅ 满足 | 所有 CString 在 fork 前预分配 |
| Landlock 前置 mount | ✅ 正确 | Landlock 限制 filesystem access，不限制 mount(2) syscall 本身 |
| PID double-fork 后的 mount ns 继承 | ✅ 正确 | mount ns 通过 fork 继承，不受 PID ns 影响 |

### 🟡 需验证项

| 风险 | 影响 | 建议 |
|------|------|------|
| **user ns 内的 bind mount 权限** | 高 — 核心功能不可用 | `mount --bind` 在 user ns 内有额外限制：source 路径的挂载点必须属于创建 user ns 的用户的 mount namespace。如果 source 是宿主机的 `/usr`，在 user ns 内可能无法 bind。**建议用 `prototype` 优先验证 `--bind /usr /mnt`** |
| **user ns 内的 `MS_PRIVATE\|MS_REC`** | 中 — 传播隔离失败 | 在 user ns 内对新 mount ns 的 `/` 做 `MS_PRIVATE|MS_REC` 通常可行，但如果父 mount ns 的 `/` 已经是 slave，此操作可能失败。**方案：如果 `MS_PRIVATE` 失败，可尝试 `MS_SLAVE` 作为降级** |
| **user ns 内 tmpfs 的大小限制** | 低 — 默认 50% 物理内存 | tmpfs 默认 max size = 物理内存的 50%。大量写入 tmpfs 可能导致 OOM。**考虑增加 `--tmpfs /path:size=1G` 语法** |
| **`--bind /src /dst` 中 /dst 不存在** | 中 — 用户困惑 | 内核不允许在不存在路径上 mount。用户需要先创建目标路径。**考虑父进程自动创建 `mkdir -p` target 目录** |

### 用户 namespace 内 bind mount 的限制（需特别关注）

```
# 在 user ns 内，bind mount 的 source 必须满足：
# 1. source 路径的挂载点属于当前 user ns 的"所有者"
# 2. source 路径不可为 mount namespace 内 shared 子树的一部分

# 这可能导致以下场景失败：
unshare -U --map-root-user sh -c 'mount --bind /usr /mnt && ...'
# → mount: /mnt: 权限不够 (EPERM)
```

**缓解方案：**
1. 确保 `--bind` 的 source 路径是宿主机正常挂载点（ext4/xfs 等），不是 shared 子树
2. 如果 EPERM，降级跳过错并输出诊断信息
3. 或者父进程在 fork 前验证 source 的 mount 属主

---

## 二、可维护性分析

### 🟢 模块边界

```
config.rs (MountSpec + MountConfig)    ← 用户面，纯数据
    ↓ 父进程预编码
linux/mod.rs (prepare_mount_ops)        ← 编码 + 生命周期管理
    ↓ RawMountOp[]
linux/mount.rs (do_mounts)              ← 子进程面，纯 syscall
    ↓ 调用
child_setup.rs (enter_child)            ← 已有模块，无循环依赖
```

依赖方向是单向的：`config → mod.rs → mount.rs → child_setup.rs`。无循环依赖。

### 🟢 与现有模式的同构性

| 现有模式 | Mount 等价 | 
|---------|-----------|
| `NsOp { flag, try_mode }` | `RawMountOp { source, target, fstype, flags, data }` |
| `prepare_ruleset_fd()` | `prepare_mount_ops()` |
| `configure_loopback()` | `do_mounts()` |
| `NetworkConfig { loopback }` | `MountConfig { enabled, ops }` |
| pre_exec 中 if-check | pre_exec 中 if-check |

这种同构性降低了 reviewer 和未来维护者的认知成本。

### 🟡 需注意

| 问题 | 建议 |
|------|------|
| `MountConfig.enabled` + `ops` 两条路径启用 mount ns | 语义略微模糊：如果 `ops` 非空但 `enabled=false`，是否启用 mount ns？设计说"自动启用"。如果 `ops` 为空但 `enabled=true`，也启用。**建议统一为：mount ns 当且仅当 `enabled \|\| !ops.is_empty()`** |
| `ro_bind` 展开为 2 条 `RawMountOp` 的逻辑在父进程中 | 这增加了 `prepare_mount_ops()` 的复杂性。如果未来新增 mount 类型（如 overlay），需要确保展开逻辑的可维护性。**建议将展开逻辑集中在一处，不要分散** |
| 测试需要 root / user ns + `--unshare-user` | 与现有 net ns 测试相同的跳过模式。**可接受** |

---

## 三、可理解性分析

### 🟢 设计文档质量

- 背景完整：context.md 已经分析过 why
- 方案对比清晰：三方案 + 对比矩阵
- 决策有理由：每项决策都有"选择 + 理由"
- 边界场景覆盖：8 个场景

### 🟢 概念一致性

- `MountSpec` = 用户面 mount 描述（字符串路径）
- `RawMountOp` = 子进程面 mount 操作（raw pointer）
- 区分清晰，映射明确

### 🟡 改进点

| 问题 | 建议 |
|------|------|
| `MountSpec.fstype` 取值 "none" / "tmpfs" 的约定不够直观 | **建议用 `is_bind: bool` + `is_tmpfs: bool` 字段替代 `fstype: String`**，避免 Magic String。或至少文档中说明 fstype 取值约定 |
| do_mounts() 的 i32 返回值的含义（0=成功，非0=1-based）不够 Rusty | **建议包装为 `Result<(), usize>` 或自定义枚举**，虽然子进程不用，但父进程的测试代码可读性更好 |

---

## 四、性能与可靠性分析

### 🟢 性能模型

性能数字（来自方案 C 的 back-of-envelope）可信：
- 5 次 mount：~70μs
- 10 次 mount：~90μs
- 单次 mount(2) 约 2-5μs

与现有 pre_exec 序列的对比：
- 当前 base（无 mount）：~50μs（unshare + chdir + NO_NEW_PRIVS + landlock + seccomp）
- 新增 5 mount：+20μs（+40%）
- 在 ~70μs 的 pre_exec 总耗时中，对用户感知的影响可忽略（sub-millisecond）

### 🟡 故障模式

| 模式 | 当前处理 | 风险 |
|------|---------|------|
| mount(2) 中间失败 | _exit(127)，stderr 消息 | **中** — 前 N 个 mount 已成功，但进程直接退出。虽无泄漏（mount ns 自动清理），但已成功的 mount 未被记录，使用者无法分析"哪个 mount 成功到哪一步" |
| MS_PRIVATE 失败 | _exit(127) | **高** — 如果此步失败，后续 mount 操作可能传播回宿主。应该至少试 `MS_SLAVE` 降级 |
| user ns 内 `--bind` 的 source 不可 bind | _exit(127)，用户困惑 | **中** — 错误消息只说"mount failed"，不说明原因。考虑在父进程预检 |
| seccomp 拦截 `mount(2)` | _exit(127) | **低** — 用户自己的 seccomp 配置，应自己知道在拦什么 |
| tmpfs 用尽内存 | 被动 OOM kill | **低** — 非 mount 代码的责任，全系统 OOM 处理 |

### 🟡 降级策略

**当前设计缺少降级路径。** 对于某些场景，mount 失败不应是整个命令失败的理由。建议：

```
# 场景：用户想"尽量"隐藏 /tmp，但不强制
seabox run --try-mount --tmpfs /tmp -- ./script.sh
```

但当前设计明确不做 optional mount（D6）。这个取舍合理——保持简单，用户可以通过外部脚本自己降级。**但至少应该确保 `MS_PRIVATE|MS_REC` 的失败有降级（`MS_SLAVE`），因为这不是用户配的，是设计隐含的。**

### 🟡 资源管理

| 资源 | 管理方式 | 风险 |
|------|---------|------|
| `CString` backing store | 父进程中持有 `PreparedMountOps._cstrings` | 低 — 生命周期绑定到 `execute()` 调用 |
| `mount fd` | 无，mount(2) 不需要 fd | 无 |
| tmpfs 内存 | 内核管理，进程退出时释放 | 无 |
| bind mount 的引用计数 | 内核管理，mount ns 关闭时解除 | 无 |

无资源泄漏风险。

### 🟢 可观测性

- do_mounts() 失败后写 stderr（已有）
- mount 数量可预知（`MountConfig::ops.len()`）
- 父进程中可记录 prepare 的 mount ops 数量

---

## 五、风险排序

| 风险 | 影响 | 可能性 | 优先级 |
|------|------|--------|--------|
| user ns 内 `--bind` EPERM | 核心功能不可用 | 中 | P0 |
| `MS_PRIVATE` 失败无降级 | mount 传播回宿主 | 低 | P1 |
| target 路径不存在 | 用户困惑 | 中 | P1 |
| `--tmpfs` 无大小限制 | 隐含 OOM 风险 | 低 | P2 |
| `--unshare-mnt` + 无 user ns 时 mount 失败 | 非 root 下不可用 | 高（但非 root 是主流） | P0（文档中注明依赖） |

---

## 六、改进建议

### 🔧 易修复（实施时做）

1. **`MS_PRIVATE` 降级为 `MS_SLAVE`**：如果 `MS_PRIVATE|MS_REC` 失败，尝试 `MS_SLAVE|MS_REC`。代码改动 ≤5 行，但对正确性至关重要
2. **父进程预检 target 目录存在性**：在 `prepare_mount_ops()` 中检查 `MountSpec.target` 指向的目录是否存在。如果不存在，报错提前，不等到子进程 mount 时
3. **错误消息增加 mount 序号和类型**：失败时写 `"mount #3 (bind: /usr → /mnt) failed"`，帮助用户定位
4. **为 `mount` 测试增加 user ns 可用性探测**：复用 `namespaces::is_user_namespace_available()`

### 💬 需讨论

1. **是否自动 `mkdir -p` target 目录？** bwrap 会。好处是用户不需要自己保证路径存在。风险是 `mkdir` 在子进程中需要堆操作（`mkdir(2)` 本身是 syscall，但路径字符串处理...）。父进程 pre-check + 建议方案比自动 mkdir 更稳妥。

2. **`MountSpec.fstype` 的 Magic String 还是字段？** 当前用 `"none"` / `"tmpfs"` 区分 bind 和 tmpfs。改用 `is_bind: bool` + `is_tmpfs: bool` 更 Rusty，但父进程展开 ro_bind 时需要额外分支。可保持 fstype 方案，加文档说明。

### 🏗️ 架构级

1. **mount 数 >20 时的性能优化路线**：当前设计采用 PPM，适合典型场景（3-10 mounts）。如果未来出现大量 mount 场景（>20），可考虑 pre-mount worker 优化。当前不需要实现。
2. **`--proc /proc` 的扩展路径**：只需加 `MountSpec::proc(target)` 工厂方法 + `do_mounts` 不需要改。预留了扩展点。

---

## 七、总结

**可行，但需先验证 `--bind` 在 user ns 内的行为。** 建议实施顺序：

1. 🔴 **P0**：用 `prototype` 验证 user ns 内 `mount --bind /usr /mnt` + `mount --tmpfs /tmp` + `MS_PRIVATE` 在目标内核上的行为
2. 🔴 **P0**：文档中注明 `--bind` / `--ro-bind` 需要 `--unshare-user`（非 root 时）
3. 🟡 **P1**：实现 `MS_PRIVATE` → `MS_SLAVE` 降级
4. 🟡 **P1**：父进程预检 target 目录存在性
5. 🟢 然后按 `design.md` 的模块设计实施
