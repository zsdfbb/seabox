# ADR：Mount Namespace 集成设计方案选择

- **日期：** 2026-07-28
- **状态：** 草案
- **前置：** `docs/arch/mount-namespace/context.md` → `docs/arch/mount-namespace/design.md`

---

## 背景

seabox 当前使用 Landlock ACL 做文件系统权限控制。Landlock 控制"能读/写哪些路径"，但不能控制"能看到什么路径"。讨论确认：多 Agent 场景、工具版本隔离、ephemeral 全局安装等需求需要 mount namespace 提供的**视图隔离**能力。

## 设计方案评估

三个并行 agent 生成了三份候选方案：

| 方案 | 倾向 | 核心思路 | 代码量 |
|------|------|---------|--------|
| A | 最小复杂度 | `MountSpec` 结构体 + 父进程预展开 ro_bind | ~260 行 |
| B | 可扩展优先 | `MountOp` 枚举 + 模块化架构 + 扩展点预留 | ~450 行 |
| C | 性能优先 | PPM（Pre-Parsed Mount）+ 延迟估算 | ~300 行 |

## 决策

### D1：CLI 语法 — `--bind SRC DST` 两参

- **选择：** 两参
- **理由：** bubblewrap 兼容，路径可含空格。`--landlock path:perm` 的 colon 语法对单参数场景合理，但 mount 的 src/dst 都是路径，两参更自然

### D2：Mount 建模 — `MountSpec` 结构体

- **选择：** 结构体（非枚举）
- **理由：** 当前仅需 bind / ro-bind / tmpfs 三种类型，结构体 + flag 字段足够。枚举会增加匹配分支，对扩展性的提升在短期内无场景驱动。后续可通过 `fstype` 字段区分类型（"bind" / "tmpfs" / "proc"）

### D3：ro_bind 实现 — 父进程展开为两条 RawMountOp

- **选择：** 父进程预展开
- **理由：** 子进程的 mount 循环保持纯线性遍历，零条件分支。对子进程的零堆约束无影响（RawMountOp 数组是 POD，预分配的 CString 在父进程中持有）

### D4：`MS_PRIVATE|MS_REC` — 必须做

- **选择：** 在 mount ops 之前执行
- **理由：** 新 mount ns 的 `/` 默认从宿主传播树继承 shared 属性。不做此步则每个 mount 操作（`--tmpfs /tmp` 等）会通过挂载传播事件泄漏到宿主内核的挂载树，对宿主产生可见影响。bwrap 同样以此开头，这是正确性前提而非优化

### D5：CLONE_NEWNS 自动启用

- **选择：** mount ops 非空时自动加入 `ns_ops`
- **理由：** 用户在表达"我要 mount"时就已经明确了 mount ns 的需求。不需要额外的 `--unshare-mnt` flag。但保留 `--unshare-mnt` flag 供仅需 mount ns 隔离无 mount 操作的场景使用

### D6：不做 `--proc /proc`

- **选择：** 本次不做
- **理由：** procfs 挂载需要 `gid=5` 等选项，且暴露宿主机进程信息与当前沙箱模型无关。如果后续有需求，只需在 `MountSpec` 中加一个 `proc()` 工厂方法，不需要改子进程代码

### D7：optional mount 不做

- **选择：** 不做
- **理由：** mount 操作不应该静默跳过——如果 mount 失败，用户期望一个明确的错误。后续如果有"某些 mount 不是必需的"场景，可以加 `MountSpec::optional` 字段

### D8：子进程 mount 函数返回 bool

- **选择：** `do_mounts()` 返回成功/失败（i32 1-based index）
- **理由：** 返回失败序号比直接 `_exit` 更好——父进程（将来）可以读取 exit code 判断是哪个 mount 失败。当前简化为非零即 _exit

## 被否方案

### 方案 B 的 MountOp 枚举

被否理由：枚举带来的扩展性在当前阶段没有场景支撑。`MountSpec` 结构体的 `fstype` 字段已经能区分不同 mount 类型。后续需要扩充 mount 类型时，加一个工厂方法即可——不需要提前定义枚举变体。

### 方案 C 的 Pre-mount worker 路线

被否理由：性能分析显示在典型 mount 数量（3-10 个）下 PPM 已经是最优方案。Pre-mount worker 需要额外的 helper fork + setns，引入了进程管理复杂度，且仅在 mount 数 >20 时有微弱优势。如果未来出现大量 mount 场景，可以优化为批量 mount 或 worker 路线，但当前不需要为此增加复杂度。

### Cgroup 隔离方向

当 mount ns 集成完成后，Phase 2b 原计划中的 eBPF 网络过滤正式被 mount ns 方案替代。在可预见的未来，文件系统视图隔离（mount ns）比 IP 级网络过滤（eBPF）对 Agent 场景更有实际价值。
