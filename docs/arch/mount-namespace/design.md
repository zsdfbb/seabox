# Mount Namespace + 文件系统重排 — 设计方案

> 设计时间：2026-07-28
> 状态：**草案**
> 前置文档：`context.md`

---

## 1. 调研摘要

### bubblewrap 的 mount 实现

bwrap 的子进程序列（`network.c` + `bubblewrap.c`）：

```
fork() → unshare(CLONE_NEWNS)
      → mount(NULL, "/", NULL, MS_PRIVATE|MS_REC, NULL)   // 断开传播
      → 遍历用户请求的 mount 操作（tmpfs / bind / proc / dev）
      → chdir → execve
```

关键点：
- `MS_PRIVATE|MS_REC` 是将新 mount ns 的 `/` 从宿主传播树中断开的前提，**不可省略**
- 递归 bind mount（`MS_BIND | MS_REC`）是默认行为
- ro-bind 分两步：先 bind，再 `MS_REMOUNT|MS_BIND|MS_RDONLY|MS_REC`
- `--proc /proc`、`--dev /dev` 通过 `mount -t proc` / `mount -t devtmpfs` 实现

### seabox 的约束

- 子进程零堆操作（ADR 0003）→ 所有 mount 参数需在 fork 前预计算为 raw pointer
- `mount(2)` 是纯 syscall，在子进程中调用无堆分配问题 → 安全
- user ns 内 `CLONE_NEWNS` + `mount(2)` 可用（内核 3.8+，需要 user ns 提供 CAP_SYS_ADMIN）
- 不支持 `--dev /dev`（user ns 内无 `mknod` 权限）
- `--proc /proc` 可支持（`mount -t proc` 不需要特殊权限）

---

## 2. 三方案对比

三份候选方案由三个独立的架构 agent 生成，分别代表**最小复杂度**、**可扩展优先**、**性能优先**三种设计哲学。

### 对比矩阵

| 维度 | 方案 A：最小复杂度 | 方案 B：可扩展优先 | 方案 C：性能优先 |
|------|:---:|:---:|:---:|
| **CLI 语法** | `--bind SRC:DST`（colon） | `--bind SRC DST`（两参） | `--bind SRC DST`（两参） |
| **mount 建模** | `MountSpec` 结构体 | `MountOp` 枚举 | `MountSpec` 结构体 |
| **ro_bind 实现** | 父进程拆两条 op | 两次 mount 调用 | 合并到 flags |
| `MS_PRIVATE\|MS_REC` | ❌ 未处理 | ✅ 显式 | ❌ 未处理 |
| `--proc /proc` | ❌ 不做 | ✅ 枚举变体 | ✅ `--proc` flag |
| **optional mount** | ❌ | ✅ `optional: i32` | ❌ |
| **Crate API 行数** | ~260 | ~450 | ~300 |
| **child 循环行数** | 6 | 10 | 8 |
| **性能（5 mounts）** | ~70μs | ~72μs | ~70μs |
| **bwrap 兼容度** | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| **未来扩展性** | ⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ |

### 性能分析（来自方案 C）

| mount 数 | 方案 A/B（PPM） | Pre-mount worker |
|----------|:---:|:---:|
| 0 | 50μs (base) | 50μs |
| 3 | 62μs | 88μs |
| 5 | 70μs | 100μs |
| 10 | 90μs | 115μs |
| 20 | 130μs | 145μs |
| 50 | 250μs | 225μs |

PPM（Pre-Parsed Mount）在 mount 数 < 20 时最优。典型场景（3-10 mounts）PPM 比 pre-mount worker 快 15-30%。

---

## 3. 推荐方案：混合 A→B（最小复杂度 + 关键正确性保证）

### 核心决策

| # | 决策 | 选择 | 理由 |
|---|---|---|---|
| D1 | CLI 语法 | **`--bind SRC DST` 两参** | bwrap 兼容，路径可含空格 |
| D2 | mount 建模 | **`MountSpec` 结构体（非枚举）** | 够用，~260 行 |
| D3 | ro_bind 实现 | **父进程展开为两条 RawMountOp** | child 零额外逻辑 |
| D4 | `MS_PRIVATE\|MS_REC` | **必须做** | 否则 mount 传播回宿主 |
| D5 | `--proc /proc` | **暂不做** | 后续可加，不破坏兼容性 |
| D6 | optional mount | **不做** | 允许失败->不知哪里出问题 |
| D7 | `CLONE_NEWNS` 启用 | **mount ops 非空时自动加入 ns_ops** | 用户不需要记 `--unshare-mnt` |
| D8 | `--unshare-mnt` flag | **新增**（与 mount ops 独立） | 仅需隔离 mount ns 无 mount 时有用 |
| D9 | child mount 函数 | **返回成功/失败 bool** | 失败时 stderr 后 _exit(127) |

### 语义表

```
# mount ns 隔离（无额外 mount）
seabox run --unshare-mnt -- ./script.sh

# 隐式 mount ns（mount 操作自动启用）
seabox run --bind /opt/node18/usr /usr -- node --version

# 只读 bind + tmpfs
seabox run \
  --ro-bind /images/tools /usr \
  --tmpfs /tmp \
  -- cargo build

# 组合 Landlock（权限）+ mount ns（视图）
seabox run \
  --unshare-mnt \
  --tmpfs /tmp --tmpfs /var --tmpfs /etc \
  --landlock /project:rw \
  -- ./script.sh
```

### flag 冲突解析

| flags | mount ns? | mount 操作？ | 说明 |
|-------|-----------|-------------|------|
| (无) | 否 | 无 | 当前行为 |
| `--unshare-mnt` | 是 | 无 | 仅隔离 mount ns |
| `--bind /src /dst` | **是**（auto） | 是 | 自动 implicit |
| `--ro-bind /src /dst` | **是**（auto） | 是 | 自动 implicit |
| `--tmpfs /tmp` | **是**（auto） | 是 | 自动 implicit |
| `--unshare-all` | 是 | 无 | 包括 CLONE_NEWNS |
| `--unshare-mnt --share-net` | 是 | 无 | mount + 网络独立 |

---

## 4. 模块设计

```
src/linux/
├── mod.rs            ← +prepare_mount_ops()、+mount 参数传 child
├── child_setup.rs    ← +RawMountOp POD、+do_mounts() 调用
├── mount.rs          ← [NEW] do_mounts() + MountOp POD + 可用性探测
├── ...
src/config.rs         ← +MountConfig + MountSpec + with_* 方法
src/main.rs           ← +--unshare-mnt、--bind、--ro-bind、--tmpfs
tests/mount_test.rs   ← [NEW] 集成测试
```

### MountConfig（config.rs）

```rust
/// 单条 mount 操作。
#[derive(Debug, Clone)]
pub struct MountSpec {
    /// 源路径（tmpfs 时为 None）。
    pub source: Option<String>,
    /// 挂载目标路径。
    pub target: String,
    /// 文件系统类型（"none" = bind, "tmpfs" = tmpfs）。
    pub fstype: String,
    /// mount(2) flags（MS_BIND, MS_REC, MS_RDONLY, MS_NOSUID 等）。
    pub flags: u64,
    /// 可选 data 字符串（如 "size=1G"）。
    pub data: Option<String>,
}

/// Mount 配置。
#[derive(Debug, Clone, Default)]
pub struct MountConfig {
    /// 明确要求 unshare mount ns（当 ops 为空时仍可设置此标志）。
    pub enabled: bool,
    /// mount 操作列表。
    pub ops: Vec<MountSpec>,
}
```

### RawMountOp + do_mounts（child_setup.rs + mount.rs）

```rust
/// 子进程可见的 mount 操作描述符（POD，repr(C)）。
/// 所有 raw pointer 指向 fork 前预分配的 CString 存储。
#[repr(C)]
pub struct RawMountOp {
    pub source: *const libc::c_char,
    pub target: *const libc::c_char,
    pub fstype: *const libc::c_char,
    pub flags: libc::c_ulong,
    pub data: *const libc::c_char,
}

/// 在子进程中执行所有 mount 操作。
/// 返回 0 = 成功，非 0 = 1-based 失败序号。
/// # Safety
/// 仅在 fork 后、Landlock 前调用。ops 必须指向预分配的 RawMountOp 数组。
pub unsafe fn do_mounts(ops: *const RawMountOp, count: usize) -> i32;
```

### pre_exec 序列变更

```
1. unshare(ns_ops)                    ← CLONE_NEWNS 在 mount ops 非空时自动加入
2. mount(NULL, "/", NULL, MS_PRIVATE|MS_REC, NULL)  ← 断开传播
3. mount(RawMountOp[])               ← 遍历执行所有 op
4. PID ns (double-fork + reaper)
5. chdir
6. prctl(NO_NEW_PRIVS)
7. uid/gid map
8. configure_loopback()
9. sethostname
10. landlock_restrict_self
11. seccomp USER_NOTIF + ext BPF
12. execve
```

`MS_PRIVATE|MS_REC` 和 mount ops 都在 Landlock 之前执行，确保：
- mount 操作不被 Landlock 规则干扰
- Landlock 规则对 mount 后的文件系统拓扑生效
- mount 传播不会泄露到宿主（`MS_PRIVATE|MS_REC`）

---

## 5. CLI flag

```
--unshare-mnt              隔离 mount namespace（可选，mount ops 非空时自动）
--bind SRC DST             可写递归 bind mount
--ro-bind SRC DST          只读递归 bind mount（先 bind 再 remount ro）
--tmpfs DST                挂载 tmpfs
```

隐性行为：
- `--bind` / `--ro-bind` / `--tmpfs` 任一个存在时，自动 `unshare(CLONE_NEWNS)` 
- `--unshare-all` 包含 mount ns
- CHILD 序列中用到的所有路径字符串都在 fork 前预计算为 CString

---

## 6. 边界场景

| 场景 | 行为 |
|------|------|
| `--bind /nonexist /dst` | pre_exec 中 mount 失败，_exit(127) |
| `--tmpfs /nonexist` | 内核不允许在不存在路径上 mount，_exit(127) |
| `--bind /usr /usr --landlock /usr:ro` | mount 先执行，放通 `/usr`；Landlock 再限制 ro |
| `--unshare-mnt` 无 mount ops | 仅隔离 mount ns，不做 mount |
| user ns 不存在时 | CLONE_NEWNS 可 unshare（无需特权），但之后 mount(2) 会失败 |
| mount ops 非零 + seccomp 拦截 165 | mount(2) 被 seccomp 拦截 → _exit(127) |
| `--unshare-all --share-net` | mount ns 仍隔离，其他 ns 按 flag 处理 |

---

## 7. 测试计划

| 测试 | 验证点 |
|------|--------|
| `mount_tmpfs_works` | `--tmpfs /mnt` 后 /mnt 可写 |
| `mount_bind_visible` | `--bind /src /dst` 后 /dst 可见宿主 /src 内容 |
| `mount_ro_bind_readonly` | `--ro-bind /src /dst` 后写入 /dst 被拒绝 |
| `mount_auto_ns` | mount ops 非空时自动 CLONE_NEWNS |
| `mount_with_landlock` | `--bind + --landlock` 组合正常 |
| `mount_multiple_ops` | 3 个 mount 操作全部生效 |
| `unshare_mnt_only` | `--unshare-mnt` 无 mount ops，mount ns 隔离 |
| `mount_failure_exit` | bind 不存在路径 → exit 非零 |

---

## 8. 不做的事

- **`--proc /proc`**：暂不支持，后续可加 `MountSpec::proc("/proc")` 工厂构造
- **`--dev /dev`**：user ns 内不支持 devtmpfs（无 `mknod` 权限），只允许 `devpts`
- **overlayfs**：需要更复杂的内核支持验证，后续考虑
- **`--mount` 通用语法**：`--bind`/`--ro-bind`/`--tmpfs` 已覆盖主流场景
- **optional mount**：mount 不应该静默失败
- **`pivot_root` / `chroot`**：那是更完整的 rootfs 替换，不做

---

## 8.5 已知限制与修复：`--ro-bind` 非 root 下 remount EPERM（2026-08-04，已修复）

`ro_bind` 的只读 remount 用 NULL-source 的 `mount(2)` 形式，内核在 userns 里对**不带源 superblock 锁定 flags**（nosuid/nodev/noexec/ro/atime）的 remount 返回 **EPERM**（strace 实测）。`/tmp`（tmpfs nosuid,nodev）必炸；`--bind` 本身无此问题。

**修复**：父进程 `source_mount_flags()` 从 `/proc/self/mountinfo` 读源挂载 opts 映射为 MS_* flags，remount 时 OR 进 flags。另修 `main.rs` 挂载 CLI 顺序 bug（`indices_of` 按命令行顺序合并 `--bind`/`--ro-bind`/`--tmpfs`，否则叠加可写子目录会被后挂的基座埋住）。

**现状**：非 root 下 `--ro-bind` 可用（含"只读基座 + 可写叠加子目录"模式）。Landlock 仍是非 root 只读保护的首选（零挂载），`--ro-bind` 是容器式层。详见 `docs/learned.md`。

---

## 9. 代码量估算

| 文件 | 新增行数 |
|------|---------|
| `src/config.rs` | ~50（MountSpec + MountConfig + 构造 + with_*） |
| `src/linux/mount.rs` | ~50（MountOp POD + do_mounts() + 可用性探测） |
| `src/linux/mod.rs` | ~40（prepare_mount_ops + ns_ops 插入 + 参数传递） |
| `src/linux/child_setup.rs` | ~40（enter_child 参数 + 序列调用） |
| `src/main.rs` | ~30（4 个 clap flag + 解析 + build_config 传入） |
| `tests/mount_test.rs` | ~120（8 个集成测试） |
| **总计** | **~330** |
