# Mount Namespace + 文件系统重排 — 架构上下文

## 概述

分析 sandbox-runtime 引入 mount namespace（`CLONE_NEWNS`）和文件系统重排能力的必要性、方案、与现有 Landlock 机制的配合关系。

核心问题：**Landlock 提供声明式权限控制（能读/写哪些路径），mount ns 提供文件系统视图控制（能看到什么路径）。两者正交。sandbox-runtime 当前只有前者，是否应该补上后者？**

---

## 现有架构

### 当前文件系统隔离手段

| 手段 | 能力 | 粒度 | 内核要求 |
|------|------|------|---------|
| Landlock ACL | 路径级别的读写执行控制 | 路径 + 权限位 | 5.13+ |
| seccomp（用户配置） | syscall 过滤 | 每个 syscall | 5.0+ |
| user ns | UID/GID 映射、capability 降级 | 进程级 | 3.8+ |

### 当前 pre_exec 序列（`src/linux/child_setup.rs`）

```
1. unshare(CLONE_NEWUSER / NET / IPC / UTS / CGROUP)
2. double-fork + reaper（PID ns）
3. chdir
4. prctl(NO_NEW_PRIVS)
5. uid/gid map
6. configure_loopback（NETLINK lo UP）
7. sethostname
8. landlock_restrict_self
9. seccomp USER_NOTIF
10. external BPF
11. execve
```

Landlock 在步骤 8 加载。mount 操作如果在 mount ns 内，需要插入在 **1 之后、8 之前**——因为 Landlock 限制了后续所有的文件系统访问，mount 也需要先做完。

### 关键约束（ADR 0003）

`fork()` 后到 `execve()` 之间的子进程禁止堆操作。mount ns 的操作（`mount(2)`、准备路径）需要在父进程预计算或在 child 中用纯 syscall 完成。

---

## 为什么 bwrap 有这个能力

bwrap 出身于 **Flatpak 项目**。Flatpak 要解决的问题是"给 GUI 应用（如 GIMP）一个完整的自包含 runtime"：

```
bwrap --ro-bind /usr/lib/x86_64-linux-gnu /usr/lib \
      --ro-bind /app/gimp /app \
      --tmpfs /tmp \
      --proc /proc \
      --dev /dev \
      --bind ~/.var/app/org.gimp.GIMP/config ~/.config \
      -- /app/bin/gimp
```

**每一步都是在重建视图**：不声明就不会出现在子进程的 `/` 下面。这需要视图隔离，权限隔离不够——Landlock 已拦截写，但 `/etc/passwd` 仍可读、仍可见文件存在。

| bwrap 场景 | Landlock 能不能解决 | 为什么不行 |
|-----------|-------------------|-----------|
| 给应用一个自定义的 /usr（特定 runtime） | ❌ | Landlock 不能改路径内容，只能控制权限 |
| 隐藏宿主机 /etc、/var、/home | ❌ | ro 只是不可写，文件仍然可见 |
| 给应用一个空的 /tmp | ❌ | Landlock 不能"让文件消失" |
| 挂载 procfs、devtmpfs | ❌ | Landlock 不涉及特殊文件系统 |

bwrap 2015 年诞生时 **Landlock 还不存在**（5.13, 2021）。mount ns + bind mount 是当时做文件系统隔离的标准做法。它不是"选择"mount ns 而非 Landlock，而是 Landlock 当时不可选。

而 sandbox-runtime 选择 Landlock 不是因为 Landlock 更好，而是因为当前场景（Agent 在宿主机上跑，需要访问宿主机文件）是**权限隔离**问题，Landlock 更轻量、更声明式。

```
bwrap 的问题                sandbox-runtime 的问题
─────────────────           ─────────────────
给 GIMP 一个 runtime        给 Claude Code 一个 shell
GIMP 不该看到宿主机          Agent 需要看到宿主机（项目文件、git、工具链）
Flatpak app 不知道宿主机     Agent 知道自己在宿主机上
视图从零构建                 权限在现有文件系统上叠加
```

如果 sandbox-runtime 的场景扩展到**视图隔离**（多 Agent 工具层、CodeWhale 云部署），mount ns 就会变成必需的——跟 bwrap 一样。

---

### 场景 1：工具版本隔离

**问题**：不同 Agent / 不同项目需要不同版本的工具链。

```
# 宿主机只有 Node 20
# Agent A 需要 Node 18
$ node --version
v20.0.0

# 想做的事：给 Agent 一个"假 /usr"其中 node 是 18 版
sandbox-runtime run --unshare-mount \
  --bind /opt/node18/bin/node /usr/bin/node \
  -- node --version
→ v18.0.0
```

**Landlock 做不到**：Landlock 控制权限（rw/ro），不改路径内容。

### 场景 2：Ephemeral 全局安装

**问题**：Agent 经常 `npm install -g` / `cargo install` / `pip install`，写入宿主机的 `/usr/local`。

```
# 所有全局安装写入 tmpfs，退出自动消失
sandbox-runtime run --unshare-mount \
  --tmpfs /usr/local \
  -- npm install -g typescript && tsc --version
```

**Landlock 做不到**：即使用 `--landlock /usr/local:rw`，写入也是直接落盘。没有"自动消失"语义。

### 场景 3：代理工具层

**问题**：Agent 需要一个可预测的工具环境，不依赖宿主机装了啥。

```
# 预构建一个 agent-tools 目录，里面装了 git / node / cargo / python / ...
# 作为只读 base 挂载到 /usr，宿主机 /usr 完全隐藏
sandbox-runtime run --unshare-mount \
  --ro-bind /images/agent-tools /usr \
  --tmpfs /tmp \
  -- cargo build
```

**Landlock 做不到**：Landlock 不能替换路径内容。

### 场景 4：多 Agent 的 /tmp 隔离

**问题**：两个 Agent 同时跑，共享 `/tmp` 导致文件冲突或信息泄露。

```
# Agent A 的 /tmp 只有 A 能看见
sandbox-runtime run --unshare-mount --tmpfs /tmp -- ./build.sh
# Agent B 的 /tmp 只有 B 能看见
sandbox-runtime run --unshare-mount --tmpfs /tmp -- ./test.sh
```

**Landlock 部分覆盖**：`--landlock /tmp:rw` 能隔离写权限（A 不能写 B 的文件），但不能阻止 A 读 B 的文件（`--landlock /tmp:ro` 也允许读）。

### 场景 5：Agent 探索不受信代码

**问题**：Agent 从网上下载并执行一个不受信脚本。如果脚本试图读 `/etc/passwd` 或扫描宿主机进程，Landlock 可以拦截读（`/:ro` + deny read），但不能隐藏文件的存在。

```
# mount ns 可以完全隐藏宿主机的敏感目录
sandbox-runtime run --unshare-mount \
  --tmpfs /etc \
  --tmpfs /var \
  --ro-bind /project /project \
  -- sh -c 'ls /etc; ls /var'
→ 都是空的
```

---

## 方案对比

### 方案 A：最小 mount ns（仅 --unshare-mount，无文件系统重排）

只加 `--unshare-mount` flag，在 pre_exec 中 `unshare(CLONE_NEWNS)`，但不做任何 mount 操作。用户如果想 mount，需要自己在命令里调 `mount(2)`（如果 seccomp 放行了 165）。

| 优点 | 缺点 |
|------|------|
| 实现量极小（~30 行） | 用户需要在 command 里自己 mount，麻烦 |
| 不影响当前 Landlock 体系 | 对 Agent 场景无直接帮助 |

### 方案 B：完整文件系统重排

新增 `--tmpfs /path`、`--bind /src /dst`、`--ro-bind /src /dst` 等 flag，在 pre_exec 中执行 mount 操作。

| 优点 | 缺点 |
|------|------|
| Agent 直接受益、bwrap 兼容 | 实现量大（~500 行）、child 代码复杂度增加 |
| 填补"bwrap 超集"的最后缺口 | mount 参数需在 fork 前预计算为 raw 指针 |
| 与 Landlock 互补而非替代 | 测试覆盖需要 root 或 user ns + `mount(2)` 支持 |

### 方案 C：折中（--unshare-mount + 父进程预 mount）

父进程在 fork 前解析 mount 配置、创建临时目录、在**当前** mount ns 中预 mount（需要 `CAP_SYS_ADMIN`），然后 fork + unshare 一个新 mount ns，子进程继承父进程的 mount 但后续操作不传播到宿主机。

| 优点 | 缺点 |
|------|------|
| 避免在 child 中调用 mount(2) | 父进程 mount 影响宿主机（虽然后续 unshare NEWNS 隔离） |
| 不需要改 child_setup 的 async-signal-safe 约束 | 语义复杂：mount 发生在不同 ns 中 |
| | 仍然需要 CAP_SYS_ADMIN |

---

## 与 Landlock 的关系

mount ns 和 Landlock 是**互补而非替代**：

```
Landlock:  路径 A → ro, 路径 B → rw    (权限)
mount ns:  宿主机 /usr → 镜像 /usr     (视图)

配合使用：
  --unshare-mount --ro-bind /images/tools /usr \
  --landlock /usr:ro --landlock /tmp:rw
  → /usr 是镜像内容（只读），/tmp 可写（落盘）
```

**如果同时有两者**，安全的默认策略：

```
# 视图：只有 project 和 tmpfs（隐藏了宿主机 /etc、/var、/home）
sandbox-runtime run --unshare-mount \
  --ro-bind /project /project \
  --tmpfs /tmp --tmpfs /etc --tmpfs /var \
  --landlock /project:rw --landlock /tmp:rw \
  -- ./build.sh
```

---

## 实现要点

### schema

```rust
pub struct MountConfig {
    /// 要挂载的 tmpfs 目标路径（`--tmpfs /path`）
    pub tmpfs: Vec<String>,
    /// 可读写 bind mount（`--bind /src /dst`）
    pub bind: Vec<(String, String)>,
    /// 只读 bind mount（`--ro-bind /src /dst`）
    pub ro_bind: Vec<(String, String)>,
}
```

挂载点：

```rust
impl MountConfig {
    /// 目标路径长度上限（PATH_MAX = 4096，栈缓冲区够用）
    pub const fn mount_count(&self) -> usize {
        self.tmpfs.len() + self.bind.len() + self.ro_bind.len()
    }
}
```

### MountDescriptor（child 可见的 POD）

```rust
#[repr(C)]
struct MountDescriptor {
    /// 源路径指针（对于 tmpfs 为 null）
    source: *const u8,
    source_len: u32,
    /// 目标路径指针
    target: *const u8,
    target_len: u32,
    /// mount flags（MS_BIND, MS_RDONLY, 0 for tmpfs）
    flags: u32,
    /// 文件系统类型（"tmpfs\0" 或 null）
    fstype: *const u8,
}
```

### pre_exec 序列变更

```
1. unshare(USER/IPC/NET/UTS/CGROUP)
2. unshare(CLONE_NEWNS)          ← 新增
3. ... 
5. uid/gid map
6. mount 操作（tmpfs / bind）     ← 新增，在 NO_NEW_PRIVS 之后
7. configure_loopback
8. sethostname
9. landlock_restrict_self
10. seccomp
11. execve
```

注意 `mount(2)` 放在 NO_NEW_PRIVS 之后是可行的——NO_NEW_PRIVS 不影响已有 capability 的执行，只阻止通过 setuid 等方式提升。在 user ns 内 mount 只需要 `CAP_SYS_ADMIN`，已经在 ns 创建时授予了。

Mount 操作必须在 Landlock 之前（Landlock 一旦加载会限制后续 mount 的目标路径访问，虽然 Landlock 本身不阻止 `mount(2)` syscall，但 mount 的目标路径可能不可写）。

---

## 边界场景

| 场景 | 行为 |
|------|------|
| `--bind /nonexistent /dst` | pre_exec 失败，_exit(127) |
| `--tmpfs /mnt` + 目标不存在 | mount 失败（内核无法在不存在路径上挂载） |
| `--ro-bind / /mnt` | 将整个宿主机 / 绑定挂载到 /mnt，只读 |
| `--unshare-mount` + 无 mount flag | 仅隔离 mount ns，不做额外 mount |
| 内核不支持 user ns 时 | mount ns 不可用（`CLONE_NEWNS` 需要 user ns 提供 CAP_SYS_ADMIN） |
| mount 途中失败 | 无法回滚已成功的 mount，子进程 _exit(127) |

---

## 约束

| 维度 | 详情 |
|------|------|
| **技术** | `mount(2)` 系统调用在 user ns 内可用，但受限于新 user ns 的 capability 范围。内核 5.12+ 支持 user ns 内的 `mount --bind` 和 `mount -t tmpfs` |
| **技术** | `MountDescriptor` 中的路径字符串需在 fork 前预分配，child 中只读引用 |
| **技术** | 不能支持 `--dev /dev`（`mount -t devtmpfs`），因为 user ns 内无权限创建设备节点 |
| **技术** | `--proc /proc` 需要 `gid=5` 等 mount 选项，需要额外处理 |
| **演进** | 需要更新 `NamespacesConfig` 增加 `mount: bool` 字段 |
| **演进** | CLI 新增 `--unshare-mount`、`--tmpfs`、`--bind`、`--ro-bind` flag |

---

## 不做的范围

- **设备节点**：`mknod(2)` 在 user ns 内不可用，不做 `--dev /dev`
- **overlayfs**：需要 `mount -t overlay`，内核 user ns 内支持不完善。不做 overlay，用 tmpfs + bind 组合代替
- **pivot_root**：bwrap 也不常用。不做

---

## 未澄清问题

- [ ] `--proc /proc` 是否值得支持？Agent 场景下 proc 可见性（看到宿主机其他进程）是否是威胁？
- [ ] mount 操作的顺序：是先做 tmpfs 还是先做 bind？如果 `--bind /usr /usr` 和 `--tmpfs /tmp` 混用，是否有依赖？
- [ ] 是否支持递归 bind mount（`MS_BIND | MS_REC`）？bwrap 默认是递归的。
- [ ] 如果 mount target 路径在宿主机上是 symlink，应该怎么处理？
- [ ] Landlock 和 mount ns 同时使用时，权限检查的顺序？先 mount 改变视图，再 Landlock 加权限限制。这是安全的。

---

## 后续建议

| 步骤 | 内容 | 产出 |
|------|------|------|
| 1 | 用 `arch-design` 做 mount ns 方案设计（方案 A/B/C 对比） | `docs/arch/mount-namespace/design.md` |
| 2 | 用 `prototype` 验证 `unshare(CLONE_NEWNS)` + mount 在 user ns 内的可用性 | 验证报告 |
| 3 | 如果验证通过，作为 Phase 2b 取代 eBPF 路线 | — |
