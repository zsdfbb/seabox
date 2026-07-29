# 执行计划: mount namespace 集成

> 设计: `docs/arch/mount-namespace/design.md`
> 审查: `docs/arch/mount-namespace/review.md`
> ADR: `docs/arch/mount-namespace/adr-mount-namespace-design.md`

## 任务列表

### Task 1: config.rs — MountSpec + MountConfig + with_* 方法

**文件**: `src/config.rs`
**需要修复**: 第 22 行已有 `pub mount: MountConfig` 但 `MountConfig` 未定义

**改动**:
1. 在 `NetworkConfig` 之后新增 `MountSpec` 结构体
2. 新增 `MountSpec::bind/ro_bind/tmpfs` 工厂方法
3. 新增 `MountConfig { enabled: bool, specs: Vec<MountSpec> }` + Default
4. `NamespacesConfig` 中 `ipc` 和 `pid` 之间插入 `pub mnt: bool`
5. `SandboxConfig::` 新增 `with_unshare_mnt/with_bind/with_ro_bind/with_tmpfs`
6. `SandboxConfig::Default` 补齐 `mount: MountConfig::default()`
7. `with_unshare_all()` 包含 `mnt: true`
8. 更新单元测试

### Task 2: main.rs — CLI flag

**文件**: `src/main.rs`

**改动**:
1. 新增 clap flag: `--unshare-mnt`, `--bind SRC DST`, `--ro-bind SRC DST`, `--tmpfs DST`
2. 解构并传入 `cmd_run` / `build_config`
3. `build_config` 中解析 `bind/ro-bind` 为成对 `(src, dst)` → `MountSpec`
4. 自动启用: `specs` 非空时 `namespaces.mnt = true`

### Task 3: src/linux/mount.rs — 新文件

**新文件**: `src/linux/mount.rs`

**内容**:
1. `RawMountOp` POD 结构体 (`#[repr(C)]`)
2. `pub unsafe fn do_mounts(ops: *const RawMountOp, count: usize) -> i32`
3. `pub fn make_private()` — MS_PRIVATE|MS_REC, fallback MS_SLAVE|MS_REC
4. `pub fn is_mount_namespace_available() -> bool`
5. 常量: `MS_BIND`, `MS_REC`, `MS_RDONLY`, `MS_NOSUID`, `MS_NODEV`, `MS_PRIVATE`, `MS_SLAVE`, `MS_REMOUNT`

### Task 4: src/linux/mod.rs — 集成到 execute()

**文件**: `src/linux/mod.rs`

**改动**:
1. `pub mod mount;` 注册
2. `ns_ops` 构建中当 `ns.mnt` 时插入 `CLONE_NEWNS`
3. 新增 `prepare_mount_ops()`: MountSpec[] → (RawMountOp[], CString backing)
4. 传递 `mount_ops`, `mount_ops_len`, `do_private` 参数到 `enter_child`
5. `ro_bind` 展开为 2 条 op: bind + remount ro

### Task 5: src/linux/child_setup.rs — pre_exec 序列

**文件**: `src/linux/child_setup.rs`

**改动**:
1. 新增 `use super::mount::RawMountOp;`
2. `enter_child` 签名末尾追加 3 个参数
3. step 1 后插入: `make_private()` → `do_mounts()`

### Task 6: tests/mount_test.rs — 集成测试

**新文件**: `tests/mount_test.rs`

**内容**: 8 个测试 case, 参考 `tests/network_test.rs`

## 执行顺序

串行执行:
1. Task 3 (mount.rs) — 新文件，独立
2. Task 1 (config.rs) — 配置层，依赖 mount.rs 的常量
3. Task 2 (main.rs) — CLI，依赖 config.rs
4. Task 4 (mod.rs) — 集成，依赖 mount.rs + config.rs
5. Task 5 (child_setup.rs) — 依赖 mount.rs
6. Task 6 (tests) — 依赖全部

每次 subagent 实现 → review subagent 审查 → 通过后下一个
