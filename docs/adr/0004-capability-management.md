# ADR 0004: Linux Capability 权限管理

> 日期：2026-08-02
> 状态：**提案**
> 关联：`docs/arch/cap-management/design.md`

---

## 背景

seabox 现有安全边界对 capability 门控的 syscall 不设防：

- **root 无 `--unshare-user`** 运行时，子进程保留宿主全部 caps（ptrace/setns/mount/mknod 全放行）。这是当前模型唯一的宿主暴露面。
- **`--uid 0`**（userns 内 root 映射）时子进程为 ns 内 root，持全量 ns-scoped caps。
- 非 root 默认路径（同 uid 映射）exec 后 ns 内零 cap（实测 `CapEff=0`），无需干预。

bwrap 提供了 `--cap-add`/`--cap-drop`（含 `ALL`），实现为三条 raw syscall 原语（capset / PR_CAPBSET_DROP / PR_CAP_AMBIENT_RAISE）。本仓库定位为 bwrap 功能超集，定位表承诺 namespace/seccomp/environment 保持 flag 级兼容，capability 属其中既有承诺。

## 决策

为 Linux 后端实现 capability 管理，采用以下五项决策。

## 具体决定

| # | 决策 | 值 |
|---|---|---|
| D1 | 默认 cap 集 | **全量零 cap（含 host-root）**。对齐 bwrap man 页 "By default no caps are left"，背离 bwrap 代码（root 默认继承全 caps）。提供 `--cap-inherit` 作为 bwrap root 语义 opt-in 逃生门 |
| D2 | `--cap-add` 限定 userns | `--cap-add` **自动叠加 userns**（root 与非 root 均触发），cap 只在新 userns 内有效，杜绝 host-root + cap-add 把 cap 回灌宿主命名空间 |
| D3 | 实现原语 | `capset(V3)` 收窄 eff/perm/inh + `prctl(PR_CAPBSET_DROP)` 收缩 bounding + `prctl(PR_CAP_AMBIENT_RAISE)` exec 前抬 ambient。全部 raw syscall、零 libcap 依赖、零堆、async-signal-safe（符合 ADR 0003） |
| D4 | 应用位置 | 所有需要 cap 的 setup（unshare/mount/loopback/sethostname/landlock）**之后**、seccomp **之前** |
| D5 | 按需执行 | 整块无操作时跳过；非 root 终态零 cap 时**跳过 bounding 收缩**（实测：capset 清零后非 euid-0 无法重提 cap）；只遍历置位 bit；cap 名→编号解析在父进程 fork 前完成 |

## 决策理由

1. **D1 关闭首要缺口**：root 无 userns 场景是唯一让宿主真正暴露的路径。默认零 cap + `PR_SET_NO_NEW_PRIVS`（已无条件设置）+ bounding 收窄（杜绝 CAP_SETPCAP 重抬）使 exec 后无任何路径恢复宿主 caps。`--cap-inherit` 为依赖宿主全 caps 的旧脚本提供显式逃生门。
2. **D2 防 cap 回灌**：host-root 若在 init ns 内 cap-drop 后 cap-add，恢复的 cap 直接作用在宿主命名空间。限定 userns 让任何 `--cap-add` 的产物都限制在 seabox 新建的 userns 内。与现有"非 root 下 --unshare-pid/--unshare-net 自动叠加 userns"模式一致。
3. **D3 与 bwrap 同构**：三条原语被实测背书（F1-F3）。ambient 是非 root 进程 exec 后保留 cap 的唯一机制（exec 重算 permitted&inheritable，非 root 无 file caps 时清零除非 ambient）。
4. **D4 不破坏现有功能**：`--bind`/`--allow-network`/`--hostname` 依赖 cap 的 setup 在 capset 之前完成，无需用户额外 `--cap-add SYS_ADMIN`（与 bwrap 需显式 cap-add 才可 mount 不同）。
5. **D5 热路径零成本**：非 root 默认（Agent 最热路径）整块跳过，零额外 syscall。bounding 跳过有 F2 实测依据。

## 已确认的实测锚点（本环境）

- F1：非 root userns creator 持 ns 内全量 caps，inheritable=0。
- F2：非 root creator capset 清零后无法重提 cap（EPERM）→ bounding 收缩对非 root 非必需。
- F3：PR_CAP_AMBIENT_RAISE 需 cap 同时在 permitted 和 inheritable。

## 未决点与风险

- **F5（未验证）**：非 root `--cap-add` 的可靠性依赖"写非零 uid_map 后 permitted 是否保留"。本环境写 uid_map 恒 EPERM，无法实测。设计将其视为 best-effort，由探针测试（`tests/capability_test.rs` 探针 2）在 CI 判定，不成立则相关测试 skip 而非 fail。文档明示"`--cap-add` 对普通用户仅在 `--uid 0` / root / file-cap 场景可靠"。
- **R1 行为变更**：root 默认从"保留全 caps"变"零 cap"。属安全目标本意；现有测试只断言 `id -u` 不断言 CapEff，无需修改。
- **R3 bounding 在 userns 内 no-op**：PR_CAPBSET_DROP 需 init-ns 的 CAP_SETPCAP，ns 内恒 EPERM。对 ns-root 无收紧效果，可接受（ns-scoping 已隔离宿主）。
- **R4 既有 bug**：`configure_loopback` 在 uid_map 写后执行，非 root 下无 CAP_NET_ADMIN 静默失败。与 cap 管理正交，单独修复（loopback 配置前移到 uid_map 之前）。
- **R5 systemd-nspawn 类 seccomp 拒 capset**：外部 filter 拒绝 capset 会误杀 root 收零路径。以 `requested == natural` 泛化 bwrap 的 skip 优化。

## 未被选择的方案

- **仅 `--cap-drop`**：能关闭安全缺口但违背 flag 级兼容承诺；无法表达 `--cap-drop ALL --cap-add CHOWN`（bwrap 文档化核心用法）与容器式 `--uid 0 --cap-add ALL`。
- **root 自动叠加 userns 代替 cap-drop**：把 root 整体丢进 userns 是远超 cap 的破坏性变更（mount 可见性/设备访问/uid 语义全变）。
- **cap-add 要求 --unshare-user 否则报错**：破坏现有 pid/net 自动叠加 userns 模式。
- **capset-to-zero + seccomp 黑名单 capset**：子进程内合法 capset 也被 EPERM，安全边界泄漏进 seccomp。
- **引入 libcap**：bwrap 同样手写 raw syscall，引入外部依赖无必要。
