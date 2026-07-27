# ADR: `--allow-network` 实现方式（修订版）

> 日期：2026-07-26
> 状态：**决策**
> 关联：`docs/arch/phase2-wrapup/design.md`
> 废弃：第一版 ADR 中关于 ioctl + async-signal-safe 的决策

---

## 背景

第一版 ADR 选择 ioctl 配置 lo，核心理由是 async-signal-safe 约束。该约束已不成立（commit `34bc861` 使用 raw `libc::fork()`），且项目定位调整为 bubblewrap 超集，需要 CLI 兼容和未来扩展能力。

## 决策

采用 **NETLINK** 实现 loopback 配置。

## 具体决定

| # | 决策 | 值 |
|---|---|---|
| D1 | 配置方式 | **NETLINK**（RTM_NEWADDR + RTM_NEWLINK），与 bwrap 一致 |
| D2 | `--allow-network` 语义 | 不隔离 netns（等价于 `--share-net`） |
| D3 | `--share-net` flag | **新增**，bwrap 兼容别名 |
| D4 | `--unshare-net` 行为 | **保持当前**：lo DOWN（不 break） |
| D5 | 未来扩展路径 | NETLINK 基础设施可复用于 veth NAT |
| D6 | 降级策略 | 失败时写 stderr + 继续 exec |

## 决策理由

1. **async-signal-safe 已不是约束**：raw fork 后子进程可安全使用 NETLINK。第一版 ADR 的核心论据已过时。
2. **bwrap 一致**：bwrap 的 `network.c` 使用相同 NETLINK 模式，维护者迁移成本低。
3. **ifreq union 兼容问题消失**：NETLINK 使用明确定义的 `#[repr(C)]` 结构体，无 libc 版本兼容问题。
4. **可扩展**：未来 veth + NAT 同样需要 NETLINK，单一基础设施降低维护成本。

## 未被选择的方案

- **ioctl**：虽然代码少 ~150 行，但面临 ifreq union 兼容问题、与 bwrap 不一致、无法做 veth NAT。
- **`NetworkMode` 枚举体系**：过度设计，当前只需要 `loopback: bool`。未来需扩展时再升级。
- **安全默认值（隐含 `--unshare-net`）**：属于独立的安全策略变更，不应混入本收尾工作。
