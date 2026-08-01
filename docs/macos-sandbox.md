# macOS 沙箱策略

**当前状态：计划中，尚未实现。** 当前所有代码仅为 Linux 后端 (Landlock + seccomp)。

## 设计目标

通过 `sandbox-exec` 生成 Seatbelt profile (SBPL)：

```
(version 1)
(deny default)
(allow file-read* (subpath "/"))
(deny file-read* (subpath "/Users/secret"))
(allow file-write* (subpath "/tmp"))
(allow network* (loopback))
```

## 能力映射（计划）

| 配置维度 | Seatbelt 操作 |
|---|---|
| `filesystem.allow_read` | `(allow file-read* (subpath "<path>"))` |
| `filesystem.deny_read` | `(deny file-read* (subpath "<path>"))` |
| `filesystem.allow_write` | `(allow file-write* (subpath "<path>"))` |
| `filesystem.deny_write` | `(deny file-write* (subpath "<path>"))` |
| `network.enabled = true` | `(allow network* (loopback))` |
| `network.enabled = false` | `(deny network*)` |

注意 macOS 的网络策略只有 on/off（loopback 全开 vs 全阻断），**不支持域名级过滤**。

## 拒绝检测（计划）

`was_denied()` 检测 stderr 中的以下模式：

- `Sandbox: <cmd> denied <operation>`
- `Operation not permitted`
- `Bad system call`

## 与 Linux 能力差异

| 维度 | Linux | macOS |
|---|---|---|
| 文件系统粒度 | 路径级 (Landlock) | 路径级 (SBPL subpath) |
| syscall 过滤 | 自定义 BPF（13 个黑名单） | 仅 (deny default) + 显式 allow |
| 网络粒度 | on/off（当前占位） | on/off |
| 进程隔离 | user_ns + (可选) PID_ns | 无对应 |

macOS 网络隔离只到 on/off 粒度是 Seatbelt 的固有限制，跟 seabox (TS) 行为一致。
