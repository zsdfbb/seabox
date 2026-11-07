# macOS 沙箱策略

**当前状态：已实现（macOS 27.0.1 / arm64 实测通过）。** 施加侧为 `/usr/bin/sandbox-exec`，
配置层（`src/macos/config.rs`）与 SBPL 生成器（`src/macos/sbpl.rs`）无条件编译（Linux CI 可单测），
实现侧（`src/macos/imp.rs`）由 `#[cfg(target_os = "macos")]` 整模块门控。

> 完整设计见 [`docs/arch/macos-seatbelt/`](arch/macos-seatbelt/)（[context](arch/macos-seatbelt/context.md) · [design](arch/macos-seatbelt/design.md)，关键技术决策见 design.md 附录 A）。
> 本文是速查摘要；两条早期结论已被 macOS 27.0.1 实测推翻，见下方「已修正的错误结论」。

## 施加方式

通过 `/usr/bin/sandbox-exec -p <profile> -- <cmd>` 施加 Seatbelt profile (SBPL)。profile 走 `-p` 直接传参，不落临时文件。

选 `sandbox-exec` 而非 `sandbox_init`，决定性理由是**失败语义**：坏 profile 时 `sandbox-exec` 返回 rc=65 且命令不执行（fail-closed），而 `sandbox_init()` 返回 -1 但**进程无沙箱、宿主可写**（fail-open）。详见 [design.md §5](arch/macos-seatbelt/design.md)。

```
(version 1)
(deny default)
(allow file-read*)                              ; 读全开（窄白名单会 abort，见下）
(allow file-write* (subpath "/Users/me/proj"))  ; 写白名单
(deny file-read* (subpath "/Users/me/.ssh"))    ; 凭据黑名单（必须最后写）
```

## 策略形态

| 维度 | 形态 | 说明 |
|---|---|---|
| 读 | **双模式**：`All`（默认）或 `Only([roots])` | 窄白名单可行，但需枚举系统地板；预设默认用 `All` |
| 写 | **白名单** | workspace + `TMPDIR` + 显式追加；递归含子树 |
| 凭据 | 内置 deny 黑名单 | **读+写**均封 |

## 三种预设

| 预设 | 读 | 写 | 凭据保护 |
|---|---|---|---|
| `ReadOnly` | 全盘 | 仅 `TMPDIR` | ✅ 读+写 |
| `WorkspaceWrite` | 全盘 | workspace + `TMPDIR` | ✅ 读+写 |
| `FullAccess` | 全盘 | 全盘 | ❌ |

省略 `--mac-preset` → 若无任何 `--mac-*` 字段则**不施加限制**；若有字段则走**安全基线**（读全开 + 仅指定项可写 + 禁网）。
网络维度与预设**正交**。

### 预设与自定义可以混用

预设只是“填默认值”，字段总能覆盖或追加：

```bash
# 纯预设
seabox run --mac-preset workspace-write -- cargo build

# 纯自定义（无预设）
seabox run --mac-write ./target --mac-write ~/.cargo -- cargo build

# 预设 + 覆盖
seabox run --mac-preset workspace-write --mac-write ~/.cargo -- cargo build
```

`--mac-read PATH` 出现即切到 `Only` 模式（真隔离）。注意 `--mac-write` 是**递归**的，含删除权。

### 即使不限制也不等于裸跑

`(allow default)` 仍有硬限制（实测）：

| 限制 | 细节 |
|---|---|
| **setuid 程序不可用** | `ps` `top` `su` `atq` `crontab` `newgrp` 全部被拒；**任何 SBPL 规则都放不通** |
| **SIP 路径不可写** | `/etc` `/System` 等仍受保护 |

setuid 被拒的错误形态是 `sandbox-exec: execvp() of '/usr/bin/atq' failed: Operation not permitted`——Agent 用 `ps aux` 排障时会误以为策略写错。故「不配预设」实现为**不进 `sandbox-exec`**，以免白白损失该能力。`seabox check` 会单独列出这条。

## 能力映射

| 配置维度 | Seatbelt 操作 |
|---|---|
| 读放通 | `(allow file-read*)` |
| 读拒绝 | `(deny file-read* (subpath "<path>"))` |
| 写白名单 | `(allow file-write* (subpath "<path>"))` |
| 路径匹配 | `subpath`（组件前缀）/ `literal`（精确）/ `prefix`（字符串前缀，危险） |
| 网络出站端口 | `(allow network-outbound (remote ip "*:443"))` |
| 网络 loopback | `(allow network-outbound (remote ip "localhost:*"))` |
| DNS | `(allow network-outbound (remote unix-socket (path "/private/var/run/mDNSResponder")))` |

### 网络粒度（修正）

支持：**端口精确匹配**、IP 通配、unix-socket、**inbound/outbound 分离**。

不支持（语法层硬拒）：**域名白名单**、**具体 IP 白名单**——
`(remote ip "example.com:443")` 与 `(remote ip "1.1.1.1:*")` 均报
`sandbox-exec: host must be * or localhost in network address`。

也就是说：`network-outbound` 的 `remote ip` 只接受 `*` 与 `localhost` 两个主机值，
端口位可以精确到具体号（如 `"*:443"`）。这是 **SBPL 语法层**的限制，不是政策选择——
无法靠改参数绕过。因此 macOS 上「按域名放行」需要旁路方案（本地代理 + 只放通到代理端口），本轮不实现。

> 实现位置：`src/macos/sbpl.rs` 的 `push_network`，`NetAccess::Ports` 生成
> `(allow network-outbound (remote ip "*:443"))`，并**恒定附带** mDNSResponder unix-socket
>（漏掉它则沙箱内 DNS 解析失败，`curl` 报 rc=6）。

## 拒绝检测

`DenyMechanism::Seatbelt`，按精度分三级：

| 判据 | 精度 |
|---|---|
| `log show --predicate 'sender == "Sandbox"'` 拿到 `deny(1) file-write-create /path` | 精确 |
| stderr 含 `Operation not permitted` | 可能 |
| exit 134 (SIGABRT) = 读白名单过窄 | 启发式 |

**关键**：拒绝不会可靠传播为 exit code（`sh -c '... > denied 2>/dev/null; exit 0'` 得到 rc=0），所以不能只靠 exit code 分类。
`exit_code == 65` 表示 **profile 本身被拒**（我们自己的 bug），不是策略拒绝。

## 与 Linux 能力差异

| 维度 | Linux | macOS |
|---|---|---|
| 文件系统 | Landlock ACL，读写皆白名单 | SBPL，**读全开** + 写白名单 + 凭据黑名单 |
| syscall 过滤 | 自定义 BPF（13 个黑名单） | **无**（Seatbelt 无等价物） |
| 网络粒度 | on/off（当前占位） | **端口级 / unix-socket / 方向分离**，但拒域名与具体 IP |
| 进程隔离 | user_ns + (可选) PID_ns | **无对应物** |
| 失败语义 | — | `sandbox-exec` fail-closed |

macOS 后端在纵深防御上**弱于** Linux：无 syscall 过滤、无 namespace、无 capability，且读侧零隔离。`seabox check` 须明确输出这些差距。

## 已修正的错误结论

本文早期版本有两处描述被 macOS 27.0.1 实测推翻：

1. ~~「macOS 的网络策略只有 on/off，不支持细粒度」~~ → **错**。Seatbelt 支持端口精确匹配、unix-socket、inbound/outbound 分离。真正不支持的是**域名与具体 IP**。
2. ~~缺「窄白名单 → abort(134)」这一关键行为~~ → **已补**。只给 `/usr` `/System` `/bin` 等系统路径时，`/bin/sh` 直接 abort(exit 134)，内核日志 `deny(1) file-read-data /`。必须有 `(allow file-read* (literal "/"))` 起步，而 Apple 的 `system.sb` 在本机不存在，无法 import。

### 补充：白名单过窄的真实失败形态是 abort(134)，不是「权限不足」

这一条极易误诊，单独说明。读白名单只列 `/usr` `/System` `/bin` 等目录时，
`/bin/sh` **不会**报 `Operation not permitted`，而是直接 **abort（exit 134 = 128+SIGABRT）**：

```
$ sandbox-exec -p '(version 1)(deny default)(allow file-read* (subpath "/usr"))' -- /bin/sh -c 'echo hi'
Abort trap: 6          # exit 134
# 内核日志：deny(1) file-read-data /
```

原因是 dyld 在加载阶段需要读根目录 `/` 本身（`file-read-data /`），拿不到就 abort。
所以 `MacReadMode::Only` 必须自动补两条：`(allow file-read* (literal "/"))` 与
符号链接项 `(literal "/etc")` `(literal "/tmp")`。

因此 `classify_output` 把 **134 归为 `Denied{Seatbelt}`** 并在 message 里标「可能」——
宁可误报拒绝，不可误报成功。若你的命令莫名其妙 abort 而 stderr 无任何权限提示，
先查读白名单是否过窄。

另需注意：
- **规则顺序敏感（后写赢）**，与 specificity 无关——`deny_read` 必须写在写白名单之后。见 [design.md §6.1](arch/macos-seatbelt/design.md)。
- 写权限必须**整族**放通，且 `/dev/null` `/dev/tty` `/dev/dtracehelper` `/dev/stdout` `/dev/stderr` 必须在 floor 里；缺 `/dev/null` 会让 `git status` 直接失败。
- 路径必须 `realpath`：`/var` 与 `/private/var` 字面不同，`$TMPDIR` 不解析就**永不匹配**（尾斜杠本身无害）。
