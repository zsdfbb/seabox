# CLI Interface

## Usage

```
sandbox-runtime [OPTIONS] <COMMAND>...
sandbox-runtime check
sandbox-runtime serve [--port 7878]

  -c, --config FILE       配置文件
  -p, --policy POLICY     full-access | read-only | workspace
  -n, --allow-network     放通网络
  -w, --allow-write PATH  额外可写路径（可重复）
  -d, --debug             debug 日志
```

无子命令时默认走 "run" 模式，直接执行 `<COMMAND>...`。

## 常用模式

```bash
# 普通执行（应用 workspace-write 策略）
sandbox-runtime ls -la

# 只读模式（cat 可以，写全部拒绝）
sandbox-runtime --policy read-only cat /etc/passwd

# 放通网络
sandbox-runtime --allow-network curl example.com

# 使用项目级配置文件
sandbox-runtime --config .sandbox.toml cargo build

# 完全绕过沙箱（危险）
sandbox-runtime --policy full-access rm -rf /
```

## 调试

```bash
# 检查当前系统沙箱能力
sandbox-runtime check

# debug 日志
sandbox-runtime --debug -- ls /etc/shadow
```

## Examples

```bash
cargo run --example cli_basic -- ls -la
cargo run --example cli_from_toml -- --config templates/workspace-write.toml.example cargo build
cargo run --example crate_api              # 演示 crate API 嵌入
cargo run --example codewhale_adapter      # 演示与 CodeWhale 集成
cargo run --example http_server            # 启动 :7878 HTTP API
```