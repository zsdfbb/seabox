# CLI Interface

## Usage

```
sandbox-runtime run [OPTIONS] <COMMAND>...
sandbox-runtime check
sandbox-runtime serve [--port 7878]

子命令:
  run       在沙箱中执行命令（必须）
  check     检查当前系统沙箱能力
  serve     启动 HTTP API 守护进程（Phase 1 stub）

run 选项:
  -c, --config FILE       配置文件
  -p, --policy POLICY     full-access | read-only | workspace
  -n, --allow-network     放通网络
  -w, --allow-write PATH  额外可写路径（可重复）
  -d, --debug             debug 日志

<COMMAND>... 支持 -- 分隔符：sandbox-runtime run -- ls -la
```

## 常用模式

```bash
# 普通执行（应用 workspace-write 策略）
sandbox-runtime run ls -la

# 只读模式（cat 可以，写全部拒绝）
sandbox-runtime run --policy read-only cat /etc/passwd

# 放通网络
sandbox-runtime run --allow-network curl example.com

# 使用项目级配置文件
sandbox-runtime run --config .sandbox.toml cargo build

# 完全绕过沙箱（危险）
sandbox-runtime run --policy full-access rm -rf /

# 使用 -- 分隔符（避免 clap 参数解析冲突）
sandbox-runtime run -- cargo build --release
```

## 调试

```bash
# 检查当前系统沙箱能力
sandbox-runtime check

# debug 日志（Phase 2 实现）
sandbox-runtime run --debug -- ls /etc/shadow
```

## Examples

```bash
cargo run -- run ls -la
cargo run -- check
cargo run --example cli_basic -- ls -la
cargo run --example cli_from_toml -- --config templates/workspace-write.toml.example cargo build
cargo run --example crate_api              # 演示 crate API 嵌入
cargo run --example codewhale_adapter      # 演示与 CodeWhale 集成
cargo run --example http_server            # 启动 :7878 HTTP API
```
