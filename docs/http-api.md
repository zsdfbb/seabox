# HTTP API (serve 模式)

`sandbox-runtime serve` 启动 axum 服务器，绑定 `127.0.0.1:7878`，兼容 OpenSandbox v1 协议，方便 CodeWhale 的 `SandboxBackend` trait 直接对接。

## Endpoints

### `POST /v1/sandbox/run`

执行 shell 命令并返回输出。

**Request**

```http
POST /v1/sandbox/run
Content-Type: application/json

{
  "cmd": "ls -la",
  "env": {"KEY": "value"}
}
```

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `cmd` | string | ✅ | 完整 shell 命令字符串 |
| `env` | object | ❌ | 注入的环境变量 |

**Response (200)**

```json
{
  "stdout": "...",
  "stderr": "...",
  "exit_code": 0
}
```

**Error Responses**

| 状态码 | 含义 |
|---|---|
| `400` | 请求体 JSON 非法 / 字段缺失 |
| `500` | 沙箱内部错误（landlock 失败、spawn 失败等） |

## Auth

默认无认证（绑定 127.0.0.1）。如需绑定 LAN / 公网，serve 模式应在前置 reverse proxy 上做认证。

## 启动

```bash
cargo run --example http_server
# 或
sandbox-runtime serve --port 7878
```