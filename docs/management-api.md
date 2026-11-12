# 管理 API

当前 Web 后台提供 JSON API，默认地址为 `http://127.0.0.1:8788`。

| 方法与路径 | 用途 |
| --- | --- |
| `GET /api/state` | 查询认证阶段、VPN 状态、本地会话是否存在，并获取 CSRF token |
| `POST /api/auth/restore` | 恢复已保存的 Cookie/票据，向控制器验证会话 |
| `POST /api/tunnel/connect` | 完成认证后，在隔离环境内建立 VPN 隧道 |
| `POST /api/tunnel/disconnect` | 请求官方后台离线 |
| `POST /api/auth/begin` | 提交 `username`、`password`，开始新认证 |
| `GET /api/captcha` | 获取本次点击验证码图片 |
| `POST /api/auth/captcha` | 提交三个点击坐标、图片宽高 |
| `POST /api/auth/sms/send` | 请求发送短信验证码 |
| `POST /api/auth/sms/verify` | 提交 `code` 完成短信验证 |

写请求使用 JSON body 和 `X-CSRF-Token` 请求头。服务重启后 CSRF token 会变化，
应重新读取状态。浏览器请求的 Origin 必须与请求 Host 完全对应，不支持跨域调用。
普通 curl/服务端客户端可以不发送 Origin，但仍须提供 CSRF token。

## 恢复会话并连接

```bash
BASE=http://127.0.0.1:8788
CSRF=$(curl -fsS "$BASE/api/state" | jq -r .csrf)

curl -sS -X POST "$BASE/api/auth/restore" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $CSRF" -d '{}'

# 仅在 restore 响应 stage=authenticated 时调用 connect。
curl -sS -X POST "$BASE/api/tunnel/connect" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $CSRF" -d '{}'

curl -sS "$BASE/api/state" | jq '{stage,tunnel,session_available,message}'
```

恢复使用的是加密保存的 Cookie/票据，Web 不保存密码。它不会从 CLI 的密码缓存
自动重新认证，也不能跳过控制器要求的点击验证码或短信。会话失效时返回 HTTP400
及类似 `[75500002] 用户未登录` 的错误；需要重新走 begin/captcha/sms 流程。
restore 不自动建立隧道；stage=authenticated 不等于 VPN 在线。

状态字段：

- `tunnel`：`online`、`offline`、`unavailable`；判断 VPN 连接看这个字段。
- `stage`：`idle`、`captcha`、`sms`、`authenticated`、`error`。
- `session_available`：只表示本地存在缓存，不保证控制器仍认可该会话。
- `message`、`disconnect_reason`：操作结果或断线原因。

## 远程访问

原生运行脚本增加 `--allow-remote` 后，管理端口监听 `0.0.0.0` 并允许远程 Host：

```bash
python scripts/atrust-runtime.py run --server https://你的控制器地址 --allow-remote
```

直接启动 Web 服务也可以使用 `atrust-web --listen 0.0.0.0 --allow-remote`。
按本次部署要求，此选项不增加管理认证；同源与 CSRF 检查仍保留。
SOCKS 代理仍绑定本机。旧容器需更新源码/镜像并重新创建后才会生效；
此前发布的 ARM64 镜像尚未包含本次远程访问改动。
