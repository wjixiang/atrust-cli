# atrust-cli

[中文](#中文) | [English](#english)

## 中文

非官方的 Sangfor aTrust（深信服零信任客户端）Linux 命令行工具。
基于对 `atrust-2.5.16.30.deb`（UOS 构建）的逆向分析，直接通过客户端内部的
Thrift RPC 管道与守护进程通信，**无需运行 Electron 托盘界面**即可查看状态、
登出、查询 SPA 种子等。

### 安装（uv）

```bash
git clone <this-repo> && cd atrust-cli
uv sync
uv run atrust-cli --help
```

或安装到当前环境：

```bash
uv tool install .
```

### 使用

```text
atrust status [-a] [-j]      # 连接/隧道状态（-a 全量, -j JSON）
atrust login [url] [-u 用户] [--save]   # 登录（凭据模式 / 会话复用）
atrust login --forget        # 删除已缓存的凭据
atrust logout                # 注销当前会话
atrust spa <url>             # 查询 SPA 敲门种子与信息
atrust config [-j]           # 导出 SDP 客户端配置
atrust service status|start|stop|restart   # systemd 单元控制（需 root）
atrust doctor                # 环境体检
atrust logs [-f] [-n N]      # 查看/跟踪日志
atrust version               # 版本信息
```

### 隔离虚拟机与 Web 管理

需要避免 aTrust 与旁路网关 OpenClash 冲突时，可将完整客户端放进 KVM 虚拟机，
通过本机网页完成点击验证码和短信认证，手动决定是否连接隧道。

```bash
python scripts/atrust-vm.py prepare
python scripts/atrust-vm.py start
python scripts/atrust-vm.py install --deb /路径/atrust-2.5.16.30.deb
python scripts/atrust-vm.py proxy
```

管理地址：<http://127.0.0.1:8787>；应用代理：`SOCKS5 127.0.0.1:10808`。
容器承载 QEMU，aTrust 与 Web 后台在独立虚拟机中运行，不自动改变宿主机网络。
详见 [部署与管理说明](docs/vm-management.md)。

镜像构建定义与部署脚本均包含在本仓库：

- [`scripts/vm/Containerfile`](scripts/vm/Containerfile)：QEMU 容器镜像。
- [`scripts/atrust-vm.py`](scripts/atrust-vm.py)：准备、部署、同步与代理入口。
- [`scripts/vm/install-guest.sh`](scripts/vm/install-guest.sh)：客机安装与服务配置。
- [`src/atrust_cli/webui/`](src/atrust_cli/webui/)：Web 管理界面。

发布步骤见 [GitHub 发布说明](docs/publishing.md)。当前 Web 会话到隧道的交接仍属
实验性功能：曾观察到服务器以 `cookieHijacking` 撤销会话；已修正客户端身份
一致性和连接状态判断，真实环境稳定性仍需验证。

### 登录与凭据缓存

#### 捕获一次登录的会话（实验性）

如果官方客户端一登录就导致断网，可使用**仅认证**模式：

```bash
uv run atrust-cli login https://你的控制器地址 -u 用户名 --auth-only --no-cache
```

该模式隐含 `--capture` 和 `--headless`：只向控制器进行认证并加密保存
票据/Cookie，不启动官方窗口，不调用本机 `/v1/service/init` 或
`/v1/service/start`，也不等待隧道上线。它不会断开或隔离已经运行的官方
连接；测试前需确保官方客户端没有自行重连。
如服务器仍要求 accessCheck，会保存当前认证结果并明确提示访问检查未完成。
此模式不等于完整 VPN 在线，也不能保证会话长期有效。
密码认证要求 `-u 用户名`；官方窗口可能在认证后自动建隧道，
无法通过此标志阻止。通过 `login --session-info` 查看捕获摘要。

如果已有捕获的 Cookie，可只验证会话，避免重复提交密码和验证码：

```bash
uv run atrust-cli login --resume --auth-only
```

它使用会话内 authConfig（不传 `mod=1`），再尝试 `ticketExchange`。
全程不访问本机 agent，不建隧道；失败保留原缓存，不回退到密码登录。
Cookie 必须仍代表有效登录会话；注销、过期或仅含设备标识时无法免验证。

认证错误 `75500000` 是通用认证失败，不一定是随机数过期。CLI 会显示
脱敏后的服务器说明；仅在说明明确指出随机数问题时最多重试一次。
遇到图形验证码要求或超时，会从 `/passport/v1/public/checkCode` 获取新图片，
输出临时文件路径；用图片查看器打开后，在原终端输入验证码继续。
图片权限为 `0600`，不启动官方客户端，也不会因此建立隧道。

项目的 Python 命令为 `atrust-cli`；系统的 `/usr/bin/atrust` 是官方客户端。
需要安装官方客户端并保持 `aTrustDaemon` 运行。以下命令在项目目录执行：

```bash
# 在桌面环境打开官方登录窗口，完成密码/MFA 后获取会话凭证。
# --no-cache 跳过本项目已有的密码缓存，不会保存新密码。
uv run atrust-cli login https://你的控制器地址 --capture --no-cache --wait 300

# 只显示是否存在票据、Cookie 数量等摘要，不显示秘密值。
uv run atrust-cli login --session-info

# 使用捕获的会话连接后台，不启动 Electron，也不回退到密码认证。
uv run atrust-cli login --resume --headless
```

如果官方客户端已经在线，第一条命令会直接尝试获取该会话的票据。
另一条路径是 CLI 密码认证：

```bash
uv run atrust-cli login https://你的控制器地址 -u 用户名 --capture --headless
```

此路径在终端提示输入密码，并尝试调用官方本机 HTTPS API 建立隧道；
复杂的服务器认证/终端检查流程可能仍需先通过官方窗口完成。
`--capture` 本身不要求保存密码；如另外使用 `--save`，才会启用密码缓存。

会话保存到 `$XDG_STATE_HOME/atrust-cli/session.json`（默认
`~/.local/state/atrust-cli/session.json`）。票据、Cookie、认证配置和响应均加密，
随机密钥存于同目录的 `session.key`；两者权限为 `0600`，目录为 `0700`。
同时取得这两个文件的人可以解密；不要分享文件内容。`login --forget`
同时删除密码缓存、会话缓存及会话密钥，不注销官方后台会话。

实现依据官方 2.5.16.30 随包网页 SDK 的 `/v1/service/init`、
`/v1/service/start`、`sessionIdExchange` 和 `ticketExchange` 流程。
网页在约 80 秒后丢弃缓存的 sidTicket；**不能把该票据当作长期凭证**。
捕获后会尝试将本机票据换为控制器 Cookie，并获取新票据。
`--resume` 优先尝试从后台会话或 Cookie 获取新票据；失效时明确失败，
不保证跨注销、跨设备或跨重启恢复。后台已经在线时，恢复命令仅确认在线，
这不证明断线后的凭证恢复能力。

认证响应已捕获但本机交接失败时，命令仍返回失败；可用 `--session-info`
确认是否留下凭证。未返回票据或 Cookie 时不会创建空会话缓存。
该流程已通过模拟服务测试，仍需实际控制器登录验证。它不会改变
aTrust 的路由/DNS 行为，也不会自动解决 OpenClash Fake-IP 冲突。

#### 密码缓存

- `atrust login`：先查守护进程里是否已有会话；有则直接退出。
  没有会话时，若存在凭据缓存，会**先静默重放登录**（不弹窗、不输密码），
  失败才回退到官方托盘的交互登录窗口。
- `atrust login -u 用户 URL`：凭据模式（直连控制器的 passport API）。
  验证码图片保存到本地手输、短信 MFA 交互输入。加 `--save`
  会把凭据加密缓存，之后掉线重连不再需要输密码；缓存密码失效时会
  立即提示输入新密码并自动更新缓存。
- 缓存文件：`$XDG_STATE_HOME/atrust-cli/credentials.json`（默认
  `~/.local/state/atrust-cli/`，权限 0600）。

**密码缓存的安全边界**：使用 ChaCha20 + HMAC-SHA256，密钥通过 PBKDF2
从本机 machine-id、UID、用户名派生。这些信息并非真正的秘密；不能保证
缓存文件外泄后不可解密，也不防本机 root / 同账户进程。发往密码认证接口
的密码使用 RSA 加密，本项目不把密码明文写入缓存文件。

示例：

```console
$ atrust status
aTrust status:
  status                          3 (ONLINE)
  ...
daemon: active(running) [enabled]
processes: aTrustAgent, aTrustTray, aTrustXtunnel-64
client: 2.5.16.30 (electron 9.0.2)
```

### 原理

- aTrust 以 root 运行 `aTrustAgent`（systemd 单元 `aTrustDaemon`），
  并在 `/usr/share/sangfor/.aTrust/var/run/` 下暴露若干
  **Thrift（TBinaryProtocol over unix socket）** 命名管道：
  `aTrustCore-*`、`aTrustDaemon-*`、`aTrustTunnel-*` 等。
- 官方 Electron 托盘（`resources/app/src/service/thrift/*.js`，未压缩即随包分发）
  里包含全部服务的 IDL；本工具按同样的线格式实现了最小 Python 客户端。
- 状态枚举：`0=OFFLINE 1=BINDING 2=RECOVERING 3=ONLINE`。

详见 [docs/reverse-engineering.md](docs/reverse-engineering.md)（完整逆向报告）。

### 免责声明

本工具仅用于互操作与学习研究，与 Sangfor 无关；登录/隧道建流仍由官方
客户端完成。请遵守你所在组织与所在地的法律法规。

---

## English

Unofficial CLI for the Sangfor aTrust zero-trust client on Linux.
It talks to the client's internal **Thrift RPC named pipes**
(reverse-engineered from the shipped Electron app) so you can query
status, log out, inspect SPA state, etc. without touching the tray UI.

`atrust login -u USER URL` does credential login against the controller's
passport API (captcha image + SMS MFA passed through interactively).
With `--save` the credentials are cached encrypted
(ChaCha20 + HMAC, key bound to this machine via machine-id/uid — see
the security note in the Chinese section above) so dropped sessions
relogin silently; `atrust login --forget` removes the cache.

```bash
uv sync && uv run atrust-cli status
```

Zero runtime dependencies (stdlib only, Python ≥ 3.10).

### License

MIT
