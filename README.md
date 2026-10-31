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
uv run atrust --help
```

或安装到当前环境：

```bash
uv tool install .
```

### 使用

```text
atrust status [-a] [-j]      # 连接/隧道状态（-a 全量, -j JSON）
atrust logout                # 注销当前会话
atrust spa <url>             # 查询 SPA 敲门种子与信息
atrust config [-j]           # 导出 SDP 客户端配置
atrust service status|start|stop|restart   # systemd 单元控制（需 root）
atrust doctor                # 环境体检
atrust logs [-f] [-n N]      # 查看/跟踪日志
atrust version               # 版本信息
```

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

```bash
uv sync && uv run atrust status
```

Zero runtime dependencies (stdlib only, Python ≥ 3.10).

### License

MIT
