# 官方隧道组件独立运行环境

该模式将官方 aTrust daemon、用户 core、xtunnel/watchdog 和本项目的 Web
管理封装在一个独立网络空间的容器里，不运行 Electron、systemd 或 QEMU。
它仍使用官方隧道协议实现，不是自行重写协议，也不跳过设备检查和访问策略。
与旧 `atrust-manager` 镜像不同，新镜像名称为 `atrust-native`。

## 构建

支持官方 `2.5.16.30` 的 Linux amd64 / arm64 包，安装包必须与构建主机架构一致。
需要 Linux x86_64 或 ARM64、rootless Podman、pasta 和可读写的 `/dev/net/tun`。此模式不需要 KVM 或嵌套虚拟化。

```bash
python scripts/atrust-runtime.py build --deb /路径/atrust-2.5.16.30.deb
```

构建使用临时白名单上下文和多阶段镜像，只提取 native bin/lib/plugins、
UEM/EAIOC、必要辅助脚本、版本与证书。最终镜像无 Electron 程序、Chromium
资源、完整桌面 Web 应用、原始 deb、账号、预设密码或登录会话。
镜像内 `/native-manifest.json` 记录所选 native 文件及 SHA256。
部分 Qt/X11 库仍为 native 插件所依赖，不能以没有图形界面为由全部移除。
UEM/EAIOC 保留原样，策略要求的额外环境仍可能不受容器支持。

新镜像包含专有官方二进制；本项目的 MIT 许可证不授予其重新分发权。
请在自己控制的环境中构建，未确认分发授权前不要公开镜像。

## 启动

```bash
python scripts/atrust-runtime.py run --server https://你的控制器地址
```

默认入口：

- 管理界面：<http://127.0.0.1:8788>
- SOCKS5 TCP 代理：`127.0.0.1:10809`

在页面完成密码、点击验证码和短信验证，再显式点击连接。
容器不会自动恢复或连接旧账号。SOCKS 在未连接 VPN 时使用容器的普通网络，
不提供只允许 VPN 流量的 kill switch；不要将“代理可达”等同于“VPN 在线”。

```bash
curl --socks5-hostname 127.0.0.1:10809 https://内网站点/
ssh -o 'ProxyCommand=nc -X 5 -x 127.0.0.1:10809 %h %p' 用户名@内网IP
```

端口与旧 VM 模式分开，可用 `--web-port` 和 `--socks-port` 自定义。
启动脚本仅发布本机地址，不应将没有额外身份验证的管理/代理端口公开。
SOCKS 实现支持 CONNECT、代理端域名解析和 TCP 半关闭，不支持 UDP ASSOCIATE。

```bash
python scripts/atrust-runtime.py status
python scripts/atrust-runtime.py logs
python scripts/atrust-runtime.py stop
python scripts/atrust-runtime.py start
```

重建镜像后需停止并 `remove` 旧容器，再用相同的 `run --server` 命令创建；
`remove` 不删除命名卷。单纯 `start` 仍使用原容器镜像。

supervisor 为 PID1 下的受监督进程，任一必要服务退出将使容器失败退出，
健康检查反映管理服务和隔离状态，不代表控制器允许 VPN 上线。
官方日志及加密会话留在 `atrust-native-state` 命名卷中，停止/启动不会清除。
日志可能包含官方程序记录的敏感值，不应直接上传。supervisor 的标准输出只显示
服务生命周期；Web 请求体、密码与票据不打印。持久化会话的客户端身份必须一致。

## 网络与权限

容器使用独立的 pasta 网络，只传入 TUN 设备，不共享宿主机网络、PID、DBus、
Docker socket 或宿主机根目录。仅给予 NET_ADMIN、NET_BIND_SERVICE 和监督进程
切换用户、管理进程和维护私有状态权限所需的能力；不使用 `--privileged`。官方 daemon 在容器内以
root 运行，core、Web、SOCKS 以 uid1000 运行；rootless 容器 root 并非宿主机 root。
rootless 容器共享宿主机内核，隔离强度与 KVM 不同。

启动时传入宿主网络 namespace 标识，supervisor 验证实际网络空间不同后才允许
Web 建立隧道；不支持 host network。不要手动伪造该标识或挂载宿主机状态目录。
运行 `run` 所需的创建权限由 Podman 自己管理。

容器内 Unbound 将 DNS 经严格 TLS 发往 AliDNS，证书校验开启，不回退到明文 DNS，
避免从旁路网关获取 Fake-IP。网络须允许 TCP853。自定义上游可修改
`scripts/runtime/unbound.conf` 后重建。控制器内部域名解析能力需在真实连接后验证。

## 存储与构建环境

该脚本使用独立 `.runtime/containers` 和 `.runtime/volumes`，不影响旧 VM 的
`.vm` 存储。`.runtime/` 被 Git 忽略，不能打包发布。
可用以下方式将镜像缓存放在其他分区（脚本会在本地记住该路径）：

```bash
export ATRUST_RUNTIME_STORAGE=/你的缓存目录/atrust-native
```

## 验证范围

仓库测试包含 SOCKS5 的真实本地 TCP 往返、域名解析、半关闭、非法协议拒绝，
以及既有认证、加密会话、CSRF 和连接稳定性测试。
只有通过真实控制器完成 MFA、隧道上线和内网数据传输后，才能声称某个部署
可替代旧 VM。不能以健康检查或合成认证测试代替此验证。

## 本次验证与可迁移镜像

2026-11-12 在本机 rootless Podman 中实测：冷启动和停止/启动成功，官方 core
RPC 返回正常，HTTP 返回未登录状态，镜像中不存在 Electron 可执行文件，
容器网络 namespace 与宿主不同；Unbound 严格 DoT 解析与控制器 HTTPS
`authConfig` 获取成功，经过新 SOCKS 访问公网返回 HTTP200。
宿主路由与规则保持一致（IPv6 RA 路由的 expires 倒计时不作为结构变动）。
55 项后端测试通过。随后用户在新容器完成真实 MFA，实际 native 状态为 online /
tunnelAvailable，并已创建 utun7，core RPC 和容器健康检查正常。内网数据
传输仍待目标地址验收，不能仅凭创建 TUN 接口认定内网访问通过。

本机已导出 `.runtime/atrust-native.docker.tar.gz`（约285MiB），包含官方 native
组件，供你控制的环境内迁移。它不是可公开分发的纯源码镜像。目标服务器可：

```bash
python scripts/atrust-runtime.py load --archive /路径/atrust-native.docker.tar.gz
python scripts/atrust-runtime.py run --server https://你的控制器地址
```

本次由于项目分区空间不足，构建缓存位于 `/tmp/atrust-native-podman-1000`，
路径记录在被 Git 忽略的 `.runtime/storage-path`。这份缓存会随主机重启清除；
镜像归档和状态卷保存在项目分区。缓存消失后需先 load，再重新创建容器。
新部署应将 `ATRUST_RUNTIME_STORAGE` 指向空间充足的持久化分区。

## 内网 SSH 验收

提供一个你有权限测试的内网 SSH 地址，可以执行：

```bash
python scripts/runtime/check-connection.py --ssh 你的内网IP:22
```

检查管理服务的隔离/在线状态，再通过本机 SOCKS5 接收 SSH 协议标识。
不提交 SSH 用户名、密钥或密码，不登录或运行远程命令。没有 `--ssh` 时只检查
隧道状态并返回退出码2，明确表示内网传输未验收；不会将在线状态当作数据测试。

## ARM64 原生构建

已从官方 CDN 获取同版本 ARM64 安装包，并验证 deb 的 Architecture=arm64，
主 agent 与 xtunnel 的 ELF e_machine 均为183（AArch64），没有使用 x86 模拟。
官方下载导航：<https://atrustcdn.sangfor.com/tools/clientVersion/index.html>。

在 ARM64 Linux 主机执行：

```bash
curl -fL https://atrustcdn.sangfor.com/standard/linux/2.5.16.30/uos/arm64/aTrustInstaller_arm64.deb -o /tmp/atrust-arm64.deb
echo '2e9545079243bb8e01d895f89cbdd3b52e8094200457b71047b3b6ef92c316f2  /tmp/atrust-arm64.deb' | sha256sum -c -
python scripts/atrust-runtime.py build --deb /tmp/atrust-arm64.deb
python scripts/atrust-runtime.py run --server https://你的控制器地址
```

构建会按主机选择 `linux/amd64` 或 `linux/arm64`，并同时核对 deb 元数据与
两个关键 ELF 的实际架构，拒绝把 x86 包误标为 ARM 镜像。基础环境补充了
ARM native 插件需要的 Wayland/EGL 系统库。默认构建使用 Podman；
`build --engine docker` 可使用本机 Docker 构建，但运行脚本仍使用 rootless Podman。
不在本机自动注册 binfmt，也不在 x86 主机上伪装成功完成 ARM 原生验证。

`.github/workflows/native-arm64.yml` 使用 GitHub 的原生 `ubuntu-24.04-arm`
runner，手动触发后下载经过 SHA256 固定的官方包、构建 ARM 镜像，并在独立
Docker 网络验证后台服务、RPC、HTTP、健康检查及 SOCKS5 协商。只有显式选择
publish 且确认目标 GHCR 包已存在并为私有时，才推送 `atrust-native:arm64`。
工作流要求事先用账号拥有者的认证创建私有包、连接本仓库，并保留不含官方组件
的 `package-init` 标签，并在包设置的 Manage Actions access 中授予本仓库写权限。发布前先验证该标签可认证读取、匿名读取被拒绝，
拒绝向未初始化或公开的包上传官方二进制，不能依赖首次推送的默认可见性。
CI 没有用户凭据，不验证真实 MFA、控制器访问策略或内网数据传输；
这些仍需在操作者自己的 ARM64 主机完成。

若不授予 CI 包权限，可以传入 `transfer_certificate` 公共 X.509 证书，由 CI
导出经过 CMS 加密的镜像归档。私钥只保留在操作者本机，CI 不接收私钥；
公共仓库中只上传密文 artifact，保留1天。操作者下载、解密并导入镜像后，
使用自己的本机 registry 登录推送。没有证书时不导出镜像 artifact。
