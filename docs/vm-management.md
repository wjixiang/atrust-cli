# 隔离虚拟机与 Web 管理

该设备采用两层结构：容器仅运行 QEMU，完整的官方 aTrust 后台和 Web
管理服务运行在独立的 Ubuntu 22.04 KVM 虚拟机中。aTrust 的路由、DNS、
防火墙改动留在客机；不将宿主机 `/etc`、网络管理接口或 Docker socket
交给 aTrust，不使用特权容器。

## 本机入口

- Web 管理：<http://127.0.0.1:8787>
- SSH：`python scripts/atrust-vm.py ssh`
- 应用 SOCKS5：`127.0.0.1:10808`（运行 `proxy` 后提供）

Web 页面支持密码认证、按顺序点击三个字符、刷新验证码、短信发送倒计时、
短信验证码填写、会话恢复、清除本地会话，以及显式连接/断开 VPN。
密码只在待完成验证码的进程内存中短暂保留，最长 5 分钟；不写入镜像、
磁盘或浏览器存储。短信码不保存。Cookie 和票据使用单独的随机密钥加密保存。

认证结束后不会自动连接隧道。只有点击“连接 VPN”才初始化客机的官方 core
并启动隧道。“断开 VPN”调用官方后台的 Offline 接口，不主动执行服务器注销。
会话是否仍有效由控制器决定；清除本地文件不等于服务器端注销。

管理 API 使用同源校验、Host 白名单、CSRF token、受限请求大小与禁止缓存响应。
页面默认只允许通过 `127.0.0.1`/`localhost` 访问。本地地址可被同机其他账户
访问；不要将端口公开到局域网。通过 SSH 远程管理时，先转发到操作者本机。
该版本面向单用户本机管理，不提供互联网登录入口或多租户权限模型。

## 首次部署

需要 Linux x86_64、普通用户可读写的 `/dev/kvm`、rootless Podman、OpenSSH
客户端以及 Python 3.11+。宿主机不需要安装 QEMU/libvirt，也不需要宿主机 sudo。
脚本使用独立的 Podman 存储目录，不依赖用户已有的容器存储配置。

```bash
python scripts/atrust-vm.py prepare
python scripts/atrust-vm.py start
python scripts/atrust-vm.py install --deb /绝对路径/atrust-2.5.16.30.deb
python scripts/atrust-vm.py proxy
```

默认资源：2 vCPU、3 GiB 内存、24 GiB 稀疏磁盘。下载的官方 Ubuntu cloud
image 按同站点 HTTPS 提供的 SHA256SUMS 校验。镜像和全部运行状态保存在
被 Git 忽略的 `.vm/` 中，包含 SSH 私钥和可能存在的会话密钥，不要分享该目录。
运行状态保存在独立的客机磁盘中，重建 OCI 镜像不会清除它。

`install` 将官方 deb 的原始文件解包到客机，并配置 daemon、无头 user core、
Web 服务。它不运行桌面安装器的杀浏览器、托盘启动和安装包文件名处理钩子。
客户端运行库兼容处理沿用本项目已有的 Arch 打包方式；程序的登录、MFA、
设备/访问检查仍由真实控制器完成。官方 deb 不复制到 OCI 镜像中，需由操作者
提供本地文件，也不在此项目中重新分发。

客机使用 AliDNS 的 DNS-over-TLS（严格模式，无明文外部 DNS 回退），
避免从旁路网关获得 Fake-IP；首次启动便应用该设置。若网络阻断 TCP 853，
需要在客机内调整加密 DNS 上游，不能仅修改宿主机 DNS。

## 日常使用

1. 打开本机 Web 管理地址，输入账号密码。
2. 按图像底部提示点击三个字符，位置按原始图片 272×192 转换；可撤销、
   清空或换图，也可在展开的坐标输入中手工填写。
3. 如果要求短信验证，点击发送并填写收到的验证码。验证失败会保留待完成步骤。
4. 显示“认证完成”后，按需点击“连接 VPN”。
5. 将需要访问内网的应用配置为 `SOCKS5 127.0.0.1:10808`，并开启代理端解析
   域名；其他应用继续使用宿主机原网络。

例如：

```bash
curl --socks5-hostname 127.0.0.1:10808 https://内网站点域名/
```

SOCKS 入口由 SSH 动态转发提供，转发到客机的 TCP 栈；它不是 aTrust 自带的
公共 SOCKS 服务。隧道未连接时，代理使用客机的普通网络。不同资源是否允许
访问仍受学校/组织策略控制。

```bash
python scripts/atrust-vm.py status   # 容器/虚拟机运行状态
python scripts/atrust-vm.py stop     # 关闭代理并停止虚拟机
python scripts/atrust-vm.py start
python scripts/atrust-vm.py proxy    # 启动后重新打开本地应用代理
python scripts/atrust-vm.py sync     # 更新客机内的 Python/Web 源码
```

## 自定义 OCI 镜像

镜像定义为 `scripts/vm/Containerfile`，构建上下文为项目根目录。
`.dockerignore` 只允许应用源码和 VM 脚本进入上下文，排除运行磁盘、密钥、
会话文件及 Git 历史。镜像包含 QEMU、源码、Web 资源及客机安装脚本。

`prepare` 自动构建 `localhost/atrust-manager:latest`。直接构建可用：

```bash
podman build -t localhost/atrust-manager:latest -f scripts/vm/Containerfile .
```

本机部署脚本为避免已有损坏的 Podman graphroot，使用 `.vm/containers`
和专用 runroot；普通 `podman images` 不一定显示它。可通过脚本 `status`
检查当前实例。

镜像默认入口可启动已经初始化的 `/vm` 磁盘；首次仍需运行上述 prepare/install。
这避免将用户会话、官方安装包或预设密码烘焙进可分发镜像。
容器使用 host network 只是为了让 QEMU 的 **loopback hostfwd** 端口直接可用，
同时移除所有 capabilities。官方 aTrust 不在这个网络命名空间中运行，
客机也没有宿主机文件系统共享。

## 开发验证

```bash
uv run pytest -q
uv run --with playwright python scripts/vm/check-ui.py
```

浏览器测试使用本机 Chromium，拦截所有认证 API 为合成数据；覆盖三点坐标、
短信倒计时、认证与隧道分离、连接/断开控件和手机布局，不会提交真实凭据。
后端测试覆盖状态转换、密码生命周期、会话加密、Host/Origin/CSRF 拒绝及
禁止在宿主机调用连接接口。

仅测试认证界面时也可以运行 `uv run atrust-web --port 8788`。
普通宿主机缺少客机标记文件，即使传入 `--allow-tunnel` 也不会允许建立隧道。

参考：[QEMU user networking](https://www.qemu.org/docs/master/system/devices/net.html)、
[Ubuntu cloud image](https://cloud-images.ubuntu.com/jammy/current/)。
