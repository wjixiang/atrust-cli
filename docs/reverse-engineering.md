# Sangfor aTrust 2.5.16.30 (Linux/UOS) 逆向分析报告

分析对象：`aTrustInstaller_amd64.deb`（`cn.com.sangfor.atrust` 2.5.16.30,
UOS 构建, 203 MB, sha256 `aa8ba935…70b75a6`）
方法：完全静态分析 —— ar/tar 解包、脚本与 JS 审读、Ghidra 12 headless 反编译
（JDK 27）、readelf/strings 符号分析。**未执行任何被分析二进制。**

---

## 1. 包结构

| 路径 | 内容 |
|---|---|
| `/usr/share/sangfor/aTrust/` | 主程序（Electron 9.0.2 托盘 + 原生组件） |
| `/usr/share/sangfor/aTrust/resources/bin/` | 特权二进制与库（root 侧） |
| `/usr/share/sangfor/aTrust/resources/app/` | Electron 应用（**JS 未加 asar、未强混淆**） |
| `/usr/share/sangfor/aTrust/resources/shell/` | 启动脚本、EAIOC 组件包、UEM.zip |
| `/usr/lib/systemd/system/` | `aTrustDaemon.service`、`aTrustShell.service`、`aTrustTray@.service` |
| `/usr/lib/systemd/user/` | `aTrustTray.service`、`aTrustShell.service` |
| `/opt/apps/cn.com.sangfor.atrust/` | UOS 应用商店条目 |
| control 脚本 | preinst/postinst/prerm/postrm + uem_* 系列 + SdpProgress（ELF） |

- deb 带 `sign` 成员：`signed by 深信服科技股份有限公司… 2025-11-25`
- `resources/sangfor2024.crt` 是 **UOS 应用商店签名证书**（UOS APP Signing CA 签发），
  并非 TLS 根证书。

## 2. 进程/服务架构

```
systemd
 └─ aTrustDaemon.service (root)
     └─ shell/aTrustDaemon.sh
         └─ aTrustAgent --plugin plugin-daemon --plugin-cmd |   ← root 守护进程
             ├─ 插件目录 plugins/aTrustCore/  (libaTrustCore.so 19.5MB,
             │   libUemPlugin.so, libaTrustAuth/Auth/Update/Storage/CaService/
             │   EnvReportor/LoggerUpload/GMAuth.so, libEAIOSDKWrapper.so …)
             ├─ 插件目录 plugin-daemon/aTrustDaemon/ (libaTrustDaemon.so,
             │   libaTrustPromote.so, libaTrustSSLProxy.so)
             └─ 派生 aTrustXtunnel-64 (26MB, Go) ← VPN 隧道引擎

用户会话
 └─ aTrustTray (Electron 9.0.2, Chromium 83)  ← 桌面托盘/登录 UI
     ├─ src/plugins/aTrustSSLProxy.node        ← 本地 GM MITM 代理
     └─ aTrustTray2 (Qt 托盘)
```

- `aTrustDaemon.service`：`Restart=always`、`RestartSec=5s`、
  `RestartForceExitStatus=SIGKILL SIGSEGV …`（被 kill -9 也会被拉起）。
- `aTrustTray@.service` 按用户模板化（多用户支持）。

## 3. 本地 RPC（本 CLI 的基础）

- 传输：**Thrift TBinaryProtocol over unix socket**
  （nodejs thrift 包默认的 TBufferedTransport 组合）
- 管道目录：`/usr/share/sangfor/.aTrust/var/run/`（目录 0777）：
  - `aTrustCore-fcd60898-…` / `aTrustDaemon-8ec18c00-…` /
    `aTrustTunnel-c46a26c5-…` / `aTrustQtTray-8c34…` / `aTrustDiagnosisTool-…`
- 服务与方法（IDL 完整暴露于 `resources/app/src/service/thrift/*.js`）：
  - **SdpCoreService**：`GetStatus`/`GetAllStatus`（返回 `map<string,string>`）、
    `GetSpaInfo(url)`、`GetSdpConfig`、`QuerySpaSeedExist(url)`、`SetSpaSeed`、
    `Logout(type:string, localSendLogoutEvent:bool)`、`Offline`、
    `RefreshClientConfig`、`QueryAddrAllowedToSwitch`、`QueryAntiUninstallMainAddr`、
    `IsRpcStatusNormal`
  - **SdpDaemonService**：`RegisterMonitor`/`UnRegisterMonitor`/`GetMonitorList`
  - 另有 SdpCSApplication / SdpDiagnosisService / SdpPromoteService / SdpBroadcast
- 状态枚举：`Status {OFFLINE=0, BINDING=1, RECOVERING=2, ONLINE=3}`

## 4. SPA（单包授权）敲门 — libudpKnock.so

命名空间 `sangfor::udpKnock` / `sangfor::spa`，反编译确认
`UdpSpaPackageV1/V2::generateSpaData` 的构造：

```
明文 = timestamp || nonce || seed || extdata      （seed 由控制器登录后下发）
密文 = SM4-CBC(明文, key, 随机IV)                  （EVP_sm4_cbc, PKCS7 填充）
包   = 头部/身份字段 ‖ 密文 ‖ SM3(前面全部字节)     （EVP_sm3 摘要追加）
```

- 相关函数：`generateSpaData`、`sendUdpKnockPackage`、`knockDoor(Private)`、
  `KnockDoorImmediately`、`isTimeToKnockDoor`、`aes_encrypt/decrypt_cookie`
  （AES-CBC 备用路径）、CityHash64/128。
- `getKnockDataProviderFunc` 由 core 插件注入种子 → 未登录前无法敲门。

## 5. 本地 SSL“GM 代理”（MITM）— aTrustSSLProxy.node

- 类：`SSLProxyManager`（单例，随机本地端口）、`MITMProxyImpl(SSL_CTX*, SSL_CTX*)`
  （**双上下文 = 客户端侧/上游侧**）、`SSLSession::proxy_to_upstream/downstream`。
- 反编译要点（`SSLContext::prepare`，Ghidra）：
  - **`SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL)`** — 对上游服务器证书
    完全不校验；
  - 证书+私钥经 `set_key_and_cert_from_mem` 从内存 PEM 装入（客户端侧）。
- Electron 主进程 `main.js`：把整个 session 的代理设为
  `127.0.0.1:<proxyPort>`（bypass 仅 `127.0.0.1,localhost,localhost.sangfor.com.cn`），
  且追加命令行 `--ignore-certificate-errors`。
- 作用：为托盘内嵌网页提供国密（SM2/SM3/SM4, GMTLS）兼容通道；
  Kylin V10 / Ubuntu 16 下禁用。

## 6. 网络栈 — aTrustXtunnel-64（Go, 未 strip pclntab）

符号/字符串证据：`datacenter.SdpcVersionDataCapacitiesQuickSocks5`、
`fakeip:%s to realip failed`、`enable vnic forward failed`、`ignore conntrack dump data`、
`cannot marshal DNS message`（内嵌 DNS 解析器）、k8s apimachinery 依赖（仅作数据结构库）。
即：**SOCKS5 + FakeIP/DNS 重定向 + conntrack 感知**的用户态隧道，
配合 iptables（见下）而非内核模块。

## 7. 系统改动与加固行为（安装/运行期）

- **iptables**（preinst/prerm 中维护）：nat 表 `ATRUST_DNS`（DNS 劫持/重定向）、
  filter 表 `ATRUST_BLOCK_DNS`、ipv6 mangle/nat `ATRUST_DNS`。
- **root 命令执行通道**（libaTrustDaemon.so 内嵌，值得警惕）：
  ```bash
  echo -n 'SHELL_CMD=dpkg -i /tmp/sangfor/aTrust/download/aTrustInstaller_amd64.deb' \
    > /tmp/aTrustShell_root.conf
  systemctl start aTrustShell        # Type=oneshot, /bin/bash -c "${SHELL_CMD}"
  ```
  systemd 单元从 `/tmp/aTrustShell_root.conf` 读取要执行的命令；
  `/tmp` 全局可写 ⇒ 存在竞争/预置文件利用面（实际可利用性取决于目标系统
  polkit 对 `systemctl start` 的授权策略）。
- 安装时强杀进程：`killall -9 aTrustAgent/aTrustXtunnel-64/aTrustTray2`，
  `environment_check` 可 `kill -9` Firefox（当前版本该调用被注释）。
- 共享目录 `/usr/share/sangfor/.aTrust` chmod **777**。
- EAIOC：Ubuntu 上经 `eaio_packman` 安装 AIO 组件（eaio_base/sys/ui/service/…）。
- UEM：`uem/UEM.zip`（51MB）+ Java 组件（`uem_service/uem_tray/jar`，
  需 `java-runtime`）；UEM.json 记录分支 `SP_aTrust_2516CL_03`。

## 8. 客户端自保护（Electron 侧）

- 拒绝 `--inspect` / `--remote-debugging-port` 启动（除非放行标志文件存在）。
- `<exe>/../.protect` 存在时，退出需父进程通过 Sangfor 签名校验
  （`allowStop()`，Windows CCPlugin 完整实现）。
- 隐藏快捷键：`Ctrl+Alt+Shift+Space+P` 开 DevTools；
  `Ctrl+Alt+Shift+Space+U` UEM 调试器（Windows）。
- 反钓鱼弹窗、禁止卸载窗口（`TRAY_FORBIDDEN_UNINSTALL`）。

## 9. 与本 CLI 相关的结论

| 需求 | 途径 |
|---|---|
| 状态查询 | `aTrustCore-*` pipe → `GetStatus/GetAllStatus` |
| 注销 | `Logout("normal", true)` |
| SPA 状态 | `QuerySpaSeedExist(url)` / `GetSpaInfo(url)` |
| 配置 | `GetSdpConfig` |
| 服务控制 | systemd `aTrustDaemon` |

## 10. 遗留问题 / 未验证

- 隧道协议细节（QuickSocks5 线格式、与控制器的 SDPC API）——未深入。
- `aTrustTunnel-*`、`SdpCSApplication` 服务的完整方法表未全部枚举。
- SdpProgress（安装进度小工具）与 eaio_packman 未分析。
- 所有结论均来自静态分析；未在运行环境验证 RPC 行为（CLI 的实测以用户
  机器上的实际输出为准）。

— 报告完 —
