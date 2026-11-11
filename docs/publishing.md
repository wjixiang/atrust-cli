# 发布到 GitHub

仓库同时包含 CLI、Web 管理界面、VM 部署脚本和 OCI 镜像构建定义。
本项目源码采用 MIT 许可证；官方 aTrust 安装包不属于本许可证范围，也不随仓库或
OCI 镜像重新分发。使用者需自行提供兼容的官方安装包。

## 发布内容

提交源码、测试与文档。`.vm/` 是本地运行目录，含磁盘、SSH 私钥和可能存在的
认证会话，不应提交、打包或上传为 GitHub Release 附件。验证码截图、网络诊断
输出及凭据缓存同样不应上传。`.dockerignore` 使用白名单约束镜像构建上下文。

镜像构建与部署说明见 [VM 管理](vm-management.md)。可分发的是由
`scripts/vm/Containerfile` 构建的干净 OCI 镜像，不能分发使用后的客机磁盘。

## 创建远程仓库并推送

在 GitHub 创建空仓库，不添加 README、许可证或 .gitignore，然后执行：

```bash
git remote add origin git@github.com:YOUR_ACCOUNT/atrust-cli.git
git push -u origin main
```

也可以使用已经登录的 GitHub CLI（自行选择可见性）：

```bash
gh repo create atrust-cli --private --source=. --remote=origin --push
```

## 检查与限制

```bash
uv run pytest -q
git diff --check
git status --short
```

GitHub Actions 在 Python 3.10 和 3.12 上运行后端测试，不访问真实控制器。
浏览器合成测试需另行安装 Chromium，运行方式见 VM 管理文档。
真实 MFA 与隧道稳定性不由这些测试证明；Web 会话交接仍为实验性功能。
