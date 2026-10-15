# 新电脑开发环境恢复与版本发布

本指南适用于重装或更换本地开发电脑后，继续维护原仓库 `Elegying/AnyTLS_Panel`。源码、依赖锁和 GitHub Actions 工作流可以重新拉取；旧电脑的虚拟环境、构建产物和缓存不需要保留。

能从 GitHub 恢复的是已推送的内容；未推送提交、未提交修改和本地数据需要从自己的备份恢复。

前提是原 GitHub 仓库和生产服务器仍然保留。GitHub 仓库变量与 Secrets 不会随本地重装消失，也不会被 `git clone` 下载。若重装的是面板服务器，应先按[运维手册](OPERATIONS.md#更新)恢复数据库、运行密钥和部署配置。

按顺序完成第 1–4 节即可恢复本地开发。只有准备发布新版本时，才执行第 5–8 节；推送正式版本标签会触发发布，已配置生产目标时还会更新服务器。

## 1. 安装本地工具

本地使用 Python 3.12 或 3.13，与 [CI](../.github/workflows/ci.yml) 的测试版本一致。以下命令统一使用 Python 3.12。需要访问 GitHub、Python 包索引及所用系统的软件源。

### macOS

未安装 Xcode 命令行工具时，执行并等待系统安装窗口完成：

```bash
xcode-select --install
```

按 [Homebrew 官方安装说明](https://docs.brew.sh/Installation)安装 Homebrew，并执行安装器最后显示的 shell 环境配置命令。重新打开终端，确认 `brew --version` 可用后安装工具：

```bash
brew install git gh python@3.12 shellcheck actionlint
python3.12 --version
make --version
```

### Ubuntu 24.04 或 Windows 的 WSL 2

Windows 用户先按 [Microsoft WSL 安装说明](https://learn.microsoft.com/windows/wsl/install)，在管理员 PowerShell 中安装 Ubuntu 24.04：

```powershell
wsl --install -d Ubuntu-24.04
```

按提示重启并完成 Linux 用户初始化。此后的命令都在 Ubuntu 终端执行，代码也保存在 Linux 用户目录中；不要把 Bash 命令直接粘贴到 PowerShell。

Ubuntu 24.04 中执行：

```bash
sudo apt-get update
sudo apt-get install -y git gh python3.12 python3.12-venv make shellcheck
```

需要在 Linux 本地检查工作流语法时，可另按 [actionlint 官方说明](https://github.com/rhysd/actionlint/blob/main/docs/install.md)安装该工具。`make check` 在找不到 actionlint 时会明确提示跳过这一项。

## 2. 恢复 GitHub 授权并克隆原仓库

下面采用 HTTPS 和 GitHub CLI 的浏览器授权流程，不需要恢复旧电脑的 GitHub SSH 私钥。使用对原仓库有写权限的账号；只有在浏览器中登录 GitHub，并不会自动授权终端中的 Git。

```bash
gh auth login --hostname github.com --git-protocol https --web
gh auth setup-git --hostname github.com
gh auth status
git clone https://github.com/Elegying/AnyTLS_Panel.git
cd AnyTLS_Panel
git fetch origin --tags
git status --short --branch
```

授权行为见 [gh auth login](https://cli.github.com/manual/gh_auth_login) 和 [gh auth setup-git](https://cli.github.com/manual/gh_auth_setup-git)。不要把 Token 写进克隆地址、脚本或文档。若项目已经克隆，进入原目录检查 `git status` 和 `git remote -v`，确认远端为上述仓库后再同步；保留已有未提交内容，不通过重置或清理命令解决分歧。

将以下占位值替换成自己的提交身份；邮箱可使用 GitHub 邮箱设置页提供的 noreply 地址。配置只作用于当前仓库：

```bash
git config --local user.name "你的提交名称"
git config --local user.email "你在 GitHub 使用的提交邮箱"
gh repo view Elegying/AnyTLS_Panel --json viewerPermission,defaultBranchRef
```

确认默认分支为 `main`，且账号具有写入或维护权限。克隆到 fork 或新建同名仓库不会继承原仓库的 Secrets、服务器授权或签名身份，应继续使用原仓库。

## 3. 重建虚拟环境并验证

在项目根目录执行：

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python --version
python -m pip install --require-hashes -r requirements-dev.txt
make check
```

应看到 Python 3.12，并且依赖安装与 `make check` 均成功。后者统一运行语法检查、单元测试、80% 分支覆盖率门禁、Shell 检查、安全扫描和依赖漏洞审计，具体项目以 [Makefile](../Makefile) 为准。依赖哈希不匹配或审计失败时先定位原因，不删除 `--require-hashes`，也不跳过失败项继续发布。

不需要复制旧电脑的 `.venv`、`venv`、`build`、`dist` 或 Python 缓存。重新安装依赖后可以再生成这些内容。不要为了恢复开发环境在个人电脑运行 `deploy.sh`、`install-release.sh` 或 `tests/ubuntu24_*.sh`；完整生产部署与回滚测试由隔离的 Ubuntu CI 执行。

## 4. 启动本地面板

```bash
./start.sh
```

访问 `http://127.0.0.1:8866`，默认用户名为 `admin`。首次密码保存在数据库旁的 `.initial_admin_password` 文件，只在本机查看，不提交到 Git；按 `Ctrl+C` 停止服务。需要继续以前的本地测试数据时，从自己的备份恢复，源码仓库不会包含旧数据库或运行密钥。

重新打开终端后，进入项目目录并执行 `. .venv/bin/activate` 即可继续开发。运行 `git status --short` 检查源码状态；没有输出表示没有待提交内容，忽略的本地数据和缓存另由 `.gitignore` 管理。

## 5. 核对发布与生产部署条件

发布由 [.github/workflows/release.yml](../.github/workflows/release.yml)执行：构建源码归档、生成 SHA-256、通过 GitHub OIDC 签名、创建草稿 Release；配置生产目标后，再部署并验证公网入口，最后公开 Release。签名不依赖本地长期私钥，发布资产也不需要在电脑上预先构建。

只查看云端配置名称，不输出密钥或变量值：

```bash
gh variable list --repo Elegying/AnyTLS_Panel --json name
gh secret list --repo Elegying/AnyTLS_Panel --json name
```

| 位置 | 必要名称 | 用途 |
| --- | --- | --- |
| 仓库 Variables | `PROD_HOST`、`PROD_USER`、`PROD_URL` | 服务器地址、部署账号与 HTTPS 根地址 |
| 仓库 Secrets | `PROD_SSH_PRIVATE_KEY`、`PROD_SSH_KNOWN_HOSTS` | Actions 专用部署私钥与已核验的服务器公钥记录 |
| 生产服务器 | 部署账号、对应 SSH 公钥、受限 sudo 授权和 `/usr/local/sbin/deploy-anytls-panel` | 接收并验证 CI 上传的归档、校验文件和签名，再部署指定标签 |

这些名称存在只能证明配置项已保存，不能证明密钥仍有效或服务器当前可达。也可在仓库的 Settings → Secrets and variables → Actions 中核对配置。沿用现有配置，具体职责见[维护者自动发布与部署](OPERATIONS.md#维护者自动发布与部署)。查看 Secrets 时若权限不足，应由有权限的维护者核对，不能据此认定配置丢失。

`PROD_HOST` 为空时，工作流会跳过生产部署与公网验证，但仍可发布 Release。需要自动更新服务器时，确认上述配置完整且目标正确。不要在新电脑重新创建或覆盖部署密钥来“恢复环境”；手动 SSH 运维所需的个人密钥应单独恢复或重新授权，GitHub Secrets 不提供原私钥下载。

## 6. 准备版本提交并通过 PR 合并

先确认当前工作区没有待保存修改，再同步主分支并创建准备分支。重复发布时使用未占用的分支名：

```bash
git switch main
git pull --ff-only origin main
git fetch origin --tags
git switch -c chore/prepare-release
gh release list --repo Elegying/AnyTLS_Panel --limit 10
```

选择尚未使用、符合语义化版本规则的新版本号，并一起修改：

1. `VERSION`：只写 `X.Y.Z`，不带 `v`。
2. `CHANGELOG.md`：把本次待发布内容从 `Unreleased` 移到 `## [X.Y.Z] - YYYY-MM-DD`，填写真实发布日期并保留 `Unreleased` 入口。对应版本段落必须非空。
3. `deploy.sh`：将默认 `ANYTLS_REPO_REF` 同步为 `vX.Y.Z`。
4. `README.md`、`docs/QUICKSTART.md`、`docs/OPERATIONS.md`、`docs/CONFIGURATION.md`：同步当前版本、安装地址和更新命令中的版本号，保留有历史意义的旧版说明。

`X.Y.Z` 是占位格式，必须替换成具体数字。不要只改 `VERSION`：仓库测试会检查它与部署默认值和文档是否一致。新增生产文件时同时维护 `release-files.txt`，细节见[贡献指南](../CONTRIBUTING.md)。

```bash
make check
git diff --check
git diff
git add VERSION CHANGELOG.md deploy.sh README.md \
  docs/QUICKSTART.md docs/OPERATIONS.md docs/CONFIGURATION.md
git diff --cached
git commit -m "chore: prepare next release"
git push -u origin HEAD
gh pr create --repo Elegying/AnyTLS_Panel --base main --fill
gh pr checks --repo Elegying/AnyTLS_Panel --watch --interval 15
```

如果还有本次需要发布的其他修改，审阅后单独暂存，避免混入数据库、密钥或临时文件。按仓库规则完成审查、解决失败检查，再在 GitHub 合并 PR；有合并权限时也可在该分支执行 `gh pr merge --repo Elegying/AnyTLS_Panel --squash`。`main` 受保护，不使用强推或管理员绕过规则。

PR 合并后还要等待合并提交对应的 `main` **push CI**。PR 的 CI、其他提交的 CI 或手动触发的 CI 均不能替代发布工作流要求的这条记录。

## 7. 等待 main 的 CI 并推送正式标签

下面代码块在项目根目录执行。它会核对干净工作区、主分支、未使用的版本标签和同一提交的 push CI，最后推送一个标签。**推送标签是正式发布动作；已配置生产目标时会自动更新服务器。**

```bash
bash <<'BASH'
set -euo pipefail
release_repo='Elegying/AnyTLS_Panel'
[[ -z "$(git status --porcelain)" ]] || { echo '请先保存并提交本地修改'; exit 1; }
git switch main
git pull --ff-only origin main
git fetch origin --tags
release_commit="$(git rev-parse HEAD)"
[[ "$release_commit" == "$(git rev-parse origin/main)" ]] || {
  echo '本地 main 与远端不一致'; exit 1;
}
release_tag="v$(cat VERSION)"
[[ "$release_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  echo 'VERSION 格式错误'; exit 1;
}
if git show-ref --verify --quiet "refs/tags/$release_tag"; then
  echo '版本标签已存在，请核对版本号；不要覆盖旧标签'; exit 1
fi
release_ci_id="$(gh run list --repo "$release_repo" --workflow ci.yml \
  --branch main --event push --commit "$release_commit" --limit 1 \
  --json databaseId --jq '.[0].databaseId // empty')"
[[ -n "$release_ci_id" ]] || { echo '尚未发现 main push CI，请稍后重试'; exit 1; }
gh run watch "$release_ci_id" --repo "$release_repo" --exit-status --interval 15
[[ "$(gh run view "$release_ci_id" --repo "$release_repo" \
  --json conclusion --jq .conclusion)" == 'success' ]]
git fetch origin main
[[ "$release_commit" == "$(git rev-parse origin/main)" ]] || {
  echo '等待期间 main 已更新，请重新同步并核对待发布内容'; exit 1;
}
git tag -a "$release_tag" "$release_commit" -m "AnyTLS Panel $release_tag"
git push origin "refs/tags/$release_tag"
BASH
```

只推本次标签，不使用 `git push --tags` 批量发布，也不移动或重用已发布标签。标签与 `VERSION`、远端 `main`、成功 push CI 的提交必须一致，工作流会再次核对这些条件。

## 8. 确认发布结果与处理失败

在同一项目目录查询本次标签的发布记录：

```bash
release_tag="v$(cat VERSION)"
gh run list --repo Elegying/AnyTLS_Panel --workflow release.yml \
  --branch "$release_tag" --event push --limit 5 \
  --json databaseId,headSha,status,conclusion,url
```

首次查询为空时等待片刻再查。把下面占位值替换成对应记录的数字 ID，等待完成并核对步骤结果：

```bash
gh run watch 这里替换为发布运行ID --repo Elegying/AnyTLS_Panel --exit-status --interval 15
gh run view 这里替换为发布运行ID --repo Elegying/AnyTLS_Panel \
  --json conclusion,jobs,url
gh release view "v$(cat VERSION)" --repo Elegying/AnyTLS_Panel \
  --json tagName,isDraft,isPrerelease,assets,url
```

确认 Release 已公开（`isDraft: false`、`isPrerelease: false`），且包含同版本的 `.tar.gz`、`.tar.gz.sha256`、`.tar.gz.sigstore.json` 三份资产。自动更新服务器时，`Deploy the tagged release to production` 和 `Verify the public production endpoint` 必须为 `success`，不能是 `skipped`。再登录面板核对版本、账号与订阅功能；工作流中的入口检查不能代替业务验收。

| 情况 | 处理方式 |
| --- | --- |
| 命令提示未登录或没有权限 | 重新核对 `gh auth status`、Git 远端与账号权限；修改工作流文件时还需相应 workflow 授权 |
| PR 检查失败 | 修复后推送到准备分支，等待新检查；不要跳过保护规则 |
| main push CI 失败或 main 已前进 | 确认待发布内容，修复并重新等待对应提交的 CI；此时不创建标签 |
| 推送标签时网络中断 | 先用 `git ls-remote --tags origin "refs/tags/$release_tag"` 和 Actions 记录确认是否已推送成功；远端确实没有标签时，重新核对本地标签指向的提交、远端 main 和成功 CI，再单独重试 `git push origin "refs/tags/$release_tag"`，不要覆盖或删除已存在的远端标签 |
| Release 在创建草稿后失败 | 工作流可能保留已有草稿，直接重跑可能被“Release 已存在”阻止；先核对失败步骤、已上传资产和服务器版本，由维护者处理草稿后再决定重试或发布新版本，不手工把未验证草稿公开 |
| 部署或公网检查失败 | 查看对应步骤日志，核对服务当前版本；必要时按[运维手册](OPERATIONS.md#更新)验证备份并回滚，不能把 Release 创建成功当作服务器更新成功 |

重新拉取源码只更新本地文件。面板的“检查更新”也只查询公开正式版本，实际更新仍通过上述发布部署流程，或由管理员在服务器执行[固定版本更新](OPERATIONS.md#更新)。
