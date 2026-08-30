# 贡献指南

感谢你帮助改进 AnyTLS Panel。文档、测试、错误报告和代码都属于有价值的贡献。

## 提交之前

- 普通问题先搜索现有 Issue，避免重复；
- 安全漏洞不要创建公开 Issue，请按[安全策略](SECURITY.md)私下报告；
- 大规模重构、数据库结构变化或部署模型变化，建议先开功能请求说明目标和兼容方案；
- Pull Request 应聚焦一个主题，不混入无关格式化或重命名。

## 本地环境

推荐使用 Python 3.12 或 3.13：

```bash
git clone https://github.com/Elegying/AnyTLS_Panel.git
cd AnyTLS_Panel
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements-dev.txt
```

启动本地面板：

```bash
./start.sh
```

默认监听 `127.0.0.1:8866`。开发服务器不能直接暴露到公网。

## 修改原则

- 优先使用简单、可审计的实现，不为了抽象而抽象；
- 用户界面和文档使用清晰中文，首次出现的专业术语要解释；
- API 字段保持向后兼容；确需破坏性变化时必须提供迁移路径；
- 数据库变化只能通过 `db_migrations.py` 增加新版本迁移，不能假设全新数据库；
- 新的生产文件必须加入 `release-files.txt`，并补充相应测试；
- 新环境变量必须同步更新部署脚本、systemd 模板、[配置参考](docs/CONFIGURATION.md)和测试；
- 不得在日志、测试夹具、截图或提交历史中加入真实密码、Token、订阅 URL、域名或数据库。

## 测试

提交前运行完整本地门禁：

```bash
make check
```

也可以分开执行：

```bash
python -m unittest discover -s tests -q
python -m coverage run --branch -m unittest discover -s tests -q
python -m coverage report --fail-under=80
python -m flake8 . --count --select=E9,F63,F7,F82,F401,F811
bash -n deploy.sh start.sh traffic_collector.sh uninstall.sh tests/ubuntu24_integration.sh
shellcheck deploy.sh start.sh traffic_collector.sh uninstall.sh tests/ubuntu24_integration.sh
```

涉及部署、systemd、Caddy、权限或回滚的改动必须说明 Ubuntu 24.04 集成测试影响。不要在个人主机直接运行 `tests/ubuntu24_integration.sh`；它会创建和删除系统服务，应交给隔离的 CI runner。

## 文档

- README 只保留项目定位、快速入口和最重要的安全提示；
- 操作步骤放在 `docs/QUICKSTART.md` 或 `docs/OPERATIONS.md`；
- 配置项放在 `docs/CONFIGURATION.md`；
- 外部接口放在 `docs/API.md`；
- 模块职责和重要取舍放在 `docs/ARCHITECTURE.md`；
- 用户可见行为变化同步写入 `CHANGELOG.md` 的 `Unreleased`。

文档示例必须使用 `example.com`、虚构 IP 和明显的占位 Token，且命令应能直接复制后通过替换占位值运行。

## 提交与 Pull Request

推荐使用简洁的 Conventional Commits 风格：

```text
feat: add account health summary
fix: preserve nodes when subscription parsing fails
docs: clarify HTTPS deployment prerequisites
test: cover release manifest assets
```

Pull Request 描述应回答：

1. 解决什么问题；
2. 为什么采用这个方案；
3. 用户可见变化是什么；
4. 如何验证；
5. 是否涉及数据库、配置、安全边界或部署兼容性；
6. 如何回滚。

维护者可能要求拆分范围、补测试或补迁移说明。CI 全部通过并不代表一定合并，但它是进入评审的最低条件。

## 发布约定

正式版本遵循语义化版本号 `v主版本.次版本.修订号`。Release 标签只能指向 `main` 当前提交，并且该提交必须已通过 push CI。发布说明来自 `CHANGELOG.md` 对应版本段落。

不要在普通 Pull Request 中自行创建或移动正式标签。
