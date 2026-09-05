PYTHON ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)
PYTHON_FILES := app.py database_maintenance.py db_migrations.py import_customer_services.py input_limits.py node_probe.py protocol_codecs.py security_utils.py sqlite_rate_limit.py traffic_token.py
SHELL_FILES := backup.sh deploy.sh start.sh traffic_collector.sh uninstall.sh tests/ubuntu24_integration.sh tests/ubuntu24_e2e.sh

.PHONY: help install-dev test coverage lint shellcheck security audit check

help:
	@printf '%s\n' \
	  'make install-dev  安装带哈希锁定的开发依赖' \
	  'make test         运行全部单元测试' \
	  'make coverage     运行测试并检查 80%% 分支覆盖率' \
	  'make lint         检查 Python 语法和关键静态错误' \
	  'make shellcheck   检查 Shell 语法和常见问题' \
	  'make security     扫描 Python 高、中风险安全问题' \
	  'make audit        审计生产依赖的已知漏洞' \
	  'make check        运行提交前的本地质量门禁'

install-dev:
	$(PYTHON) -m pip install --require-hashes -r requirements-dev.txt

test:
	$(PYTHON) -m unittest discover -s tests -q

coverage:
	$(PYTHON) -m coverage run --branch -m unittest discover -s tests -q
	$(PYTHON) -m coverage report \
		--include='app.py,database_maintenance.py,db_migrations.py,input_limits.py,node_probe.py,protocol_codecs.py,security_utils.py,sqlite_rate_limit.py,traffic_token.py' \
		--fail-under=80

lint:
	$(PYTHON) -m py_compile $(PYTHON_FILES)
	$(PYTHON) -m flake8 . --count --select=E9,F63,F7,F82,F401,F811 --show-source --statistics

shellcheck:
	@for script in $(SHELL_FILES); do bash -n "$$script" || exit; done
	shellcheck $(SHELL_FILES)
	@if command -v actionlint >/dev/null 2>&1; then actionlint; else printf '%s\n' 'actionlint 未安装，跳过 GitHub Actions 本地检查'; fi

security:
	$(PYTHON) -m bandit -q -ll -r $(PYTHON_FILES)

audit:
	$(PYTHON) -m pip_audit -r requirements.txt

check: lint coverage shellcheck security audit
