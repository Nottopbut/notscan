# notscan — частые задачи разработки/проверки.
#
#   make install  — поставить зависимости
#   make test     — весь pytest-набор (включая интеграционную лабу)
#   make lab      — интеграционные тесты лабы + WSTG-чеков (маркер integration)
#   make smoke    — GUI-смоук в xvfb на копии проекта (App() создаёт projects/)
#
# ВАЖНО: `make smoke` работает на временной копии — реальные projects/ и БД
# в рабочем каталоге не трогаются.

PYTHON ?= python
PYTEST ?= $(PYTHON) -m pytest
XVFB_RUN ?= xvfb-run -a

.PHONY: help install test lab smoke

help:
	@echo "make install  — pip install -r requirements.txt"
	@echo "make test     — $(PYTEST) tests/ -q"
	@echo "make lab      — $(PYTEST) tests/test_integration_lab.py tests/test_integration_wstg.py -m integration -q"
	@echo "make smoke    — GUI-смоук (App() в xvfb на копии проекта)"

install:
	$(PYTHON) -m pip install -r requirements.txt

test:
	$(PYTEST) tests/ -q

lab:
	$(PYTEST) tests/test_integration_lab.py tests/test_integration_wstg.py -m integration -q

smoke:
	@set -e; \
	tmp=$$(mktemp -d); \
	trap 'rm -rf "$$tmp"' EXIT; \
	mkdir -p "$$tmp/notscan"; \
	rsync -a \
		--exclude='.git' \
		--exclude='projects' \
		--exclude='__pycache__' \
		--exclude='.pytest_cache' \
		--exclude='*.db' \
		--exclude='*.db-wal' \
		--exclude='*.db-shm' \
		./ "$$tmp/notscan/"; \
	cd "$$tmp/notscan" && $(XVFB_RUN) $(PYTHON) -c \
		"import notscan; app = notscan.App(); app.update(); app.destroy(); print('SMOKE_OK')"
