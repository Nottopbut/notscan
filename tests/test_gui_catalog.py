"""
tests/test_gui_catalog.py — GUI: каталог чеков + авто-жизненный цикл прокси.

Тесты запускаются в отдельном процессе под ``xvfb-run`` на КОПИИ проекта в
tmp-каталоге (App() создаёт projects/ и БД — реальный репозиторий не трогаем).
По/§4.2 проверяем:
  • вкладка Checks/WSTG строится из checks/catalog.py (число/ids строк);
  • бейджи ScanConfigWindow: все active из каталога, чекбоксы passive+probe;
  • кнопки «Stop Proxy» нет (но «Stop Scan» остаётся);
  • авто-старт прокси при запуске App работает; при занятом порте — fallback
    на следующий свободный; после закрытия App порт снова bindable.

GUI-тесты помечены ``integration`` (нужен реальный mitmproxy); при отсутствии
xvfb/DISPLAY или если mitmproxy не поднялся в окружении — skip, не fail.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

PROJECT_DIR = Path(__file__).resolve().parent.parent
_RESULT_PREFIX = "RESULT_JSON "


# ──────────────────────────── helpers ────────────────────────────

def _copy_project(tmp_path: Path) -> Path:
    dst = tmp_path / "notscan_copy"
    ignore = shutil.ignore_patterns(
        "__pycache__", "*.pyc", "*.pyo", ".git", "projects",
        "history.db", "history.db-*", ".venv", "venv", "reports",
    )
    shutil.copytree(PROJECT_DIR, dst, ignore=ignore)
    return dst


def _python_cmd() -> list[str]:
    xvfb_run = shutil.which("xvfb-run")
    if xvfb_run:
        return [xvfb_run, "-a", sys.executable]
    if os.environ.get("DISPLAY"):
        return [sys.executable]
    pytest.skip("нет ни xvfb-run, ни DISPLAY — GUI-тест невозможен")


def _run_gui_script(
    project: Path,
    code: str,
    *,
    disable_proxy_autostart: bool = True,
    timeout: int = 180,
) -> dict:
    env = dict(os.environ)
    if disable_proxy_autostart:
        env["NOTSCAN_DISABLE_PROXY_AUTOSTART"] = "1"
    else:
        env.pop("NOTSCAN_DISABLE_PROXY_AUTOSTART", None)
    proc = subprocess.run(
        [*_python_cmd(), "-c", textwrap.dedent(code)],
        cwd=str(project),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    assert proc.returncode == 0, (
        f"GUI-скрипт упал (rc={proc.returncode}).\n"
        f"STDOUT:\n{proc.stdout[-3000:]}\nSTDERR:\n{proc.stderr[-3000:]}"
    )
    data = None
    for line in proc.stdout.splitlines():
        if line.startswith(_RESULT_PREFIX):
            data = json.loads(line[len(_RESULT_PREFIX):])
    assert data is not None, f"нет RESULT_JSON в stdout:\n{proc.stdout[-3000:]}"
    return data


_CATALOG_SCRIPT = r"""
import json, sys
sys.path.insert(0, ".")
import tkinter as tk
import tkinter.ttk as ttk
import checks.catalog as catalog
import notscan


def _all_widgets(widget):
    yield widget
    for child in widget.winfo_children():
        yield from _all_widgets(child)


def _button_texts(root):
    texts = []
    for w in _all_widgets(root):
        try:
            if isinstance(w, (tk.Button, ttk.Button)):
                texts.append(str(w.cget("text")))
        except Exception:
            pass
    return texts


app = notscan.App()
app.update()

tree_ids = list(app._chk_tree.get_children())
cfg = notscan.ScanConfigWindow(app)
app.update()
badges = sorted(cfg._badges.keys())
checkboxes = sorted(cfg._check_widgets.keys())
cfg.destroy()
app.update()
buttons = _button_texts(app)

result = {
    "catalog_available": notscan.catalog_available(),
    "catalog_count": len(catalog.CHECK_CATALOG),
    "catalog_ids": [d.check_id for d in catalog.CHECK_CATALOG],
    "uses_catalog": bool(getattr(app, "_uses_check_catalog", False)),
    "tree_ids": tree_ids,
    "tree_count": len(tree_ids),
    "badges": badges,
    "checkboxes": checkboxes,
    "active_ids": sorted(d.check_id for d in catalog.by_kind("active")),
    "passive_ids": sorted(d.check_id for d in catalog.by_kind("passive")),
    "probe_ids": sorted(d.check_id for d in catalog.by_kind("probe")),
    "passive_helper": sorted(notscan.passive_check_ids()),
    "probe_helper": sorted(notscan.probe_check_ids()),
    "button_texts": buttons,
    "has_stop_proxy_button": any(
        ("stop" in t.lower() and "proxy" in t.lower()) for t in buttons
    ),
    "has_stop_scan_button": any("stop scan" in t.lower() for t in buttons),
    "status": app._proxy_status_lbl.cget("text"),
    "check_vars": len(app._check_vars),
    "summary": app._chk_summary_lbl.cget("text"),
    "has_proxy_settings_widgets": all(
        hasattr(app, name)
        for name in ("_proxy_autostart_var", "_proxy_stop_on_browser_exit_var",
                     "_proxy_idle_min_var")
    ),
    "has_lifecycle_methods": all(
        hasattr(app, name)
        for name in ("_maybe_autostart_proxy", "_proxy_watchdog_tick",
                     "_check_browser_exit", "_check_idle_stop",
                     "_shutdown_proxy_sync")
    ),
}
print("RESULT_JSON " + json.dumps(result, ensure_ascii=False))
app.destroy()
print("GUI_OK")
"""


_AUTOSTART_SCRIPT = r"""
import json, socket, sys, time
sys.path.insert(0, ".")
import notscan


def _bindable(port, host="127.0.0.1"):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.0)
    try:
        s.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


app = notscan.App()
state = {"deadline": time.time() + 12.0, "auto_started": False}


def _probe():
    runner = getattr(app, "_proxy_runner", None)
    running = bool(runner is not None and runner.is_running)
    port = int(getattr(app, "_proxy_confirmed_port", 0) or 0)
    # Ждём не просто живого потока, а фактически занятого listen-порта.
    if running and port and not _bindable(port):
        state.update(
            auto_started=True,
            port=port,
            status=app._proxy_status_lbl.cget("text"),
            busy_while_running=True,
        )
        app._on_closing()
        return
    if time.time() >= state["deadline"]:
        state.update(
            auto_started=False,
            status=app._proxy_status_lbl.cget("text"),
            port=port,
            busy_while_running=False,
        )
        app._on_closing()
        return
    app.after(200, _probe)


app.after(400, _probe)
app.mainloop()
port = int(state.get("port") or 0)
state["bindable_after_close"] = bool(port) and _bindable(port)
print("RESULT_JSON " + json.dumps(state))
"""


_BUSY_PORT_SCRIPT = r"""
import json, socket, sys, time
sys.path.insert(0, ".")
import notscan


def _bindable(port, host="127.0.0.1"):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.0)
    try:
        s.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


blocker = None
# Предыдущие тесты могли ещё не отпустить 8080 — пробуем занять его с ретраями,
# чтобы port-busy гарантированно наблюдался в момент авто-старта App.
for _attempt in range(100):
    candidate = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    candidate.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        candidate.bind(("127.0.0.1", 8080))
        candidate.listen(1)
        blocker = candidate
        break
    except OSError:
        try:
            candidate.close()
        except OSError:
            pass
        time.sleep(0.05)
# blocker is None → порт занят кем-то другим; fallback обязан сработать и так.

app = notscan.App()
state = {"deadline": time.time() + 12.0}


def _probe():
    runner = getattr(app, "_proxy_runner", None)
    running = bool(runner is not None and runner.is_running)
    port = int(getattr(app, "_proxy_confirmed_port", 0) or 0)
    if running and port:
        try:
            ui_port = int(app._proxy_port.get())
        except Exception:
            ui_port = -1
        state.update(
            auto_started=True,
            port=port,
            ui_port=ui_port,
            fallback_applied=bool(port > 8080 and ui_port == port),
            status=app._proxy_status_lbl.cget("text"),
        )
        app._on_closing()
        return
    if time.time() >= state["deadline"]:
        state.update(auto_started=False, status=app._proxy_status_lbl.cget("text"))
        app._on_closing()
        return
    app.after(200, _probe)


app.after(400, _probe)
app.mainloop()
if blocker is not None:
    blocker.close()
print("RESULT_JSON " + json.dumps(state))
"""


# ──────────────────────────── tests ────────────────────────────

def test_gui_checks_tree_and_badges_use_catalog(tmp_path):
    """Checks/WSTG-дерево и бейджи ScanConfigWindow строятся из каталога."""
    project = _copy_project(tmp_path)
    data = _run_gui_script(project, _CATALOG_SCRIPT)

    assert data["catalog_available"] is True, "checks/catalog.py не загрузился"
    assert data["uses_catalog"] is True
    assert data["tree_count"] == data["catalog_count"], (
        f"GUI-строк {data['tree_count']} != чеков в каталоге {data['catalog_count']}"
    )
    assert set(data["tree_ids"]) == set(data["catalog_ids"])

    # Активные чеки каталога — все как бейджи
    assert set(data["badges"]) == set(data["active_ids"]), (
        f"бейджи != active каталога; missing={set(data['active_ids']) - set(data['badges'])}"
    )
    # Passive+probe — как чекбоксы
    expected_checkboxes = set(data["passive_ids"]) | set(data["probe_ids"])
    assert set(data["checkboxes"]) == expected_checkboxes, (
        f"чекбоксы != passive+probe; missing={expected_checkboxes - set(data['checkboxes'])}"
    )
    # Вспомогательные наборы GUI (для _build_and_run) тоже из каталога
    assert data["passive_helper"] == data["passive_ids"]
    assert data["probe_helper"] == data["probe_ids"]
    assert "info_disclosure_paths" in data["probe_ids"], "pseudo probe-чек потерян"

    # Stop Proxy кнопки нет; Stop Scan (скан, не прокси) остаётся
    assert data["has_stop_proxy_button"] is False, (
        f"в UI осталась кнопка Stop Proxy: {data['button_texts']}"
    )
    assert data["has_stop_scan_button"] is True
    assert data["check_vars"] >= data["catalog_count"]
    assert "/" in data["summary"] and "enabled" in data["summary"]
    assert data["has_proxy_settings_widgets"] is True
    assert data["has_lifecycle_methods"] is True
    # Авто-старт отключён env-переменной для этого теста
    assert data["status"].startswith("● STOPPED")


@pytest.mark.integration
def test_gui_app_autostarts_proxy_and_releases_port(tmp_path):
    """App авто-стартует прокси; после закрытия App порт bindable."""
    project = _copy_project(tmp_path)
    data = _run_gui_script(
        project, _AUTOSTART_SCRIPT, disable_proxy_autostart=False, timeout=240
    )
    if not data.get("auto_started"):
        pytest.skip(f"mitmproxy не поднялся в окружении: {data}")
    assert data["port"] > 0
    assert data["status"].startswith("● RUNNING")
    assert data["busy_while_running"] is True, "порт не занят, хотя прокси RUNNING"
    assert data["bindable_after_close"] is True, (
        "после закрытия App порт прокси не освобождён"
    )


@pytest.mark.integration
def test_gui_busy_port_fallback(tmp_path):
    """Занятый 8080 → авто-подбор следующего порта без модалки."""
    project = _copy_project(tmp_path)
    data = _run_gui_script(
        project, _BUSY_PORT_SCRIPT, disable_proxy_autostart=False, timeout=240
    )
    if not data.get("auto_started"):
        pytest.skip(f"mitmproxy не поднялся в окружении: {data}")
    assert data["fallback_applied"] is True, (
        f"порт 8080 занят, но fallback не сработал: {data}"
    )
    assert data["port"] > 8080
    assert data["ui_port"] == data["port"], "поле Port в UI не обновлено"


# ──────────── unit: каталог/fallback и probe-диспетчеризация GUI ────────────

def test_catalog_helpers_probe_passive_payload():
    """PASSIVE/probe/payload-наборы GUI строятся из каталога."""
    import checks.catalog as catalog
    import notscan

    assert notscan.catalog_available() is True
    assert notscan.passive_check_ids() == [
        d.check_id for d in catalog.by_kind("passive")
    ]
    assert notscan.probe_check_ids() == [
        d.check_id for d in catalog.by_kind("probe")
    ]
    assert "info_disclosure_paths" in notscan.probe_check_ids()
    payload_ids = notscan.payload_check_ids()
    assert "sqli" in payload_ids and "xss_reflected" in payload_ids
    # все active-чеки с payload_file попали в набор
    for defn in catalog.by_kind("active"):
        if defn.payload_file:
            assert defn.check_id in payload_ids


def test_catalog_helpers_fallback_without_catalog(monkeypatch):
    """Если checks/catalog.py недоступен — старые hardcoded-наборы (не падаем)."""
    import notscan

    monkeypatch.setattr(notscan, "_CATALOG_AVAILABLE", False)
    monkeypatch.setattr(notscan, "_CHECK_CATALOG", ())
    assert notscan.catalog_available() is False
    assert notscan.catalog_defs() == []
    assert notscan.catalog_badge_lists() == {}
    assert notscan.probe_check_ids() == ["info_disclosure_paths"]
    assert "security_headers" in notscan.passive_check_ids()
    assert "sqli" in notscan.payload_check_ids()
    assert ("sqli", True) in notscan.check_var_defs()


def test_gui_run_probe_scan_uses_new_api(monkeypatch):
    """_build_and_run probe-ветка зовёт path_probe.run_probe_scan(urls, ids, log_cb)."""
    import notscan

    captured: dict = {}

    def _fake_run_probe_scan(urls, probe_ids=None, log_cb=None):  # noqa: ARG001
        captured["urls"] = list(urls)
        captured["probe_ids"] = list(probe_ids or [])
        return 3

    monkeypatch.setattr(notscan.path_probe, "run_probe_scan", _fake_run_probe_scan)
    app = notscan.App.__new__(notscan.App)  # без Tk-инициализации
    app.log = lambda _m: None
    result = notscan.App._run_probe_scan(
        app, ["http://example.test/a"], ["metafiles", "info_disclosure_paths"]
    )
    assert result == 3
    assert captured["urls"] == ["http://example.test/a"]
    assert captured["probe_ids"] == ["metafiles", "info_disclosure_paths"]


def test_gui_run_probe_scan_fallback_legacy(monkeypatch):
    """Нет run_probe_scan → fallback на старый run_info_disclosure_scan."""
    import notscan

    monkeypatch.delattr(notscan.path_probe, "run_probe_scan", raising=False)
    captured: dict = {}

    def _legacy(urls, log_cb=None):  # noqa: ARG001
        captured["urls"] = list(urls)
        return 1

    monkeypatch.setattr(notscan.path_probe, "run_info_disclosure_scan", _legacy)
    app = notscan.App.__new__(notscan.App)
    app.log = lambda _m: None
    result = notscan.App._run_probe_scan(app, ["http://example.test/b"], ["metafiles"])
    assert result == 1
    assert captured["urls"] == ["http://example.test/b"]
