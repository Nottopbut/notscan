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
state = {"deadline": time.time() + 12.0}

# 1) при запуске прокси НЕ должен стартовать сам (дефолт proxy_autostart=False)
seen_running_at_launch = []


def _phase_launch():
    runner = getattr(app, "_proxy_runner", None)
    running = bool(runner is not None and runner.is_running)
    if running and not seen_running_at_launch:
        seen_running_at_launch.append(True)
    # ждём 1.2с, чтобы исключить гонку «авто-старт через after(300)»
    if time.time() < state.get("launch_deadline", 0):
        app.after(100, _phase_launch)
        return
    state["auto_started_at_launch"] = bool(seen_running_at_launch)
    state["state_at_launch"] = str(app._btn_start_proxy.cget("state"))
    # 2) явный старт (как по кнопке): прокси поднимается и держит порт
    ok = app._start_proxy(auto=True)
    state["start_ok"] = bool(ok)
    app.after(200, _phase_started)


state["launch_deadline"] = time.time() + 1.2
app.after(100, _phase_launch)


def _phase_started():
    runner = getattr(app, "_proxy_runner", None)
    running = bool(runner is not None and runner.is_running)
    port = int(getattr(app, "_proxy_confirmed_port", 0) or 0)
    if running and port and not _bindable(port):
        state.update(
            started_by_button=True,
            port=port,
            status=app._proxy_status_lbl.cget("text"),
            busy_while_running=True,
        )
        app._on_closing()
        return
    if time.time() >= state["deadline"]:
        state.update(
            started_by_button=False,
            status=app._proxy_status_lbl.cget("text"),
            port=port,
            busy_while_running=False,
        )
        app._on_closing()
        return
    app.after(200, _phase_started)


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

app = notscan.App()
state = {"deadline": time.time() + 12.0}


def _start_and_probe():
    # явный старт (как по кнопке), не авто-старт
    app._start_proxy(auto=True)
    app.after(200, _probe)


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
            auto_started=False,
            started_by_button=True,
            port=port,
            ui_port=ui_port,
            fallback_applied=bool(port > 8080 and ui_port == port),
            status=app._proxy_status_lbl.cget("text"),
        )
        app._on_closing()
        return
    if time.time() >= state["deadline"]:
        state.update(started_by_button=False, port=port, ui_port=-1,
                     fallback_applied=False,
                     status=app._proxy_status_lbl.cget("text"))
        app._on_closing()
        return
    app.after(200, _probe)


app.after(600, _start_and_probe)
app.mainloop()
try:
    if blocker is not None:
        blocker.close()
except Exception:
    pass
print("RESULT_JSON " + json.dumps(state))
"""


@pytest.mark.integration
def test_gui_proxy_starts_only_by_button_and_releases_port(tmp_path):
    """Прокси НЕ стартует сам при запуске App; старт — только явный (кнопка).

    После явного старта порт занят; после закрытия App — освобождён.
    """
    project = _copy_project(tmp_path)
    data = _run_gui_script(
        project, _AUTOSTART_SCRIPT, disable_proxy_autostart=False, timeout=240
    )
    assert data.get("auto_started_at_launch") is False, (
        f"прокси запустился автоматически при старте App: {data}"
    )
    assert data.get("state_at_launch") == "normal"
    if not data.get("started_by_button"):
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
    if not data.get("started_by_button"):
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


# ──────────── регресс: Start-кнопка и смена порта после авто-старта ────────────

_RESTART_UX_SCRIPT = r"""
import json, socket, time

import notscan


class FakeRunner:
    def __init__(self, host="127.0.0.1", port=0, log_callback=None, filter_noise=True, **_kw):
        self.host = host
        self.port = port
        self.filter_noise = filter_noise
        self.is_running = False
        self.last_activity_ts = 0.0

    def start(self):
        self.is_running = True

    def stop(self, wait=True):
        self.is_running = False


def free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


# реальный mitmproxy не нужен: подменяем класс движка
notscan.ProxyRunner = FakeRunner
app = notscan.App()


def pump(seconds=1.0):
    end = time.time() + seconds
    while time.time() < end:
        app.update()
        time.sleep(0.01)


pump(0.4)
app._proxy_shutdown_done = True  # не ждём реальный порт при выходе

# 1) авто-старт (эмуляция) не должен блокировать кнопку Start
ok_autostart = app._start_proxy(auto=True)
pump(0.2)
state_after_autostart = str(app._btn_start_proxy.cget("state"))

# 2) клик при том же endpoint → просто открывается браузер (без рестарта)
opened = {"n": 0}
app._open_burp_browser = lambda: opened.__setitem__("n", opened["n"] + 1)
app._start_proxy_and_browser()
pump(0.5)
opened_same = opened["n"]

# 3) пользователь изменил порт и нажал ту же кнопку → рестарт + браузер
new_port = free_port()
app._proxy_port.set(new_port)
app._start_proxy_and_browser()
deadline = time.time() + 8.0
while time.time() < deadline and opened["n"] < 2:
    app.update()
    time.sleep(0.01)

result = {
    "ok_autostart": ok_autostart,
    "state_after_autostart": state_after_autostart,
    "opened_same_endpoint": opened_same,
    "opened_after_restart": opened["n"],
    "expected_new_port": new_port,
    "new_confirmed_port": app._proxy_confirmed_port,
    "state_after_restart": str(app._btn_start_proxy.cget("state")),
}

app._proxy_shutdown_done = True
try:
    if app._proxy_runner is not None:
        app._proxy_runner.stop(wait=True)
except Exception:
    pass
try:
    app.destroy()
except Exception:
    pass

print("RESULT_JSON " + json.dumps(result))
"""


@pytest.mark.integration
def test_gui_start_button_works_after_autostart_and_port_change(tmp_path):
    """Авто-старт не блокирует Start; смена порта применяется по клику.

    Регресс бага: после авто-старта прокси кнопка «Start Proxy + Browser»
    оставалась disabled, порт нельзя было применить, браузер не открывался.
    """
    project = _copy_project(tmp_path)
    data = _run_gui_script(
        project, _RESTART_UX_SCRIPT, disable_proxy_autostart=True, timeout=180
    )
    assert data["ok_autostart"] is True
    assert data["state_after_autostart"] == "normal", (
        "после авто-старта кнопка Start заблокирована — пользователь не может "
        "открыть браузер/сменить порт"
    )
    assert data["opened_same_endpoint"] == 1, (
        "клик при запущенном прокси не открыл браузер"
    )
    assert data["opened_after_restart"] == 2, (
        "после смены порта браузер не открылся (перезапуск прокси не сработал)"
    )
    assert data["new_confirmed_port"] == data["expected_new_port"], (
        f"прокси не перезапустился на новом порту: {data}"
    )
    assert data["state_after_restart"] == "normal"
