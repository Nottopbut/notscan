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

summary_initial = app._chk_summary_lbl.cget("text")
check_vars_initial = {cid: bool(v.get()) for cid, v in app._check_vars.items()}
tree_ids = list(app._chk_tree.get_children())

cfg = notscan.ScanConfigWindow(app)
app.update()
badges = sorted(cfg._badges.keys())
checkboxes = sorted(cfg._check_widgets.keys())
badges_initial = {cid: str(b.cget("text")) for cid, b in cfg._badges.items()}
checkbox_vars_initial = {
    cid: bool(app._check_vars[cid].get()) for cid in cfg._check_widgets
}

# Регресс default-off: «All ON» включает все чеки каталога и все бейджи.
cfg._set_all(True)
app._load_checks_tree()
app.update()
summary_all_on = app._chk_summary_lbl.cget("text")
vars_all_on = {cid: bool(v.get()) for cid, v in app._check_vars.items()}
badges_all_on = {cid: str(b.cget("text")) for cid, b in cfg._badges.items()}

# «All OFF» снова гасит все чеки.
cfg._set_all(False)
app._load_checks_tree()
app.update()
summary_all_off = app._chk_summary_lbl.cget("text")
vars_all_off = {cid: bool(v.get()) for cid, v in app._check_vars.items()}
badges_all_off = {cid: str(b.cget("text")) for cid, b in cfg._badges.items()}

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
    "check_vars": len(app._check_vars),
    "summary_initial": summary_initial,
    "check_vars_initial": check_vars_initial,
    "badges_initial": badges_initial,
    "checkbox_vars_initial": checkbox_vars_initial,
    "summary_all_on": summary_all_on,
    "vars_all_on": vars_all_on,
    "badges_all_on": badges_all_on,
    "summary_all_off": summary_all_off,
    "vars_all_off": vars_all_off,
    "badges_all_off": badges_all_off,
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
    # default-off: даже fallback-дефолты (без каталога) все выключены.
    defs = notscan.check_var_defs()
    assert defs and not any(on for _cid, on in defs)
    assert ("sqli", False) in defs


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


# ══════════════════════════════════════════════════════════════════
#  Default-off чеков: unit + headless GUI-регресс (All ON/OFF)
# ══════════════════════════════════════════════════════════════════

def test_catalog_all_checks_default_off():
    """Каталог и GUI-helpers: все чеки каталога по умолчанию выключены."""
    import checks.catalog as catalog
    import notscan

    catalog_size = len(catalog.CHECK_CATALOG)
    assert catalog_size >= 39, f"каталог подозрительно мал: {catalog_size}"
    assert all(d.enabled_default is False for d in catalog.CHECK_CATALOG), (
        "у некоторых чеков enabled_default=True — по умолчанию все должны быть OFF"
    )
    defs = notscan.check_var_defs()
    assert len(defs) == catalog_size
    assert [cid for cid, _on in defs] == [d.check_id for d in catalog.CHECK_CATALOG]
    assert not any(on for _cid, on in defs), "по умолчанию все чеки должны быть выключены"


@pytest.mark.integration
def test_gui_all_checks_off_by_default_and_all_on_regression(tmp_path):
    """App+ScanConfig: 0/N → All ON → N/N → All OFF → 0/N (N = размер каталога)."""
    import checks.catalog as catalog

    catalog_size = len(catalog.CHECK_CATALOG)
    project = _copy_project(tmp_path)
    data = _run_gui_script(project, _CATALOG_SCRIPT)

    assert data["uses_catalog"] is True
    assert data["catalog_count"] == catalog_size, "GUI и каталог рассинхронизированы"
    assert sorted(data["tree_ids"]) == sorted(data["catalog_ids"])
    assert set(data["badges"]) == set(data["active_ids"]), "бейджи != active каталога"
    assert set(data["checkboxes"]) == set(data["passive_ids"]) | set(data["probe_ids"])
    assert data["check_vars"] == catalog_size

    # ── default-off ──
    off_prefix = f"0 / {catalog_size} checks enabled"
    assert data["summary_initial"].startswith(off_prefix), data["summary_initial"]
    assert not any(data["check_vars_initial"].values()), "чек-переменные не все выключены"
    assert not any(data["checkbox_vars_initial"].values()), "passive/probe не выключены"
    bad_initial = {cid: t for cid, t in data["badges_initial"].items() if not t.startswith("☐")}
    assert not bad_initial, f"бейджи без ☐ при default-off: {bad_initial}"

    # ── All ON ──
    assert data["summary_all_on"].startswith(f"{catalog_size} / {catalog_size} checks enabled"), (
        data["summary_all_on"]
    )
    assert len(data["vars_all_on"]) == catalog_size
    assert all(data["vars_all_on"].values()), "All ON включил не все чеки"
    bad_on = {cid: t for cid, t in data["badges_all_on"].items() if not t.startswith("☑")}
    assert not bad_on, f"бейджи без ☑ после All ON: {bad_on}"

    # ── All OFF ──
    assert data["summary_all_off"].startswith(off_prefix), data["summary_all_off"]
    assert not any(data["vars_all_off"].values()), "All OFF выключил не все чеки"
    bad_off = {cid: t for cid, t in data["badges_all_off"].items() if not t.startswith("☐")}
    assert not bad_off, f"бейджи без ☐ после All OFF: {bad_off}"

    # Stop Proxy по-прежнему нет; Stop Scan остаётся.
    assert data["has_stop_proxy_button"] is False
    assert data["has_stop_scan_button"] is True


# ══════════════════════════════════════════════════════════════════
#  Unit: настройки proxy/scope/ROE (persist + live-применение) и баг-фиксы
# ══════════════════════════════════════════════════════════════════

class _FakeVar:
    def __init__(self, value=False):
        self._value = value

    def get(self):
        return self._value

    def set(self, value):
        self._value = value


class _FakeEntry:
    def __init__(self, value=""):
        self._value = value

    def get(self):
        return self._value

    def delete(self, *_args):
        self._value = ""

    def insert(self, _index, value):
        self._value = str(value)


class _FakeRunner:
    def __init__(self, *, running=True, filter_noise=True, with_setter=True):
        self.is_running = running
        self.filter_noise = filter_noise
        self.calls = []
        if with_setter:
            def _set(enabled):
                self.calls.append(bool(enabled))
                self.filter_noise = bool(enabled)
            self.set_filter_noise = _set


def _fake_app(tmp_path, settings=None):
    """App без Tk-инициализации: только виджеты Settings и настройки."""
    import notscan

    app = notscan.App.__new__(notscan.App)
    app._settings = dict(settings or {})
    app._project_dir = Path(tmp_path)
    app._proxy_runner = None
    app.log = lambda _msg: None
    app._proxy_autostart_var = _FakeVar(False)
    app._proxy_filter_noise_var = _FakeVar(True)
    app._proxy_stop_on_browser_exit_var = _FakeVar(True)
    app._proxy_idle_min_var = _FakeVar("15")
    app._scope_allowlist_entry = _FakeEntry("")
    app._scope_block_private_var = _FakeVar(True)
    app._roe_max_rps_entry = _FakeEntry("0")
    app._roe_block_checks_entry = _FakeEntry("file_upload,ssrf,xxe,deserialization")
    app._roe_stop_on_session_drift = _FakeVar(True)
    app._burp_browser_path = _FakeEntry("")
    app._burp_browser_profile = _FakeEntry("")
    # Куда инжектить (task-21): поля ScanConfigWindow, персист в settings.json.
    app._inject_headers_var = _FakeVar(notscan.DEFAULT_INJECT_HEADERS_STR)
    app._only_params_var = _FakeVar("")
    app._probe_extra_headers_var = _FakeVar("")
    # task-22: профиль скана + язык (persist/read в _get/_apply_scan_settings).
    app._scan_profile_var = _FakeVar("custom")
    app._ui_language_var = _FakeVar("English")
    return app


def test_save_settings_persists_proxy_and_scan_settings(tmp_path):
    """_save_proxy_settings сохраняет proxy_* + scope/ROE/burp настройки проекта."""
    app = _fake_app(tmp_path)
    app._proxy_filter_noise_var.set(False)
    app._proxy_autostart_var.set(True)
    app._proxy_idle_min_var.set("0")
    app._scope_allowlist_entry.insert(0, "10.0.0.1,example.test")
    app._scope_block_private_var.set(False)
    app._roe_max_rps_entry.insert(0, "5")
    app._roe_block_checks_entry.insert(0, "file_upload,ssrf")
    app._roe_stop_on_session_drift.set(False)
    app._burp_browser_path.insert(0, "/opt/chrome")
    app._burp_browser_profile.insert(0, "/tmp/profile")

    app._save_proxy_settings()

    saved = json.loads((Path(tmp_path) / "settings.json").read_text(encoding="utf-8"))
    assert saved["proxy_filter_noise"] is False
    assert saved["proxy_autostart"] is True
    assert saved["proxy_idle_stop_min"] == 0.0
    assert saved["scope_allowlist"] == "10.0.0.1,example.test"
    assert saved["scope_block_private"] is False
    assert saved["roe_max_rps"] == "5"
    assert saved["roe_block_checks"] == "file_upload,ssrf"
    assert saved["roe_stop_on_session_drift"] is False
    assert saved["burp_browser_path"] == "/opt/chrome"
    assert saved["burp_browser_profile"] == "/tmp/profile"


def test_save_settings_applies_noise_filter_live(tmp_path):
    """Изменение proxy_filter_noise применяется к запущенному прокси на лету."""
    app = _fake_app(tmp_path)
    logs = []
    app.log = logs.append
    runner = _FakeRunner(filter_noise=True)
    app._proxy_runner = runner
    app._proxy_filter_noise_var.set(False)

    app._save_proxy_settings()

    assert runner.calls == [False], "set_filter_noise(False) не вызван на лету"
    assert any("на лету" in msg for msg in logs), logs
    # повторное сохранение без изменения настройки не дёргает runner
    app._save_proxy_settings()
    assert runner.calls == [False]


def test_save_settings_noise_filter_fallback_without_setter(tmp_path):
    """Если у runner'а нет set_filter_noise — честный лог про рестарт."""
    app = _fake_app(tmp_path)
    logs = []
    app.log = logs.append
    app._proxy_runner = _FakeRunner(filter_noise=True, with_setter=False)
    app._proxy_filter_noise_var.set(False)

    app._save_proxy_settings()

    assert any("после перезапуска" in msg for msg in logs), logs


def test_apply_settings_to_ui_after_project_switch(tmp_path):
    """Смена проекта: виджеты Settings перечитываются из settings.json нового проекта."""
    app = _fake_app(tmp_path)
    app._settings = {
        "proxy_autostart": True,
        "proxy_filter_noise": False,
        "proxy_stop_on_browser_exit": False,
        "proxy_idle_stop_min": 0,
        "scope_allowlist": "new.example",
        "scope_block_private": False,
        "roe_max_rps": "5",
        "roe_block_checks": "sqli",
        "roe_stop_on_session_drift": False,
        "burp_browser_path": "/opt/chrome",
        "burp_browser_profile": "/tmp/prof",
    }
    runner = _FakeRunner(filter_noise=True)
    app._proxy_runner = runner

    app._apply_settings_to_ui()
    app._apply_proxy_noise_filter()

    assert app._proxy_autostart_var.get() is True
    assert app._proxy_filter_noise_var.get() is False
    assert app._proxy_stop_on_browser_exit_var.get() is False
    assert app._proxy_idle_min_var.get() == "0"
    assert app._scope_allowlist_entry.get() == "new.example"
    assert app._scope_block_private_var.get() is False
    assert app._roe_max_rps_entry.get() == "5"
    assert app._roe_block_checks_entry.get() == "sqli"
    assert app._roe_stop_on_session_drift.get() is False
    assert app._burp_browser_path.get() == "/opt/chrome"
    assert app._burp_browser_profile.get() == "/tmp/prof"
    assert runner.calls == [False], "смена проекта не применила фильтр шума к прокси"


def test_clear_browser_noise_finds_noise_older_than_last_10k(tmp_path, monkeypatch):
    """QA-репро P1: шум только в самых СТАРЫХ записях (вне top-10k) — удаляется.

    12020 строк: ids 1..20 — шум, 21..12020 — обычные. В последних 10000 записях
    шума нет, но очистка обязана долистать историю и удалить его.
    """
    import db
    import notscan

    db.set_db_path(tmp_path / "qa_noise.db")
    try:
        noise_urls = [
            "https://www.google.com/gen_204?x=1",
            "https://update.googleapis.com/service/update2",
            "https://ssl.gstatic.com/gb/images/favicon.ico",
        ]
        with db.get_conn() as conn:
            conn.executemany(
                "INSERT INTO history (time, method, url, req_headers) VALUES (?,?,?,?)",
                [(1.0, "GET", noise_urls[i % len(noise_urls)], "{}")
                 for i in range(20)]
                + [(2.0, "GET", f"http://example.test/item/{i}", "{}")
                   for i in range(21, 12021)],
            )
        monkeypatch.setattr(notscan.mb, "askyesno", lambda *a, **k: True)
        logs = []
        app = notscan.App.__new__(notscan.App)
        app.log = logs.append
        app._scan_list = {}
        app._refresh_history = lambda: None
        app._refresh_scanlist = lambda: None

        app._clear_browser_noise()

        with db.get_conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM history").fetchone()[0]
            noisy = conn.execute(
                "SELECT COUNT(*) FROM history WHERE url LIKE '%google%' "
                "OR url LIKE '%gstatic%'"
            ).fetchone()[0]
        assert total == 12000, f"удалено не 20 шумовых записей (осталось {total})"
        assert noisy == 0, "шум старше последних 10000 не удалён"
        assert any("Удалено фоновых запросов: 20" in m for m in logs), logs[-3:]
    finally:
        db.set_db_path(tmp_path / "closed.db")


def test_clear_browser_noise_deletes_multiple_pages(monkeypatch):
    """Шум на нескольких страницах (>10k) — удаляется весь, без дублей."""
    import notscan

    noise = [
        {"id": i, "url": f"https://www.google-analytics.com/collect?v={i}"}
        for i in range(1, 12001)
    ]
    normal = [
        {"id": 20000 + i, "url": f"http://example.test/item/{i}"}
        for i in range(300)
    ]
    rows = noise + normal          # oldest → newest: шум лежит в начале
    deleted_ids: set[int] = set()
    state = {"pages": 0}

    def fake_refs(limit=10000, offset=0):
        state["pages"] += 1
        remaining = [r for r in rows if r["id"] not in deleted_ids]
        ordered = list(reversed(remaining))     # ORDER BY id DESC
        return ordered[offset:offset + limit]

    def fake_delete(ids):
        ids = [int(i) for i in ids]
        before = len(deleted_ids)
        deleted_ids.update(ids)
        return len(deleted_ids) - before

    monkeypatch.setattr(notscan.db, "fetch_history_refs", fake_refs)
    monkeypatch.setattr(notscan.db, "delete_history_ids", fake_delete)
    monkeypatch.setattr(notscan.mb, "askyesno", lambda *a, **k: True)

    logs = []
    app = notscan.App.__new__(notscan.App)
    app.log = logs.append
    app._scan_list = {}
    app._refresh_history = lambda: None
    app._refresh_scanlist = lambda: None

    app._clear_browser_noise()

    assert deleted_ids == {r["id"] for r in noise}, "удалён не весь фоновый шум"
    assert state["pages"] >= 2, "очистка не долистала историю до старых записей"
    assert any("Удалено фоновых запросов: 12000" in m for m in logs), logs[-3:]


def test_clear_browser_noise_noop_when_clean(monkeypatch):
    """Нет шума → ни одного удаления и понятный лог."""
    import notscan

    normal = [{"id": i, "url": f"http://example.test/a{i}"} for i in range(1, 6)]
    ordered = list(reversed(normal))

    monkeypatch.setattr(
        notscan.db, "fetch_history_refs",
        lambda limit=10000, offset=0: ordered[offset:offset + limit],
    )
    called = {"delete": 0}
    monkeypatch.setattr(
        notscan.db, "delete_history_ids",
        lambda ids: called.__setitem__("delete", called["delete"] + 1) or 0,
    )
    logs = []
    app = notscan.App.__new__(notscan.App)
    app.log = logs.append
    app._refresh_history = lambda: None

    app._clear_browser_noise()

    assert called["delete"] == 0
    assert any("не найдено" in m for m in logs)


def test_fetch_history_refs_paginates_without_blobs(tmp_path):
    """db.fetch_history_refs: id+url, ORDER BY id DESC, корректный offset."""
    import db

    db.set_db_path(tmp_path / "refs.db")
    try:
        with db.get_conn() as conn:
            conn.executemany(
                "INSERT INTO history (time, method, url, req_headers, resp_body_preview) "
                "VALUES (?,?,?,?,?)",
                [(1.0, "GET", f"http://x/{i}", "{}", b"blob") for i in range(25)],
            )
        page1 = db.fetch_history_refs(limit=10, offset=0)
        page2 = db.fetch_history_refs(limit=10, offset=10)
        page3 = db.fetch_history_refs(limit=10, offset=20)
        page4 = db.fetch_history_refs(limit=10, offset=30)
        assert [r["id"] for r in page1] == list(range(25, 15, -1))
        assert [r["id"] for r in page2] == list(range(15, 5, -1))
        assert [r["id"] for r in page3] == list(range(5, 0, -1))
        assert page4 == []
        assert set(page1[0]) == {"id", "url"}, "страница не должна тянуть BLOB-поля"
    finally:
        db.set_db_path(tmp_path / "closed.db")


def test_delete_scan_result_cleans_scan_links(tmp_path):
    """db.delete_scan_result не оставляет висячих scan_links (GUI Delete result)."""
    import db

    db.set_db_path(tmp_path / "links.db")
    try:
        rid1 = db.insert_scan_result(
            template_id="t1", worker_id=0, method="GET", url="http://x/a",
            status_code=200, error=None, check_type="sqli", payload="'", evidence="e1",
        )
        rid2 = db.insert_scan_result(
            template_id="t2", worker_id=0, method="GET", url="http://x/b",
            status_code=200, error=None, check_type="sqli", payload="'", evidence="e2",
        )
        db.insert_scan_link(kind="duplicate", src_result_id=rid1, dst_result_id=rid2)
        db.insert_scan_link(kind="related", src_result_id=rid2, dst_result_id=rid1)
        db.delete_scan_result(rid1)
        with db.get_conn() as conn:
            links_left = conn.execute("SELECT COUNT(*) FROM scan_links").fetchone()[0]
            results_left = conn.execute("SELECT COUNT(*) FROM scan_results").fetchone()[0]
        assert results_left == 1
        assert links_left == 0, "после удаления result остались висячие scan_links"
    finally:
        db.set_db_path(tmp_path / "closed.db")


# ══════════════════════════════════════════════════════════════════
#  Task-21: выбор, КУДА инжектить — headers / only params
# ══════════════════════════════════════════════════════════════════

_INJECTION_TARGETS_UI_SCRIPT = r"""
import json, sys
sys.path.insert(0, ".")
import notscan


def _entry_values(app):
    cfg = notscan.ScanConfigWindow(app)
    app.update()
    values = {
        "inject": cfg._inject_headers_entry.get(),
        "only": cfg._only_params_entry.get(),
        "extra": cfg._probe_extra_headers_text.get("1.0", "end").strip(),
    }
    cfg.destroy()
    app.update()
    return values


app = notscan.App()
app.update()
initial = _entry_values(app)
initial_vars = {
    "inject": app._inject_headers_var.get(),
    "only": app._only_params_var.get(),
    "extra": app._probe_extra_headers_var.get(),
}
# Пользователь меняет значения в окне скана (мусор/дубли — нормализуются).
cfg = notscan.ScanConfigWindow(app)
app.update()
cfg._inject_headers_entry.delete(0, "end")
cfg._inject_headers_entry.insert(0, " X-Forwarded-Host, X-Host , x-host, ,")
cfg._only_params_entry.insert(0, "id, q, id")
cfg._probe_extra_headers_text.insert("1.0", "Cookie: PHPSESSID=abc123\nX-Test-Header: 1")
# Text→StringVar синхронизация: в реальном UI её делают KeyRelease/FocusOut/Start.
cfg._sync_probe_extra_headers_field()
cfg.destroy()
app.update()
app._save_proxy_settings()
project_dir = str(app._project_dir)
saved = json.loads((app._project_dir / "settings.json").read_text(encoding="utf-8"))
app._proxy_shutdown_done = True
app.destroy()

# «Пересоздание App»: новый инстанс, затем возврат в старый проект.
app2 = notscan.App()
app2.update()
new_project_vars = {
    "inject": app2._inject_headers_var.get(),
    "only": app2._only_params_var.get(),
    "extra": app2._probe_extra_headers_var.get(),
}
app2._switch_project(project_dir)
app2.update()
reloaded_vars = {
    "inject": app2._inject_headers_var.get(),
    "only": app2._only_params_var.get(),
    "extra": app2._probe_extra_headers_var.get(),
}
reloaded_entries = _entry_values(app2)

result = {
    "default_headers": notscan.DEFAULT_INJECT_HEADERS_STR,
    "initial": initial,
    "initial_vars": initial_vars,
    "saved": {
        "inject": saved.get("inject_headers"),
        "only": saved.get("only_params"),
        "extra": saved.get("probe_extra_headers"),
    },
    "new_project_vars": new_project_vars,
    "reloaded_vars": reloaded_vars,
    "reloaded_entries": reloaded_entries,
}
print("RESULT_JSON " + json.dumps(result, ensure_ascii=False))
app2._proxy_shutdown_done = True
app2.destroy()
print("GUI_OK")
"""

_INJECTION_TARGETS_KWARGS_SCRIPT = r"""
import json, sys
sys.path.insert(0, ".")
import notscan
import scanner_core
import path_probe
import db

captured = {"builds": [], "probes": []}


def fake_build(history_ids, enabled_checks, do_query=True, do_body_form=True,
               do_body_json=True, do_headers=False, safe_mode=True,
               planner_enabled=True, contracts=None, tamper_modes=None,
               csrf_token_provider=None, only_params=None):
    captured["builds"].append({
        "only_params": only_params,
        "history_ids": list(history_ids),
        "enabled_checks": list(enabled_checks),
    })
    return []


def fake_probe(urls, probe_ids=None, log_cb=None, host_headers=None,
               extra_headers=None):
    captured["probes"].append({
        "urls": list(urls),
        "probe_ids": list(probe_ids or []),
        "host_headers": host_headers,
        "extra_headers": list(extra_headers) if extra_headers else extra_headers,
    })
    return 0


scanner_core.build_scan_tasks = fake_build
path_probe.run_probe_scan = fake_probe

app = notscan.App()
app.update()
# Только один active и один probe-чек — чтобы пройти "No checks selected" и
# гарантированно дойти до вызова probe.
for cid in list(app._check_vars):
    app._check_vars[cid].set(cid in ("sqli", "info_disclosure_paths"))
hid = db.insert_history(
    method="GET", url="http://127.0.0.1:9/never?id=1",
    req_headers={}, req_body=None, resp_status=200,
    resp_headers={}, resp_body_preview=None,
)
app._scan_list = {hid: db.fetch_history_by_id(hid)}
app._inject_headers_var.set("X-Forwarded-Host, X-Custom")
app._only_params_var.set("id, q, ID")
app._probe_extra_headers_var.set("Cookie: PHPSESSID=abc123\nX-Test-Header: 1")


def phase2_prepare():
    # Пустые поля = дефолт (None → engine/probe сами применяют дефолт).
    app._inject_headers_var.set("")
    app._only_params_var.set("")
    app._probe_extra_headers_var.set("")


app.after(0, app._run_scan)
app.after(1200, phase2_prepare)
app.after(1400, app._run_scan)
app.after(3500, app.quit)
app.mainloop()

print("RESULT_JSON " + json.dumps(captured, ensure_ascii=False))
app._proxy_shutdown_done = True
app.destroy()
print("GUI_OK")
"""


def test_parse_csv_names_tolerates_junk():
    """parse_csv_names: trim/дедуп/разделители/кавычки/None — без падений."""
    import notscan

    assert notscan.parse_csv_names(None) == []
    assert notscan.parse_csv_names("") == []
    assert notscan.parse_csv_names(" , ; ") == []
    assert notscan.parse_csv_names(
        " Host, X-Forwarded-Host, , host ; X-Host "
    ) == ["Host", "X-Forwarded-Host", "X-Host"]
    assert notscan.parse_csv_names(["a", " b ", "A"]) == ["a", "b"]
    assert notscan.parse_csv_names('"X-Test", \'X-Other\'') == ["X-Test", "X-Other"]


def test_parse_extra_headers_lines():
    """parse_extra_headers: "Name: value" построчно, мусор/пустые игнорируются."""
    import notscan

    parsed = notscan.parse_extra_headers(
        "Cookie: PHPSESSID=abc; theme=dark\n"
        "  X-Test-Header:  1  \n"
        "\n"
        "no-colon-here\n"
        ": no-name\n"
        "X-Empty:\n"
        "Authorization: Bearer a:b:c"
    )
    assert parsed == [
        ("Cookie", "PHPSESSID=abc; theme=dark"),
        ("X-Test-Header", "1"),
        ("Authorization", "Bearer a:b:c"),
    ]
    # settings.json может хранить список строк.
    assert notscan.parse_extra_headers(["Cookie: a=b", "bad", "X: 1"]) == [
        ("Cookie", "a=b"),
        ("X", "1"),
    ]
    assert notscan.parse_extra_headers(None) == []
    assert notscan.parse_extra_headers("") == []


def test_injection_targets_defaults_and_settings_roundtrip(tmp_path):
    """Поля injection targets: дефолты, нормализация, persist/read settings."""
    import notscan

    app = _fake_app(tmp_path)
    # Дефолты.
    assert app._scan_host_headers() == list(notscan.DEFAULT_INJECT_HEADERS)
    assert app._scan_only_params() is None
    # Мусор/дубли/регистр.
    app._inject_headers_var.set(" X-Forwarded-Host, X-Custom, x-custom ")
    app._only_params_var.set(" id, q, ID ")
    assert app._scan_host_headers() == ["X-Forwarded-Host", "X-Custom"]
    assert app._scan_only_params() == ["id", "q"]
    # Сохранение нормализует значения в settings.json.
    app._save_proxy_settings()
    saved = json.loads((Path(tmp_path) / "settings.json").read_text(encoding="utf-8"))
    assert saved["inject_headers"] == "X-Forwarded-Host, X-Custom"
    assert saved["only_params"] == "id, q"
    # Пустое поле = дефолт (None для engine/probe).
    app._inject_headers_var.set("")
    app._only_params_var.set("")
    assert app._scan_host_headers() is None
    assert app._scan_only_params() is None
    # Extra probe headers: нормализация + persist.
    app._probe_extra_headers_var.set(
        "Cookie: PHPSESSID=abc\n\nbad-line\nX-Test-Header: 1"
    )
    assert app._scan_probe_extra_headers() == [
        ("Cookie", "PHPSESSID=abc"),
        ("X-Test-Header", "1"),
    ]
    app._save_proxy_settings()
    saved = json.loads((Path(tmp_path) / "settings.json").read_text(encoding="utf-8"))
    assert saved["probe_extra_headers"] == [
        "Cookie: PHPSESSID=abc",
        "X-Test-Header: 1",
    ]
    # Чтение обратно (в т.ч. если settings хранит списки).
    app._settings = {
        "inject_headers": ["X-A", "X-B"],
        "only_params": "a, b",
        "probe_extra_headers": ["Cookie: a=b", "X-Test: 1"],
    }
    app._apply_settings_to_ui()
    assert app._inject_headers_var.get() == "X-A, X-B"
    assert app._only_params_var.get() == "a, b"
    assert app._probe_extra_headers_var.get() == "Cookie: a=b\nX-Test: 1"
    # Пустые settings → дефолт для headers, пусто для only_params/extra.
    app._settings = {}
    app._apply_settings_to_ui()
    assert app._inject_headers_var.get() == notscan.DEFAULT_INJECT_HEADERS_STR
    assert app._only_params_var.get() == ""
    assert app._probe_extra_headers_var.get() == ""


@pytest.mark.integration
def test_gui_injection_targets_fields_defaults_persist(tmp_path):
    """GUI: поля существуют, дефолты, persist после пересоздания App/смены проекта."""
    project = _copy_project(tmp_path)
    data = _run_gui_script(project, _INJECTION_TARGETS_UI_SCRIPT, timeout=240)
    default_headers = data["default_headers"]

    # Поля существуют и показывают дефолты.
    assert data["initial"] == {
        "inject": default_headers, "only": "", "extra": ""
    }, data["initial"]
    assert data["initial_vars"] == {
        "inject": default_headers, "only": "", "extra": ""
    }, data["initial_vars"]
    # Введённые значения сохраняются нормализованными (trim/дедуп).
    assert data["saved"] == {
        "inject": "X-Forwarded-Host, X-Host",
        "only": "id, q",
        "extra": ["Cookie: PHPSESSID=abc123", "X-Test-Header: 1"],
    }, data["saved"]
    # Новый проект стартует с дефолтов.
    assert data["new_project_vars"] == {
        "inject": default_headers, "only": "", "extra": ""
    }
    # Возврат в проект — значения читаются из settings.json (и в vars, и в полях).
    assert data["reloaded_vars"] == {
        "inject": "X-Forwarded-Host, X-Host",
        "only": "id, q",
        "extra": "Cookie: PHPSESSID=abc123\nX-Test-Header: 1",
    }, data["reloaded_vars"]
    assert data["reloaded_entries"] == data["reloaded_vars"], data["reloaded_entries"]


@pytest.mark.integration
def test_gui_injection_targets_kwargs_passed_to_engine_and_probe(tmp_path):
    """only_params → build_scan_tasks(), host_headers → run_probe_scan()."""
    project = _copy_project(tmp_path)
    data = _run_gui_script(project, _INJECTION_TARGETS_KWARGS_SCRIPT, timeout=240)

    builds = data.get("builds", [])
    probes = data.get("probes", [])
    assert len(builds) >= 2, f"build_scan_tasks вызван {len(builds)} раз: {builds}"
    assert len(probes) >= 2, f"run_probe_scan вызван {len(probes)} раз: {probes}"

    # Фаза 1: кастомные значения доходят до движка/probe в нормализованном виде.
    assert builds[0]["only_params"] == ["id", "q"], builds[0]
    assert probes[0]["host_headers"] == ["X-Forwarded-Host", "X-Custom"], probes[0]
    # RESULT_JSON сериализует tuples как списки.
    assert [tuple(pair) for pair in probes[0]["extra_headers"]] == [
        ("Cookie", "PHPSESSID=abc123"),
        ("X-Test-Header", "1"),
    ], probes[0]
    assert probes[0]["probe_ids"]  # probe-чек действительно выбран

    # Фаза 2: пустые поля = дефолт → None (engine/probe применяют свои дефолты).
    assert builds[1]["only_params"] is None, builds[1]
    assert probes[1]["host_headers"] is None, probes[1]
    assert not probes[1]["extra_headers"], probes[1]


# ══════════════════════════════════════════════════════════════════
#  Task-22: RU/EN i18n + упрощённый Scan Config (profiles/advanced)
# ══════════════════════════════════════════════════════════════════

_LANGUAGE_SCRIPT = r"""
import json, sys
from pathlib import Path
sys.path.insert(0, ".")
import project_manager
import notscan
import i18n

root = Path("projects")
root.mkdir(exist_ok=True)
ru_proj = root / "i18n_ru_project"
ru_proj.mkdir(parents=True, exist_ok=True)
(ru_proj / "settings.json").write_text(
    json.dumps({"ui_language": "ru"}), encoding="utf-8"
)
project_manager.create_project = lambda *a, **k: ru_proj

app = notscan.App()
app.update()


def _all_texts(root_widget):
    out = []
    stack = [root_widget]
    while stack:
        widget = stack.pop()
        try:
            stack.extend(widget.winfo_children())
        except Exception:
            pass
        try:
            if "text" in widget.keys():
                text = str(widget.cget("text") or "")
                if text:
                    out.append(text)
        except Exception:
            pass
    return out


texts = _all_texts(app)
res = {
    "lang": i18n.get_language(),
    "tabs": [app._notebook.tab(t, "text") for t in app._notebook.tabs()],
    "has_lang_combo": hasattr(app, "_ui_language_var"),
    "lang_value": app._ui_language_var.get(),
    "has_settings_ru": any("Настройки" in t for t in texts),
    "has_scanlist_ru": any(t.strip() == "Список скана" for t in texts),
    "has_history_ru": any(t.strip() == "История" for t in texts),
    "summary": app._chk_summary_lbl.cget("text"),
}
# смена языка: сохраняется в settings.json (диалог не открываем)
notscan.mb.showinfo = lambda *a, **k: None
app._ui_language_var.set(i18n.LANGUAGE_LABELS["ru"])
app._on_language_selected()
res["saved_lang"] = json.loads(
    (ru_proj / "settings.json").read_text(encoding="utf-8")
)["ui_language"]
app._proxy_shutdown_done = True
app.destroy()

# EN — язык по умолчанию (новый проект без settings)
en_proj = root / "i18n_en_project"
en_proj.mkdir(parents=True, exist_ok=True)
project_manager.create_project = lambda *a, **k: en_proj
app2 = notscan.App()
app2.update()
res["default_lang"] = i18n.get_language()
res["en_tabs"] = [app2._notebook.tab(t, "text") for t in app2._notebook.tabs()]
res["en_summary"] = app2._chk_summary_lbl.cget("text")
app2._proxy_shutdown_done = True
app2.destroy()
print("RESULT_JSON " + json.dumps(res, ensure_ascii=False))
print("GUI_OK")
"""

_UX_PROFILES_SCRIPT = r"""
import json, sys
sys.path.insert(0, ".")
import notscan
import checks.catalog as catalog

app = notscan.App()
app.update()
n = len(catalog.CHECK_CATALOG)
active = {d.check_id for d in catalog.by_kind("active")}
passive = {d.check_id for d in catalog.by_kind("passive")}
probe = {d.check_id for d in catalog.by_kind("probe")}
standard_active = set(notscan.ScanConfigWindow.STANDARD_ACTIVE_CHECKS) & active

cfg = notscan.ScanConfigWindow(app)
app.update()


def on_ids():
    return sorted(cid for cid, var in app._check_vars.items() if var.get())


res = {
    "catalog": n,
    "initial_on": on_ids(),
    "checks_visible_initial": bool(cfg._checks_frame.winfo_manager()),
    "advanced_visible_initial": bool(cfg._advanced_frame.winfo_manager()),
    "profile_initial": app._scan_profile_var.get(),
    "desc_initial": str(cfg._profile_desc_lbl.cget("text")),
}
# Quick
app._scan_profile_var.set("quick")
cfg._on_profile_change()
app.update()
res["quick_on"] = on_ids()
res["quick_safe"] = bool(app._safe_mode_var.get())
# Standard
app._safe_mode_var.set(False)
app._scan_profile_var.set("standard")
cfg._on_profile_change()
app.update()
res["standard_on"] = on_ids()
res["standard_safe"] = bool(app._safe_mode_var.get())
# Full
app._scan_profile_var.set("full")
cfg._on_profile_change()
app.update()
res["full_count"] = len(on_ids())
# Custom не меняет текущий выбор: переключение на Custom ничего не трогает
app._scan_profile_var.set("custom")
before = on_ids()
cfg._on_profile_change()
app.update()
res["custom_kept"] = on_ids() == before
cfg._only(["sqli"])
app.update()
# Ручное изменение чеков → профиль Custom
app._scan_profile_var.set("full")
cfg._on_profile_change()
app.update()
app._check_vars["sqli"].set(False)
cfg._sync_profile_with_selection()
res["profile_after_manual"] = app._scan_profile_var.get()
# Раскрытие секций
cfg._customize_checks_var.set(True)
cfg._toggle_checks_section()
cfg._advanced_var.set(True)
cfg._toggle_advanced_section()
app.update()
res["checks_visible"] = bool(cfg._checks_frame.winfo_manager())
res["advanced_visible"] = bool(cfg._advanced_frame.winfo_manager())
# Full: предупреждение при старте (отмена не закрывает окно)
calls = {"start": 0}
cfg._on_start = lambda: calls.__setitem__("start", calls["start"] + 1)
notscan.mb.askyesno = lambda *a, **k: False
app._scan_profile_var.set("full")
cfg._on_profile_change()
cfg._start()
res["full_cancel_kept_open"] = bool(cfg.winfo_exists())
res["full_cancel_start"] = calls["start"]
notscan.mb.askyesno = lambda *a, **k: True
cfg._start()
res["full_confirm_start"] = calls["start"]
res["cfg_destroyed"] = not bool(cfg.winfo_exists())
res.update({
    "active": sorted(active),
    "passive": sorted(passive),
    "probe": sorted(probe),
    "standard_active": sorted(standard_active),
})
print("RESULT_JSON " + json.dumps(res, ensure_ascii=False))
app._proxy_shutdown_done = True
app.destroy()
print("GUI_OK")
"""


@pytest.mark.integration
def test_gui_ru_language_and_default_en(tmp_path):
    """ui_language=ru применяется до UI; по умолчанию — English; выбор сохраняется."""
    project = _copy_project(tmp_path)
    data = _run_gui_script(project, _LANGUAGE_SCRIPT, timeout=240)

    # RU-режим: ключевые надписи и вкладки переведены.
    assert data["lang"] == "ru", data
    tabs = [t.strip() for t in data["tabs"]]
    assert "Прокси / Скан" in tabs, tabs
    assert "Настройки" in tabs, tabs
    assert "Результаты скана" in tabs, tabs
    assert "Проверки / WSTG" in tabs, tabs
    assert data["has_settings_ru"] is True
    assert data["has_scanlist_ru"] is True
    assert data["has_history_ru"] is True
    assert "чеков включено" in data["summary"], data["summary"]
    assert data["has_lang_combo"] is True
    assert data["lang_value"] == "Русский"
    assert data["saved_lang"] == "ru"

    # EN — default (проект без settings.json).
    assert data["default_lang"] == "en", data
    en_tabs = [t.strip() for t in data["en_tabs"]]
    assert "Proxy / Scan" in en_tabs, en_tabs
    assert "Settings" in en_tabs, en_tabs
    assert "checks enabled" in data["en_summary"], data["en_summary"]


@pytest.mark.integration
def test_gui_scan_config_profiles_and_hidden_sections(tmp_path):
    """ScanConfig: профили Quick/Standard/Full/Custom, секции скрыты, Full-warning."""
    project = _copy_project(tmp_path)
    data = _run_gui_script(project, _UX_PROFILES_SCRIPT, timeout=240)

    assert data["catalog"] >= 39, data
    passive_probe = set(data["passive"]) | set(data["probe"])
    standard_active = set(data["standard_active"])

    # Дефолт: compact-окно, все чеки OFF, обе секции спрятаны, профиль Custom.
    assert data["initial_on"] == [], data["initial_on"]
    assert data["checks_visible_initial"] is False
    assert data["advanced_visible_initial"] is False
    assert data["profile_initial"] == "custom"
    assert "Custom" in data["desc_initial"], data["desc_initial"]

    # Quick: все passive+probe, ни одного active, Safe Mode ON.
    assert set(data["quick_on"]) == passive_probe, data["quick_on"]
    assert not (set(data["quick_on"]) & set(data["active"]))
    assert data["quick_safe"] is True

    # Standard: recommended active + все passive/probe, Safe Mode ON.
    assert set(data["standard_on"]) == passive_probe | standard_active, data["standard_on"]
    assert standard_active, "в каталоге нет recommended active-чеков"
    assert data["standard_safe"] is True

    # Full: все чеки.
    assert data["full_count"] == data["catalog"]

    # Custom не меняет выбор; ручное изменение чеков → Custom.
    assert data["custom_kept"] is True
    assert data["profile_after_manual"] == "custom"

    # Секции раскрываются по тумблерам.
    assert data["checks_visible"] is True
    assert data["advanced_visible"] is True

    # Full: при старте спрашиваем подтверждение (отмена окно не закрывает).
    assert data["full_cancel_kept_open"] is True
    assert data["full_cancel_start"] == 0
    assert data["full_confirm_start"] == 1
    assert data["cfg_destroyed"] is True


# ══════════════════════════════════════════════════════════════════
#  Task-24: multi-boundary mutations + Postman environment import
# ══════════════════════════════════════════════════════════════════

_MULTIBOUNDARY_SCRIPT = r"""
import json, sys
sys.path.insert(0, ".")
import notscan
import scanner_core
import db

captured = []


def fake_build(history_ids, enabled_checks, do_query=True, do_body_form=True,
               do_body_json=True, do_headers=False, safe_mode=True,
               planner_enabled=True, contracts=None, tamper_modes=None,
               csrf_token_provider=None, only_params=None,
               do_cookies=True, do_path=True, do_body_multipart=True):
    captured.append({
        "do_cookies": do_cookies,
        "do_path": do_path,
        "do_body_multipart": do_body_multipart,
    })
    return []


scanner_core.build_scan_tasks = fake_build
app = notscan.App()
app.update()
for cid in list(app._check_vars):
    app._check_vars[cid].set(cid == "sqli")
hid = db.insert_history(
    method="GET", url="http://127.0.0.1:9/never?a=1",
    req_headers={}, req_body=None, resp_status=200,
    resp_headers={}, resp_body_preview=None,
)
app._scan_list = {hid: db.fetch_history_by_id(hid)}
cfg = notscan.ScanConfigWindow(app)
app.update()

texts = []
stack = [cfg]
while stack:
    widget = stack.pop()
    try:
        stack.extend(widget.winfo_children())
    except Exception:
        pass
    try:
        if "text" in widget.keys():
            texts.append(str(widget.cget("text") or ""))
    except Exception:
        pass

res = {
    "has_vars": all(
        hasattr(app, name)
        for name in ("_mut_cookies", "_mut_path", "_mut_multipart")
    ),
    "defaults": [
        bool(app._mut_cookies.get()),
        bool(app._mut_path.get()),
        bool(app._mut_multipart.get()),
    ],
    "has_checkbox_cookies": any(t.strip() == "Cookies" for t in texts),
    "has_checkbox_path": any(t.strip() == "Path segments" for t in texts),
    "has_checkbox_multipart": any(t.strip() == "Multipart form-data" for t in texts),
}
# 1) дефолтный запуск — все True
app.after(0, app._run_scan)
app.after(1500, app.quit)
app.mainloop()
# 2) запуск с выключенными multi-boundary
app._mut_cookies.set(False)
app._mut_path.set(False)
app._mut_multipart.set(False)
app.after(0, app._run_scan)
app.after(1500, app.quit)
app.mainloop()
res["runs"] = captured
print("RESULT_JSON " + json.dumps(res, ensure_ascii=False))
app._proxy_shutdown_done = True
app.destroy()
print("GUI_OK")
"""

_ENV_IMPORT_SCRIPT = r"""
import json, sys
from pathlib import Path
sys.path.insert(0, ".")
from tkinter import filedialog
import collection_io
import notscan
import db

app = notscan.App()
app.update()
project = Path(app._project_dir)
collection = project / "collection.json"
collection.write_text(
    json.dumps({"info": {"name": "c", "schema": "postman"},
                "item": [{"request": {"method": "GET",
                                      "url": "{{baseUrl}}/api"}}]}),
    encoding="utf-8",
)
collection_fallback = project / "collection_fallback.json"
collection_fallback.write_text(
    json.dumps({"info": {"name": "c2", "schema": "postman"},
                "item": [{"request": {"method": "GET",
                                      "url": "{{baseUrl}}/api2"}}]}),
    encoding="utf-8",
)
env_file = project / "env.json"
env_file.write_text(
    json.dumps({"name": "e", "values": [
        {"key": "baseUrl", "value": "http://x.test", "enabled": True},
    ]}),
    encoding="utf-8",
)

calls = {"ask": [], "warn": [], "info": [], "dialogs": []}
notscan.mb.askyesno = lambda title=None, message=None, *a, **k: (
    calls["ask"].append((title, message)), True)[1]
notscan.mb.showwarning = lambda *a, **k: calls["warn"].append(a)
notscan.mb.showinfo = lambda *a, **k: calls["info"].append(a)

dialog_results = []


def fake_dialog(*_a, **kwargs):
    calls["dialogs"].append(kwargs.get("title"))
    return dialog_results.pop(0) if dialog_results else ""


filedialog.askopenfilename = fake_dialog
captured = {}


def fake_missing(path, environment=None):
    calls.setdefault("missing_envs", []).append(environment)
    return [] if environment else ["baseUrl"]


def fake_import(path, variables=None):
    captured["variables"] = variables
    captured["path"] = str(path)
    return [{"method": "GET", "url": "http://x.test/api", "headers": {}, "body": None}]


collection_io.postman_missing_variables = fake_missing
collection_io.postman_environment = lambda path: {"baseUrl": "http://x.test"}
collection_io.import_collection = fake_import

res = {}

# 1) Позитив: missing + env загружен → import с variables, History пополнена.
dialog_results[:] = [str(collection), str(env_file)]
app._import_collection()
app.update()
res["positive"] = {
    "variables": captured.get("variables"),
    "env": dict(app._postman_env),
    "history": len(db.fetch_history(limit=50)),
    "ask_count": len(calls["ask"]),
    "info_count": len(calls["info"]),
    "dialogs": list(calls["dialogs"]),
}
# 2) Негатив: переменных нет → env не спрашиваем, import без variables.
calls["ask"].clear()
captured.clear()
app._postman_env.clear()
collection_io.postman_missing_variables = lambda path, environment=None: []
dialog_results[:] = [str(collection)]
app._import_collection()
app.update()
res["negative"] = {
    "variables": captured.get("variables"),
    "ask_count": len(calls["ask"]),
    "history": len(db.fetch_history(limit=50)),
}
# 3) Кнопка «⬆ Import environment»: env в память сессии + лог/диалог.
app._postman_env.clear()
dialog_results[:] = [str(env_file)]
app._import_environment()
app.update()
res["button"] = {"env": dict(app._postman_env), "info_count": len(calls["info"])}
# 4) Fallback без env-API collection_io (до мержа): локальный детектор/парсер.
app._postman_env.clear()
captured.clear()
del collection_io.postman_missing_variables
del collection_io.postman_environment
dialog_results[:] = [str(collection_fallback), str(env_file)]
app._import_collection()
app.update()
res["fallback_no_api"] = {
    "variables": captured.get("variables"),
    "env": dict(app._postman_env),
}

texts = []
stack = [app]
while stack:
    widget = stack.pop()
    try:
        stack.extend(widget.winfo_children())
    except Exception:
        pass
    try:
        if "text" in widget.keys():
            texts.append(str(widget.cget("text") or ""))
    except Exception:
        pass
res["has_env_button"] = any("Import environment" in t for t in texts)
print("RESULT_JSON " + json.dumps(res, ensure_ascii=False))
app._proxy_shutdown_done = True
app.destroy()
print("GUI_OK")
"""


@pytest.mark.integration
def test_gui_multiboundary_mutation_checkboxes_and_kwargs(tmp_path):
    """Cookies/Path/Multipart: чекбоксы в Advanced, default True, kwargs в build_scan_tasks."""
    project = _copy_project(tmp_path)
    data = _run_gui_script(project, _MULTIBOUNDARY_SCRIPT, timeout=240)

    assert data["has_vars"] is True
    assert data["defaults"] == [True, True, True], data["defaults"]
    assert data["has_checkbox_cookies"] is True, "нет чекбокса Cookies"
    assert data["has_checkbox_path"] is True, "нет чекбокса Path segments"
    assert data["has_checkbox_multipart"] is True, "нет чекбокса Multipart form-data"

    runs = data.get("runs", [])
    assert len(runs) >= 2, f"build_scan_tasks вызван {len(runs)} раз: {runs}"
    assert runs[0] == {
        "do_cookies": True, "do_path": True, "do_body_multipart": True,
    }, runs[0]
    assert runs[1] == {
        "do_cookies": False, "do_path": False, "do_body_multipart": False,
    }, runs[1]


@pytest.mark.integration
def test_gui_postman_environment_import_flow(tmp_path):
    """Env-флоу импорта: missing → env → import с variables; негатив; кнопка; fallback."""
    project = _copy_project(tmp_path)
    data = _run_gui_script(project, _ENV_IMPORT_SCRIPT, timeout=300)

    # 1) Позитив: спросили env, загрузили, импортировали с variables.
    positive = data["positive"]
    assert positive["variables"] == {"baseUrl": "http://x.test"}, positive
    assert positive["env"] == {"baseUrl": "http://x.test"}
    assert positive["history"] == 1, "импорт не добавил записи в History"
    assert positive["ask_count"] == 1, "должен быть ровно один вопрос про env"
    assert len(positive["dialogs"]) == 2, positive["dialogs"]  # collection + env

    # 2) Негатив: без missing переменных env не спрашивается.
    negative = data["negative"]
    assert negative["ask_count"] == 0, "лишний вопрос про окружение"
    assert negative["variables"] is None, negative
    assert negative["history"] == 2

    # 3) Кнопка Import environment кладёт env в память сессии.
    assert data["button"]["env"] == {"baseUrl": "http://x.test"}

    # 4) Fallback без env-API (до мержа Lead): локальные детектор/парсер работают.
    fallback = data["fallback_no_api"]
    assert fallback["variables"] == {"baseUrl": "http://x.test"}, fallback
    assert fallback["env"] == {"baseUrl": "http://x.test"}

    assert data["has_env_button"] is True, "нет кнопки ⬆ Import environment"
