"""tests/test_gui_liveness_rename.py — task-27: pre-scan liveness + rename.

GUI-тесты в отдельном процессе под xvfb-run на копии проекта в tmp.
Сеть не используется: net_probe.filter_alive_history_ids подменяется внутри
скрипта; Rename работает с настоящими временными проектами.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import textwrap
import types
from pathlib import Path

import pytest

PROJECT_DIR = Path(__file__).resolve().parent.parent
_RESULT_PREFIX = "RESULT_JSON "


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


def _run_gui_script(project: Path, code: str, *, timeout: int = 240) -> dict:
    env = dict(os.environ)
    env["NOTSCAN_DISABLE_PROXY_AUTOSTART"] = "1"
    env["NOTSCAN_UI_LANGUAGE"] = "en"
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


# ══════════════════════════════════════════════════════════════════
#  A) Liveness
# ══════════════════════════════════════════════════════════════════

_LIVENESS_SCRIPT = r"""
import json, sys, threading, types
sys.path.insert(0, ".")
import notscan
import scanner_core
import db

PLAN = {"alive": [], "details": {}}
fake_net_probe = types.ModuleType("net_probe")


def _fake_filter(history_ids, timeout=3.0, log_cb=None):
    return list(PLAN["alive"]), dict(PLAN["details"])


fake_net_probe.filter_alive_history_ids = _fake_filter
sys.modules["net_probe"] = fake_net_probe


def run_scenario(hosts):
    # hosts: list[(url_host, alive_bool)] — свежий App и скан.
    captured = {
        "build": None, "preflight": None, "probe_urls": None,
        "runner": False, "warns": [], "logs": [],
    }

    def fake_build(history_ids, enabled_checks, **kwargs):
        captured["build"] = list(history_ids)
        return ["task"]

    class FakeRunner:
        def __init__(self, **kwargs):
            captured["runner"] = True
            self.tasks_remaining = 0

        def start(self):
            pass

        def stop(self, wait=True):
            pass

    scanner_core.build_scan_tasks = fake_build
    scanner_core.ScannerRunner = FakeRunner
    notscan.mb.showwarning = lambda *a, **k: captured["warns"].append(a)
    notscan.mb.showinfo = lambda *a, **k: None
    notscan.mb.askyesno = lambda *a, **k: True

    app = notscan.App()
    app.update()
    app._private_scope_approved = True
    app._preflight_auth = lambda ids: captured.__setitem__(
        "preflight", list(ids)) or True
    app._run_probe_scan = lambda **kw: captured.__setitem__(
        "probe_urls", list(kw.get("urls") or [])) or 0
    app.log = lambda msg: captured["logs"].append(str(msg))

    by_host = {}
    for host, _alive in hosts:
        hid = db.insert_history(
            method="GET", url=f"http://{host}/x?a=1", req_headers={},
            req_body=None, resp_status=200, resp_headers={},
            resp_body_preview=None,
        )
        by_host[host] = hid
    app._scan_list = {
        hid: db.fetch_history_by_id(hid) for hid in by_host.values()
    }
    # Один probe-чек включаем, чтобы проверить фильтрацию probe-URL.
    probe_ids = notscan.probe_check_ids()
    for cid in list(app._check_vars):
        app._check_vars[cid].set(cid == "sqli" or cid == probe_ids[0])

    PLAN["alive"] = [by_host[h] for h, alive in hosts if alive]
    PLAN["details"] = {
        h: (alive, "200 OK" if alive else "connection refused")
        for h, alive in hosts
    }
    app.after(0, app._run_scan)
    app.after(2200, app.quit)
    app.mainloop()
    for _ in range(50):
        app.update()
        if not any(
            t.is_alive() for t in getattr(app, "_aux_scan_threads", ()) or ()
        ):
            break
        import time as _time
        _time.sleep(0.02)
    captured["scan_list"] = len(app._scan_list)
    captured["alive_hosts"] = [h for h, a in hosts if a]
    app._proxy_shutdown_done = True
    app.destroy()
    return captured


scenarios = {}
scenarios["dead"] = run_scenario([("dead.test", False)])
scenarios["mixed"] = run_scenario([
    ("127.0.0.1:9", True), ("alive.test", True), ("dead.test", False),
])
scenarios["all_alive"] = run_scenario([
    ("alive.test", True), ("second.test", True),
])
print("RESULT_JSON " + json.dumps(scenarios, ensure_ascii=False))
print("GUI_OK")
"""


@pytest.mark.integration
def test_gui_liveness_dead_host_aborts_scan(tmp_path):
    """Все хосты мёртвые: warning, нет build/runner, записей не удаляем."""
    project = _copy_project(tmp_path)
    data = _run_gui_script(project, _LIVENESS_SCRIPT, timeout=300)
    dead = data["dead"]

    assert dead["build"] is None, "не должно быть построения задач"
    assert dead["preflight"] is None, "preflight не должен выполняться"
    assert dead["runner"] is False, "ScannerRunner не должен создаваться"
    assert dead["scan_list"] == 1, "Scan list не чистится"
    assert any("[ALIVE]" in line and "DEAD" in line for line in dead["logs"])
    assert any("aborted" in line for line in dead["logs"])
    assert dead["warns"], "должен быть warning про недоступные хосты"
    assert "dead.test" in str(dead["warns"][-1])


@pytest.mark.integration
def test_gui_liveness_mixed_uses_only_alive(tmp_path):
    """Mixed: в build/preflight/probe — только живые ids; warning один."""
    project = _copy_project(tmp_path)
    data = _run_gui_script(project, _LIVENESS_SCRIPT, timeout=300)
    mixed = data["mixed"]

    assert mixed["build"] is not None
    assert len(mixed["build"]) == 2, mixed["build"]
    assert mixed["preflight"] == mixed["build"]
    assert mixed["runner"] is True
    assert mixed["scan_list"] == 3, "мёртвые записи остаются в Scan list"
    assert mixed["probe_urls"] is not None
    assert len(mixed["probe_urls"]) == 2, mixed["probe_urls"]
    assert all("dead.test" not in url for url in mixed["probe_urls"])
    assert len(mixed["warns"]) == 1, mixed["warns"]
    assert "dead.test" in str(mixed["warns"][0])
    logs = "\n".join(mixed["logs"])
    assert "DEAD (connection refused)" in logs


@pytest.mark.integration
def test_gui_liveness_all_alive_unchanged(tmp_path):
    """Все живы: оба id в build/preflight/probe, без warning."""
    project = _copy_project(tmp_path)
    data = _run_gui_script(project, _LIVENESS_SCRIPT, timeout=300)
    alive = data["all_alive"]

    assert alive["build"] is not None and len(alive["build"]) == 2
    assert alive["preflight"] == alive["build"]
    assert alive["probe_urls"] is not None and len(alive["probe_urls"]) == 2
    assert alive["warns"] == [], alive["warns"]
    assert any("[ALIVE]" in line and "OK (200 OK)" in line for line in alive["logs"])


# ══════════════════════════════════════════════════════════════════
#  B) Rename
# ══════════════════════════════════════════════════════════════════

_RENAME_SCRIPT = r"""
import json, sys
from pathlib import Path
sys.path.insert(0, ".")
from tkinter import simpledialog
import project_manager
import notscan
import db
import ui_theme

warns = []
errors = []
notscan.mb.showwarning = lambda *a, **k: warns.append(a)
notscan.mb.showerror = lambda *a, **k: errors.append(a)
notscan.mb.showinfo = lambda *a, **k: None

ask = {"value": None, "calls": 0}


def fake_askstring(*a, **k):
    ask["calls"] += 1
    return ask["value"]


simpledialog.askstring = fake_askstring

app = notscan.App()
app.update()
res = {}
old_dir = Path(app._project_dir)

# 1) Успешное переименование текущего проекта.
ask["value"] = "renamed_project"
res["success"] = bool(app._rename_project())
new_dir = Path(app._project_dir)
res["success_info"] = {
    "old_gone": not old_dir.exists(),
    "new_exists": new_dir.exists(),
    "name": new_dir.name,
    "title_has_name": new_dir.name in app.title(),
    "db_path_parent": db.get_db_path().parent.name,
    "settings_exists": (new_dir / "settings.json").exists(),
}
# 2) Отмена (None) — без изменений.
ask["value"] = None
before = app._project_dir
res["cancel"] = bool(app._rename_project())
res["cancel_unchanged"] = app._project_dir == before
# 3) Пустое имя — без изменений.
ask["value"] = "   "
before = app._project_dir
res["empty"] = bool(app._rename_project())
res["empty_unchanged"] = app._project_dir == before
# 4) Занятое имя — ошибка, папка не изменилась.
taken = app._project_dir.parent / "taken_project"
taken.mkdir(parents=True, exist_ok=True)
ask["value"] = "taken_project"
before = app._project_dir
errors.clear()
res["collision"] = bool(app._rename_project())
res["collision_unchanged"] = app._project_dir == before
res["collision_error"] = bool(errors)
# 5) Guard во время скана: диалог не вызывается, warning.
class _Runner:
    tasks_remaining = 1
    def stop(self, wait=True):
        pass
app._scan_runner = _Runner()
before_calls = ask["calls"]
warns.clear()
ask["value"] = "must_not_happen"
res["guard"] = bool(app._rename_project())
res["guard_unchanged"] = app._project_dir == before
res["guard_no_dialog"] = ask["calls"] == before_calls
res["guard_warned"] = bool(warns)
app._scan_runner = None
# 6) Пункт меню Project → Rename Project…
menu = app.nametowidget(app.cget("menu"))
labels = []
for i in range(int(menu.index("end")) + 1):
    try:
        labels.append(str(menu.entrycget(i, "label")))
    except Exception:
        pass
    try:
        submenu = menu.nametowidget(menu.entrycget(i, "menu"))
        for j in range(int(submenu.index("end")) + 1):
            try:
                labels.append(str(submenu.entrycget(j, "label")))
            except Exception:
                pass
    except Exception:
        pass
res["menu_labels"] = labels
res["menu_has_rename"] = any("Rename Project" in lbl for lbl in labels)
# 7) SessionPicker: rename НЕ текущей сессии.
second = project_manager.create_project()
window = notscan.SessionPickerWindow(app)
window.update()
target_iid = None
for iid, proj in window._proj_by_iid.items():
    if Path(proj) == Path(second):
        target_iid = iid
        break
res["picker_found_second"] = target_iid is not None
window._tree.selection_set(target_iid)
ask["value"] = "picker_second_renamed"
window._rename_selected()
window.update()
new_second = Path(second).parent / "picker_second_renamed"
res["picker"] = {
    "old_gone": not Path(second).exists(),
    "new_exists": new_second.exists(),
    "in_list": any(Path(p) == new_second for p in window._proj_by_iid.values()),
}
window.destroy()
app._proxy_shutdown_done = True
app.destroy()
print("RESULT_JSON " + json.dumps(res, ensure_ascii=False))
print("GUI_OK")
"""


@pytest.mark.integration
def test_gui_rename_current_project(tmp_path):
    """Rename текущего проекта: dir/db/title/settings; отмена/collision/guard."""
    project = _copy_project(tmp_path)
    data = _run_gui_script(project, _RENAME_SCRIPT, timeout=300)

    assert data["success"] is True
    info = data["success_info"]
    assert info["old_gone"] is True
    assert info["new_exists"] is True
    assert info["name"] == "renamed_project"
    assert info["title_has_name"] is True
    assert info["db_path_parent"] == "renamed_project"
    assert info["settings_exists"] is True

    assert data["cancel"] is False and data["cancel_unchanged"] is True
    assert data["empty"] is False and data["empty_unchanged"] is True
    assert data["collision"] is False and data["collision_unchanged"] is True
    assert data["collision_error"] is True
    assert data["guard"] is False and data["guard_unchanged"] is True
    assert data["guard_no_dialog"] is True
    assert data["guard_warned"] is True
    assert data["menu_has_rename"] is True

    assert data["picker_found_second"] is True
    assert data["picker"]["old_gone"] is True
    assert data["picker"]["new_exists"] is True
    assert data["picker"]["in_list"] is True


# ──────────────────────────── unit ────────────────────────────

def test_fallback_rename_sanitize_and_collision(tmp_path):
    """Fallback rename: sanitize имени + запрет существующей папки."""
    import notscan

    src = tmp_path / "proj"
    src.mkdir()
    (src / "history.db").write_bytes(b"db")

    new_path = notscan.App._fallback_rename_project(src, "  new name  ")
    assert new_path.exists()
    assert not src.exists()
    assert (new_path / "history.db").exists()

    coll = tmp_path / "taken"
    coll.mkdir()
    with pytest.raises(ValueError):
        notscan.App._fallback_rename_project(new_path, "taken")
    assert new_path.exists(), "при collision папка не меняется"

    with pytest.raises(ValueError):
        notscan.App._fallback_rename_project(new_path, "   ")


def test_liveness_fallback_without_net_probe(monkeypatch):
    """Нет/сломан net_probe.filter_alive_history_ids → считаем всех живыми."""
    import notscan

    app = notscan.App.__new__(notscan.App)
    app.log = lambda _msg: None
    empty_module = types.ModuleType("net_probe")
    monkeypatch.setitem(sys.modules, "net_probe", empty_module)
    alive, details, checked = app._filter_alive_history_ids([1, 2, 3])
    assert alive == [1, 2, 3]
    assert details == {}
    assert checked is False
