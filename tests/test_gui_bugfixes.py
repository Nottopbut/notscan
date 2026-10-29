"""Регрессы по баг-репорту QA (HEAD edff5a0):
  • двойной клик «Start Proxy + Browser» не открывает второй браузер;
  • авто-refresh Results/History не сбрасывает пагинацию;
  • History: пагинация «Load more» и счётчик «показано / всего» (не только 500);
  • авто-путь _start_proxy(auto=True): порт 0/65536 → валидный 8080;
  • Tutorial/welcome больше не обещают авто-старт прокси.
"""

import json
import os
import tempfile

import pytest

from tests.test_gui_catalog import _RESULT_PREFIX, _copy_project, _run_gui_script


# ──────────────────────────── браузер: без дублей ────────────────────────────

_DOUBLE_BROWSER_SCRIPT = r"""
import json, sys, time
sys.path.insert(0, ".")
import notscan

launched = []


class FakePopen:
    def __init__(self, args, **kwargs):
        self.args = args
        self.pid = 4242
        launched.append(args)

    def poll(self):
        return None


class FakeRunner:
    def __init__(self, host="127.0.0.1", port=8080, log_callback=None,
                 filter_noise=True, **_kw):
        self.host = host
        self.port = port
        self.is_running = True
        self.filter_noise = filter_noise
        self.pac_url = "http://127.0.0.1:8123/proxy.pac"

    def start(self):
        self.is_running = True

    def stop(self, wait=True):
        self.is_running = False

    def set_filter_noise(self, value):
        self.filter_noise = value


app = notscan.App()
app._launch_browser_process = lambda args: FakePopen(args)
app._proxy_runner = FakeRunner()
app._proxy_confirmed_host = "127.0.0.1"
app._proxy_confirmed_port = 8080
app._proxy_host.delete(0, "end")
app._proxy_host.insert(0, "127.0.0.1")
app._proxy_port.set(8080)

# Два клика подряд: второй не должен открыть второй браузер.
app._start_proxy_and_browser()
app._start_proxy_and_browser()
launches_after_double_click = len(launched)

# Повторная постановка в очередь тоже дедуплицируется.
app._browser_proc = None
app._schedule_browser_open(10)
app._schedule_browser_open(10)
deadline = time.time() + 3.0
while time.time() < deadline and len(launched) < 2:
    app.update()
    time.sleep(0.02)

print("RESULT_JSON " + json.dumps({
    "launches_after_double_click": launches_after_double_click,
    "launches_total": len(launched),
}))
app._on_closing()
"""


@pytest.mark.integration
def test_gui_double_start_opens_browser_once(tmp_path):
    project = _copy_project(tmp_path)
    data = _run_gui_script(project, _DOUBLE_BROWSER_SCRIPT, timeout=240)
    assert data["launches_after_double_click"] == 1, (
        f"двойной клик открыл браузер {data['launches_after_double_click']} раз"
    )
    assert data["launches_total"] == 2, (
        f"повторная очередь должна дать ровно один браузер: {data}"
    )


# ──────────────── пагинация History: Load more и счётчик ────────────────

_HISTORY_PAGINATION_SCRIPT = r"""
import json, sys
sys.path.insert(0, ".")
import notscan
import db

app = notscan.App()
for i in range(1200):
    db.insert_history(
        method="GET", url=f"http://target.test/item/{i}",
        req_headers={}, req_body=None, resp_status=200,
        resp_headers={}, resp_body_preview=b"ok",
    )
app._refresh_history(reset=True)
shown_first = len(app._history_tree.get_children())
counter_first = app._history_count_lbl.cget("text")
app._load_more_history()
shown_second = len(app._history_tree.get_children())
app._load_more_history()
shown_third = len(app._history_tree.get_children())
counter_third = app._history_count_lbl.cget("text")
state = app._btn_load_more_history.cget("state")
print("RESULT_JSON " + json.dumps({
    "shown_first": shown_first,
    "counter_first": counter_first,
    "shown_second": shown_second,
    "shown_third": shown_third,
    "counter_third": counter_third,
    "load_more_state": str(state),
}))
app._on_closing()
"""


@pytest.mark.integration
def test_gui_history_pagination_and_counter(tmp_path):
    project = _copy_project(tmp_path)
    data = _run_gui_script(project, _HISTORY_PAGINATION_SCRIPT, timeout=240)
    assert data["shown_first"] == 500, data
    assert data["shown_second"] == 1000, data
    assert data["shown_third"] == 1200, data
    assert "/ 1200" in data["counter_first"], data["counter_first"]
    assert "/ 1200" in data["counter_third"], data["counter_third"]
    assert str(data["load_more_state"]).lower() in ("disabled", "disable"), data


# ─────────── авто-refresh не сбрасывает offset Results/History ───────────

_REFRESH_PRESERVE_SCRIPT = r"""
import json, sys
sys.path.insert(0, ".")
import notscan
import db

app = notscan.App()
# Results: сперва «прокрутили» до 1000, авто-refresh не должен сбросить.
app._results_offset = 1000
app._refresh_results(reset=False)
offset_after_refresh = app._results_offset
rid = db.insert_scan_result(
    template_id="t-auto", worker_id=0, method="GET",
    url="http://target.test/x", status_code=200, error=None,
    check_type="xss", payload="<script>", evidence="reflected",
)
app._auto_refresh_loop()
offset_after_new_row = app._results_offset

# History: авто-refresh тоже сохраняет offset.
app._history_offset = 500
app._refresh_history(reset=False)
hist_offset_after_refresh = app._history_offset
db.insert_history(method="GET", url="http://target.test/new", req_headers={},
                  req_body=None, resp_status=200, resp_headers={},
                  resp_body_preview=b"ok")
app._auto_refresh_loop()
hist_offset_after_new_row = app._history_offset

# Явный reset (новый скан) — сбрасывает.
app._refresh_results(reset=True)
offset_after_reset = app._results_offset

print("RESULT_JSON " + json.dumps({
    "offset_after_refresh": offset_after_refresh,
    "offset_after_new_row": offset_after_new_row,
    "hist_offset_after_refresh": hist_offset_after_refresh,
    "hist_offset_after_new_row": hist_offset_after_new_row,
    "offset_after_reset": offset_after_reset,
}))
app._on_closing()
"""


@pytest.mark.integration
def test_gui_auto_refresh_preserves_pagination(tmp_path):
    project = _copy_project(tmp_path)
    data = _run_gui_script(project, _REFRESH_PRESERVE_SCRIPT, timeout=240)
    assert data["offset_after_refresh"] == 1000, data
    assert data["offset_after_new_row"] == 1000, (
        f"авто-refresh сбросил Results-пагинацию: {data}"
    )
    assert data["hist_offset_after_refresh"] == 500, data
    assert data["hist_offset_after_new_row"] == 500, (
        f"авто-refresh сбросил History-пагинацию: {data}"
    )
    assert data["offset_after_reset"] == 0, data


# ─────────── _start_proxy(auto=True): валидный порт 0/65536 ───────────

_PORT_VALIDATION_SCRIPT = r"""
import json, sys
sys.path.insert(0, ".")
import notscan


class FakeRunner:
    instances = []

    def __init__(self, host="127.0.0.1", port=8080, log_callback=None,
                 filter_noise=True, **_kw):
        self.host = host
        self.port = port
        self.is_running = False
        self.filter_noise = filter_noise
        FakeRunner.instances.append(self)

    def start(self):
        self.is_running = True

    def stop(self, wait=True):
        self.is_running = False

    def set_filter_noise(self, value):
        self.filter_noise = value


notscan.ProxyRunner = FakeRunner
notscan.port_is_free = lambda host, port: True
app = notscan.App()
out = {}
for label, value in (("zero", "0"), ("too_big", "65536"), ("bad", "abc")):
    app._proxy_runner = None
    app._proxy_port.set(value)
    ok = app._start_proxy(auto=True)
    out[label] = {
        "ok": bool(ok),
        "ui_port": str(app._proxy_port.get()),
        "runner_port": FakeRunner.instances[-1].port if FakeRunner.instances else None,
    }
print("RESULT_JSON " + json.dumps(out))
app._on_closing()
"""


@pytest.mark.integration
def test_gui_internal_start_validates_port(tmp_path):
    project = _copy_project(tmp_path)
    data = _run_gui_script(project, _PORT_VALIDATION_SCRIPT, timeout=240)
    for key in ("zero", "too_big", "bad"):
        item = data[key]
        assert item["ok"] is True, f"{key}: прокси не стартовал на валидном fallback: {data}"
        assert item["runner_port"] == 8080, f"{key}: неверный fallback-порт: {item}"
        assert item["ui_port"] == "8080", f"{key}: UI-порт не скорректирован: {item}"


# ─────────── тексты Help/Tutorial без «авто-старт прокси» ───────────

def test_tutorial_and_docs_do_not_promise_proxy_autostart():
    import notscan

    step_texts = " ".join(
        f"{s.get('title', '')} {s.get('text', '')}" for s in notscan.TUTORIAL_STEPS
    )
    assert "запускается автоматически" not in step_texts
    assert "не запускается сам" in step_texts or "НЕ запускается сам" in step_texts

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    overview = open(os.path.join(root, "docs", "FUNCTIONAL_OVERVIEW.md"),
                    encoding="utf-8").read()
    assert "запускается автоматически" not in overview
