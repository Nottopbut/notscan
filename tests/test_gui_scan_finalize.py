"""Регресс «скан повис после N запросов и ждал Stop».

Сценарий: payload-задач нет (включены только passive/probe-чеки), но запущены
вспомогательные потоки. Раньше `_build_and_run` возвращался без `_scan_finished`,
и GUI навсегда оставался в состоянии «сканируется» (progress 9/N, кнопка Stop).
Теперь после завершения aux-потоков скан финализируется сам.
"""

import json

import pytest

from tests.test_gui_catalog import _copy_project, _run_gui_script

_SCRIPT = r"""
import json, sys, time
sys.path.insert(0, ".")
import notscan
import db

app = notscan.App()
app.update()

# одна history-запись, чтобы Scan list был непустым
hid = db.insert_history(method="GET", url="http://127.0.0.1:9/x",
                        req_headers={}, req_body=None, resp_status=200,
                        resp_headers={}, resp_body_preview=b"ok")
rec = db.fetch_history_by_id(hid)
app._scan_list = {hid: rec}

# Только probe-чек: payload-задач не будет, но probe-поток запускается.
for cid, var in app._check_vars.items():
    var.set(cid == "host_header_injection")
app._preflight_auth = lambda history_ids: True
app._private_scope_approved = True

def fake_probe(urls, probe_ids):
    time.sleep(0.6)
    app.log("[TEST] fake probe done")
    return 0
app._run_probe_scan = fake_probe

state = {"done": False, "progress": "", "elapsed": 0.0}
t0 = time.time()

def poll():
    state["progress"] = str(app._scan_progress.cget("text"))
    if app._scan_runner is None and state["progress"] == "Done":
        state["done"] = True
        state["elapsed"] = round(time.time() - t0, 1)
        print("RESULT_JSON " + json.dumps(state))
        app._on_closing()
        return
    if time.time() - t0 > 15:
        state["elapsed"] = round(time.time() - t0, 1)
        print("RESULT_JSON " + json.dumps(state))
        app._on_closing()
        return
    app.after(100, poll)

app._run_scan()
app.after(100, poll)
app.mainloop()
"""


@pytest.mark.integration
def test_gui_scan_with_only_aux_checks_finalizes(tmp_path):
    project = _copy_project(tmp_path)
    data = _run_gui_script(project, _SCRIPT, language="en", timeout=120)
    assert data["done"] is True, f"скан не финализировался сам: {data}"
    assert data["elapsed"] < 10, data
