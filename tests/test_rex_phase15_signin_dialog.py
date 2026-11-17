"""PLAN.md Phase 15 — SignInDialog's own button wiring.

Separate from test_rex_phase15_signin_gate.py (which covers main()'s
once-per-profile gating without touching real Qt): these tests construct
the real dialog under the offscreen QPA platform and click through it, so
the Google/QThread bridge and the synchronous key-verify path are each
exercised end-to-end, not just asserted by reading the code.

Requires QT_QPA_PLATFORM=offscreen (set here, not relied on from the
environment, so this file runs the same under any invocation):
  .venv/bin/python -m pytest tests/test_rex_phase15_signin_dialog.py -v
"""
import http.client
import json
import os
import pathlib
import sys
import time
import webbrowser
from urllib.parse import parse_qs, urlparse

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import rex as rexmod  # noqa: E402

pytestmark = pytest.mark.skipif(not rexmod.HAS_QT, reason="PyQt6 not installed")


@pytest.fixture(scope="module")
def qapp():
    return rexmod.QApplication.instance() or rexmod.QApplication([])


def _pump(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rexmod.QApplication.processEvents()
        if predicate():
            return True
        time.sleep(0.02)
    return False


def test_google_button_success_persists_key_and_accepts(qapp, monkeypatch, tmp_path):
    monkeypatch.setattr(rexmod, "CONFIG_PATH", str(tmp_path / "cfg.json"))

    def fake_open(url):
        cb = parse_qs(urlparse(url).query)["callback"][0]
        p = urlparse(cb)
        conn = http.client.HTTPConnection(p.hostname, p.port, timeout=5)
        conn.request("GET", "/?token=tok1&username=bob&memory_token=mt1")
        conn.getresponse().read()
        conn.close()
    monkeypatch.setattr(webbrowser, "open", fake_open)

    dialog = rexmod.SignInDialog()
    accepted = []
    dialog.accepted.connect(lambda: accepted.append(1))
    dialog.btn_google.click()

    assert _pump(lambda: dialog.result is not None)
    assert dialog.result == {"api_key": "tok1", "username": "bob", "memory_token": "mt1"}
    assert accepted == [1]
    assert rexmod._load_config()["aegis_api_key"] == "tok1"


def test_google_button_failure_shows_error_and_persists_nothing(qapp, monkeypatch, tmp_path):
    cfg_path = tmp_path / "cfg.json"
    monkeypatch.setattr(rexmod, "CONFIG_PATH", str(cfg_path))

    def fake_open(url):
        cb = parse_qs(urlparse(url).query)["callback"][0]
        p = urlparse(cb)
        conn = http.client.HTTPConnection(p.hostname, p.port, timeout=5)
        conn.request("GET", "/?error=access_denied")
        conn.getresponse().read()
        conn.close()
    monkeypatch.setattr(webbrowser, "open", fake_open)

    dialog = rexmod.SignInDialog()
    accepted = []
    dialog.accepted.connect(lambda: accepted.append(1))
    dialog.btn_google.click()

    assert _pump(lambda: "access_denied" in dialog.status.text())
    assert dialog.result is None
    assert accepted == []
    assert not cfg_path.exists() or "aegis_api_key" not in rexmod._load_config()


def test_key_button_valid_key_persists_and_accepts(qapp, monkeypatch, tmp_path):
    monkeypatch.setattr(rexmod, "CONFIG_PATH", str(tmp_path / "cfg.json"))

    class _FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return json.dumps({"valid": True, "plan": "free"}).encode()

    monkeypatch.setattr(rexmod.urllib.request, "urlopen",
                         lambda req, timeout=10: _FakeResponse())

    dialog = rexmod.SignInDialog()
    accepted = []
    dialog.accepted.connect(lambda: accepted.append(1))
    dialog.btn_key.click()
    dialog.key_input.setText("good-key")
    dialog.btn_verify.click()

    assert accepted == [1]
    assert dialog.result == {"api_key": "good-key", "plan": "free"}
    assert rexmod._load_config()["aegis_api_key"] == "good-key"


def test_key_button_invalid_key_shows_error_and_persists_nothing(qapp, monkeypatch, tmp_path):
    cfg_path = tmp_path / "cfg.json"
    monkeypatch.setattr(rexmod, "CONFIG_PATH", str(cfg_path))

    class _FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return json.dumps({"valid": False}).encode()

    monkeypatch.setattr(rexmod.urllib.request, "urlopen",
                         lambda req, timeout=10: _FakeResponse())

    dialog = rexmod.SignInDialog()
    accepted = []
    dialog.accepted.connect(lambda: accepted.append(1))
    dialog.btn_key.click()
    dialog.key_input.setText("bad-key")
    dialog.btn_verify.click()

    assert accepted == []
    assert dialog.result is None
    assert not cfg_path.exists() or "aegis_api_key" not in rexmod._load_config()


def test_skip_button_rejects_without_touching_config(qapp, monkeypatch, tmp_path):
    cfg_path = tmp_path / "cfg.json"
    monkeypatch.setattr(rexmod, "CONFIG_PATH", str(cfg_path))

    dialog = rexmod.SignInDialog()
    rejected = []
    dialog.rejected.connect(lambda: rejected.append(1))
    dialog.btn_skip.click()

    assert rejected == [1]
    assert dialog.result is None
    assert not cfg_path.exists()
