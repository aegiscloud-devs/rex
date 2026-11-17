"""PLAN.md Phases 13-14 — rex.py: Google sign-in and pasted-API-key sign-in.

Both reuse aegis1's existing, already-proven endpoints (`/auth/google`'s
desktop-callback round-trip and `/api/v1/auth/validate-key`) rather than
inventing a new protocol. These tests drive the real local handler
(_google_sign_in) end-to-end through a mocked `webbrowser.open` that acts as
the browser completing the round-trip, and drive _verify_aegis_key through a
mocked `urlopen` — never the network.

Run with:  .venv/bin/python -m pytest tests/test_rex_phase13_14_signin.py -v
"""
import http.client
import json
import pathlib
import socket
import sys
import webbrowser
from urllib.parse import parse_qs, urlparse

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import rex as rexmod  # noqa: E402


def _callback_from(url):
    """Pull the ?callback= rex handed to aegis1's /auth/google out of the
    URL _google_sign_in opened — this is what a real browser would land on
    after the user finishes Google's consent screen."""
    return parse_qs(urlparse(url).query)["callback"][0]


def _hit_callback(url, query):
    """Simulate the browser's final GET to rex's one-shot loopback server."""
    cb = urlparse(_callback_from(url))
    conn = http.client.HTTPConnection(cb.hostname, cb.port, timeout=5)
    conn.request("GET", "/?" + query)
    conn.getresponse().read()
    conn.close()


# --------------------------------------------------------------------------
# Phase 13 — Google sign-in
# --------------------------------------------------------------------------

def test_google_sign_in_success_resolves_dict_and_persists_key(monkeypatch, tmp_path):
    monkeypatch.setattr(rexmod, "CONFIG_PATH", str(tmp_path / "cfg.json"))
    monkeypatch.setattr(
        webbrowser, "open",
        lambda url: _hit_callback(url, "token=tok123&username=alice&memory_token=mt1"),
    )

    result = rexmod._google_sign_in(timeout=5)

    assert result == {"api_key": "tok123", "username": "alice", "memory_token": "mt1"}
    assert rexmod._load_config() == {"aegis_api_key": "tok123", "aegis_username": "alice"}


def test_google_sign_in_error_callback_raises_and_persists_nothing(monkeypatch, tmp_path):
    cfg_path = tmp_path / "cfg.json"
    monkeypatch.setattr(rexmod, "CONFIG_PATH", str(cfg_path))
    monkeypatch.setattr(
        webbrowser, "open",
        lambda url: _hit_callback(url, "error=access_denied"),
    )

    with pytest.raises(RuntimeError, match="access_denied"):
        rexmod._google_sign_in(timeout=5)

    assert not cfg_path.exists() or "aegis_api_key" not in rexmod._load_config()


def test_google_sign_in_timeout_raises_and_frees_the_port(monkeypatch, tmp_path):
    monkeypatch.setattr(rexmod, "CONFIG_PATH", str(tmp_path / "cfg.json"))
    opened = {}

    def fake_open(url):
        opened["port"] = int(urlparse(_callback_from(url)).port)
        # The browser never completes the round-trip — simulates the user
        # closing the tab, denying consent with no redirect, etc.

    monkeypatch.setattr(webbrowser, "open", fake_open)

    with pytest.raises(TimeoutError):
        rexmod._google_sign_in(timeout=0.3)

    # Not just "the call returned" — the listening socket must actually be
    # released, or a second sign-in attempt would eventually exhaust ports.
    # The daemon thread blocked in accept() releases the fd asynchronously
    # relative to server_close() returning, so poll briefly rather than
    # asserting on the first attempt.
    import time
    deadline = time.monotonic() + 1
    last_err = None
    while time.monotonic() < deadline:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("127.0.0.1", opened["port"]))
            probe.close()
            break
        except OSError as e:
            last_err = e
            probe.close()
            time.sleep(0.05)
    else:
        raise AssertionError(f"port {opened['port']} never freed: {last_err}")


# --------------------------------------------------------------------------
# Phase 14 — pasted AEGIS Cloud API key
# --------------------------------------------------------------------------

class _FakeResponse:
    def __init__(self, body):
        self._body = json.dumps(body).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._body


def test_verify_aegis_key_valid_persists_key_and_sends_version_header(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(rexmod, "CONFIG_PATH", str(tmp_path / "cfg.json"))
    captured = []

    def fake_urlopen(req, timeout=10):
        captured.append(req)
        return _FakeResponse({"valid": True, "plan": "free", "version": rexmod.VERSION})
    monkeypatch.setattr(rexmod.urllib.request, "urlopen", fake_urlopen)

    data = rexmod._verify_aegis_key("good-key")

    assert data["valid"] is True
    assert rexmod._load_config()["aegis_api_key"] == "good-key"
    assert captured[0].headers.get("X-aegis-version") == rexmod.VERSION


def test_verify_aegis_key_invalid_raises_and_persists_nothing(monkeypatch, tmp_path):
    cfg_path = tmp_path / "cfg.json"
    monkeypatch.setattr(rexmod, "CONFIG_PATH", str(cfg_path))
    monkeypatch.setattr(
        rexmod.urllib.request, "urlopen",
        lambda req, timeout=10: _FakeResponse({"valid": False}),
    )

    with pytest.raises(ValueError):
        rexmod._verify_aegis_key("bad-key")

    assert not cfg_path.exists() or "aegis_api_key" not in rexmod._load_config()


def test_verify_aegis_key_network_failure_propagates(monkeypatch, tmp_path):
    monkeypatch.setattr(rexmod, "CONFIG_PATH", str(tmp_path / "cfg.json"))

    def _boom(req, timeout=10):
        raise rexmod.urllib.error.URLError("no route to host")
    monkeypatch.setattr(rexmod.urllib.request, "urlopen", _boom)

    with pytest.raises(rexmod.urllib.error.URLError):
        rexmod._verify_aegis_key("whatever-key")
