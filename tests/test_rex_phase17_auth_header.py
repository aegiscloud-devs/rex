"""PLAN.md Phase 17 — rex.py's half: submit_malware_report() sends
Authorization: Bearer <aegis_api_key>, so aegis1 can key the
distinct-reporter count by account instead of the self-asserted install_id.

Run with:  .venv/bin/python -m pytest tests/test_rex_phase17_auth_header.py -v
"""
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import rex as rexmod  # noqa: E402


class _FakeResponse:
    def __init__(self, body):
        self._body = json.dumps(body).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._body


@pytest.fixture
def sample_file(tmp_path):
    f = tmp_path / "suspect.exe"
    f.write_bytes(b"not actually malware, just test bytes")
    return f


def test_env_var_key_rides_as_authorization_bearer(monkeypatch, tmp_path, sample_file):
    monkeypatch.setattr(rexmod, "CONFIG_PATH", str(tmp_path / "cfg.json"))
    monkeypatch.setenv("AEGIS_API_KEY", "env-key-abc")
    captured = []
    monkeypatch.setattr(
        rexmod.urllib.request, "urlopen",
        lambda req, timeout=30: (captured.append(req), _FakeResponse({"ok": True}))[1],
    )

    rexmod.submit_malware_report(str(sample_file))

    assert captured[0].headers.get("Authorization") == "Bearer env-key-abc"


def test_persisted_key_rides_as_authorization_bearer(monkeypatch, tmp_path, sample_file):
    monkeypatch.setattr(rexmod, "CONFIG_PATH", str(tmp_path / "cfg.json"))
    monkeypatch.delenv("AEGIS_API_KEY", raising=False)
    rexmod._save_config({"aegis_api_key": "persisted-key-xyz"})
    captured = []
    monkeypatch.setattr(
        rexmod.urllib.request, "urlopen",
        lambda req, timeout=30: (captured.append(req), _FakeResponse({"ok": True}))[1],
    )

    rexmod.submit_malware_report(str(sample_file))

    assert captured[0].headers.get("Authorization") == "Bearer persisted-key-xyz"


def test_env_var_takes_precedence_over_persisted_key_in_the_header_too(
    monkeypatch, tmp_path, sample_file
):
    monkeypatch.setattr(rexmod, "CONFIG_PATH", str(tmp_path / "cfg.json"))
    rexmod._save_config({"aegis_api_key": "persisted-key"})
    monkeypatch.setenv("AEGIS_API_KEY", "env-key-wins")
    captured = []
    monkeypatch.setattr(
        rexmod.urllib.request, "urlopen",
        lambda req, timeout=30: (captured.append(req), _FakeResponse({"ok": True}))[1],
    )

    rexmod.submit_malware_report(str(sample_file))

    assert captured[0].headers.get("Authorization") == "Bearer env-key-wins"
