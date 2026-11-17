"""PLAN.md Phase 16 — sign-in required specifically to submit a malware report.

submit_malware_report() now gates on AEGIS_API_KEY (env, checked first) or a
persisted aegis_api_key (Phase 13/14) before doing anything else — no hash
computed, no request built. --audit/--capabilities/--fix must stay entirely
unaffected: this phase must not leak scope beyond the two reporting flags.

Run with:  .venv/bin/python -m pytest tests/test_rex_phase16_report_gate.py -v
"""
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import rex as rexmod  # noqa: E402


@pytest.fixture
def sample_file(tmp_path):
    f = tmp_path / "suspect.exe"
    f.write_bytes(b"not actually malware, just test bytes")
    return f


def test_no_key_anywhere_raises_before_any_network_call(monkeypatch, tmp_path, sample_file):
    monkeypatch.setattr(rexmod, "CONFIG_PATH", str(tmp_path / "cfg.json"))
    monkeypatch.delenv("AEGIS_API_KEY", raising=False)
    called = []
    # If the gate didn't run first, this would raise AttributeError (no
    # fake response shaped right) rather than silently succeeding — either
    # way, `called` being non-empty proves the network was reached.
    monkeypatch.setattr(rexmod.urllib.request, "urlopen",
                         lambda *a, **k: called.append(1))

    with pytest.raises(PermissionError):
        rexmod.submit_malware_report(str(sample_file))

    assert not called, "the gate must run before any request is built, not after it fails"


def test_env_var_satisfies_the_gate_without_touching_config_path(
    monkeypatch, tmp_path, sample_file
):
    cfg_path = tmp_path / "cfg.json"
    monkeypatch.setattr(rexmod, "CONFIG_PATH", str(cfg_path))
    monkeypatch.setenv("AEGIS_API_KEY", "env-key-123")

    import json

    class _FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return json.dumps({"report_id": "r1"}).encode()

    monkeypatch.setattr(rexmod.urllib.request, "urlopen",
                         lambda req, timeout=30: _FakeResponse())

    result = rexmod.submit_malware_report(str(sample_file))

    assert result == {"report_id": "r1"}
    # The env var satisfies the gate on its own — it must not get written to
    # disk as a side effect of being read.
    assert "aegis_api_key" not in rexmod._load_config()


def test_persisted_key_also_satisfies_the_gate(monkeypatch, tmp_path, sample_file):
    monkeypatch.setattr(rexmod, "CONFIG_PATH", str(tmp_path / "cfg.json"))
    monkeypatch.delenv("AEGIS_API_KEY", raising=False)
    rexmod._save_config({"aegis_api_key": "persisted-key"})

    import json

    class _FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return json.dumps({"report_id": "r2"}).encode()

    monkeypatch.setattr(rexmod.urllib.request, "urlopen",
                         lambda req, timeout=30: _FakeResponse())

    result = rexmod.submit_malware_report(str(sample_file))
    assert result == {"report_id": "r2"}


def test_cli_submit_report_without_a_key_exits_usage(monkeypatch, tmp_path, sample_file):
    monkeypatch.setattr(rexmod, "CONFIG_PATH", str(tmp_path / "cfg.json"))
    monkeypatch.delenv("AEGIS_API_KEY", raising=False)
    called = []
    monkeypatch.setattr(rexmod.urllib.request, "urlopen",
                         lambda *a, **k: called.append(1))

    rc = rexmod._cli_main(["--submit-report", str(sample_file)])

    assert rc == rexmod.EXIT_USAGE
    assert not called


# --------------------------------------------------------------------------
# this phase must not leak scope beyond --submit-report/--submit-sample
# --------------------------------------------------------------------------

def test_audit_capabilities_and_fix_are_unaffected_by_the_gate(monkeypatch, tmp_path):
    monkeypatch.setattr(rexmod, "CONFIG_PATH", str(tmp_path / "cfg.json"))
    monkeypatch.delenv("AEGIS_API_KEY", raising=False)

    assert rexmod._cli_main(["--capabilities", "--json"]) == rexmod.EXIT_CLEAN
    assert "aegis_api_key" not in rexmod._load_config()

    rc = rexmod._cli_main(["--audit", "--json"])
    assert rc in (rexmod.EXIT_CLEAN, rexmod.EXIT_FINDINGS)
    assert "aegis_api_key" not in rexmod._load_config()

    # --fix with no finding to act on refuses cleanly (no_finding), same as
    # always — it must not newly demand a sign-in either.
    rc = rexmod._cli_main(["--fix", "not-a-real-section", "--json"])
    assert rc in (rexmod.EXIT_CLEAN, rexmod.EXIT_USAGE)


def test_capabilities_reports_account_required_for_reporting_only(monkeypatch, tmp_path):
    monkeypatch.setattr(rexmod, "CONFIG_PATH", str(tmp_path / "cfg.json"))
    anon = rexmod.capabilities()["anonymity"]
    assert anon["account_required"] is False
    assert set(anon["account_required_for"]) == {"--submit-report", "--submit-sample"}


# --------------------------------------------------------------------------
# --sign-in
# --------------------------------------------------------------------------

def test_sign_in_google_persists_key(monkeypatch, tmp_path):
    monkeypatch.setattr(rexmod, "CONFIG_PATH", str(tmp_path / "cfg.json"))

    import http.client
    import webbrowser
    from urllib.parse import parse_qs, urlparse

    def fake_open(url):
        cb = parse_qs(urlparse(url).query)["callback"][0]
        p = urlparse(cb)
        conn = http.client.HTTPConnection(p.hostname, p.port, timeout=5)
        conn.request("GET", "/?token=tok1&username=carol")
        conn.getresponse().read()
        conn.close()
    monkeypatch.setattr(webbrowser, "open", fake_open)

    rc = rexmod._cli_main(["--sign-in", "google", "--json"])

    assert rc == rexmod.EXIT_CLEAN
    assert rexmod._load_config()["aegis_api_key"] == "tok1"


def test_sign_in_key_prompts_stdin_and_persists_key(monkeypatch, tmp_path):
    monkeypatch.setattr(rexmod, "CONFIG_PATH", str(tmp_path / "cfg.json"))
    monkeypatch.setattr("builtins.input", lambda prompt="": "pasted-key")

    import json

    class _FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return json.dumps({"valid": True, "plan": "free"}).encode()

    monkeypatch.setattr(rexmod.urllib.request, "urlopen",
                         lambda req, timeout=10: _FakeResponse())

    rc = rexmod._cli_main(["--sign-in", "key", "--json"])

    assert rc == rexmod.EXIT_CLEAN
    assert rexmod._load_config()["aegis_api_key"] == "pasted-key"


def test_sign_in_failure_exits_usage(monkeypatch, tmp_path):
    monkeypatch.setattr(rexmod, "CONFIG_PATH", str(tmp_path / "cfg.json"))
    monkeypatch.setattr("builtins.input", lambda prompt="": "bad-key")

    import json

    class _FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return json.dumps({"valid": False}).encode()

    monkeypatch.setattr(rexmod.urllib.request, "urlopen",
                         lambda req, timeout=10: _FakeResponse())

    rc = rexmod._cli_main(["--sign-in", "key"])

    assert rc == rexmod.EXIT_USAGE
    assert "aegis_api_key" not in rexmod._load_config()
