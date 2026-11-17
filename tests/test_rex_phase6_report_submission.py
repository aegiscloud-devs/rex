"""PLAN.md Phase 6 — rex.py: report-submission CLI capability.

submit_malware_report() is user-initiated only (--submit-report /
--submit-sample); nothing on the audit path calls it. These tests cover the
phase's "done when" list: a persisted (not per-call) install_id, the
--report / --submit-report flag collision, the --submit-sample upload cap
refusing before anything is read or sent, a network failure mapping to
EXIT_NETWORK without raising out of the CLI, and the request body carrying
only the file's basename.

Run with:  .venv/bin/python -m pytest tests/test_rex_phase6_report_submission.py -v
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


def _fake_urlopen(captured, response=None):
    def _urlopen(req, timeout=30):
        captured.append(json.loads(req.data.decode("utf-8")))
        return _FakeResponse(response or {"report_id": "r1", "verdict": "pending"})
    return _urlopen


@pytest.fixture
def sample_file(tmp_path):
    sub = tmp_path / "evidence"
    sub.mkdir()
    f = sub / "suspect.exe"
    f.write_bytes(b"not actually malware, just test bytes")
    return f


# --------------------------------------------------------------------------
# install_id persistence
# --------------------------------------------------------------------------

def test_two_calls_in_the_same_process_send_the_same_install_id(
    monkeypatch, tmp_path, sample_file
):
    monkeypatch.setattr(rexmod, "CONFIG_PATH", str(tmp_path / "cfg.json"))
    captured = []
    monkeypatch.setattr(rexmod.urllib.request, "urlopen", _fake_urlopen(captured))

    rexmod.submit_malware_report(str(sample_file))
    rexmod.submit_malware_report(str(sample_file))

    assert len(captured) == 2
    assert captured[0]["install_id"] == captured[1]["install_id"]
    assert captured[0]["install_id"]  # non-empty


def test_a_fresh_config_path_produces_a_different_install_id(
    monkeypatch, tmp_path, sample_file
):
    captured = []
    monkeypatch.setattr(rexmod.urllib.request, "urlopen", _fake_urlopen(captured))

    monkeypatch.setattr(rexmod, "CONFIG_PATH", str(tmp_path / "install-a.json"))
    rexmod.submit_malware_report(str(sample_file))

    monkeypatch.setattr(rexmod, "CONFIG_PATH", str(tmp_path / "install-b.json"))
    rexmod.submit_malware_report(str(sample_file))

    assert captured[0]["install_id"] != captured[1]["install_id"]


# --------------------------------------------------------------------------
# --report / --submit-report must not collide
# --------------------------------------------------------------------------

def test_report_and_submit_report_resolve_to_distinct_flags():
    parser = rexmod._build_argparser()

    args = parser.parse_args(["--report", "saved.json"])
    assert args.report == "saved.json"
    assert args.submit_report is None

    args = parser.parse_args(["--submit-report", "suspect.exe"])
    assert args.submit_report == "suspect.exe"
    assert args.report is None


# --------------------------------------------------------------------------
# --submit-sample upload cap
# --------------------------------------------------------------------------

def test_submit_sample_over_cap_refuses_before_reading_or_sending(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(rexmod, "MAX_SAMPLE_BYTES", 4)
    big = tmp_path / "big.bin"
    big.write_bytes(b"12345")  # 5 bytes > the monkeypatched 4-byte cap

    called = []
    monkeypatch.setattr(rexmod.urllib.request, "urlopen",
                         lambda *a, **k: called.append(1))

    with pytest.raises(rexmod.RexSubmitTooLarge):
        rexmod.submit_malware_report(str(big), include_bytes=True)
    assert not called, "a file over the cap must never reach the network"


def test_cli_submit_sample_over_cap_exits_usage_without_network(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(rexmod, "MAX_SAMPLE_BYTES", 4)
    monkeypatch.setattr(rexmod, "CONFIG_PATH", str(tmp_path / "cfg.json"))
    big = tmp_path / "big.bin"
    big.write_bytes(b"12345")

    called = []
    monkeypatch.setattr(rexmod.urllib.request, "urlopen",
                         lambda *a, **k: called.append(1))

    rc = rexmod._cli_main(["--submit-sample", str(big)])
    assert rc == rexmod.EXIT_USAGE
    assert not called


# --------------------------------------------------------------------------
# network failure -> EXIT_NETWORK, never raises out of the CLI
# --------------------------------------------------------------------------

def test_cli_submit_report_network_failure_returns_exit_network(
    monkeypatch, tmp_path, sample_file
):
    monkeypatch.setattr(rexmod, "CONFIG_PATH", str(tmp_path / "cfg.json"))

    def _boom(*a, **k):
        raise rexmod.urllib.error.URLError("no route to host")
    monkeypatch.setattr(rexmod.urllib.request, "urlopen", _boom)

    rc = rexmod._cli_main(["--submit-report", str(sample_file)])
    assert rc == rexmod.EXIT_NETWORK


def test_cli_submit_report_missing_file_exits_usage(tmp_path):
    rc = rexmod._cli_main(["--submit-report", str(tmp_path / "does-not-exist")])
    assert rc == rexmod.EXIT_USAGE


# --------------------------------------------------------------------------
# request body: basename only, never the full path
# --------------------------------------------------------------------------

def test_file_name_in_payload_is_basename_only(monkeypatch, tmp_path, sample_file):
    monkeypatch.setattr(rexmod, "CONFIG_PATH", str(tmp_path / "cfg.json"))
    captured = []
    monkeypatch.setattr(rexmod.urllib.request, "urlopen", _fake_urlopen(captured))

    rexmod.submit_malware_report(str(sample_file))

    assert captured[0]["file_name"] == "suspect.exe"
    assert str(sample_file.parent) not in captured[0]["file_name"]
    assert "/" not in captured[0]["file_name"]


def test_submit_sample_includes_bytes_submit_report_does_not(
    monkeypatch, tmp_path, sample_file
):
    monkeypatch.setattr(rexmod, "CONFIG_PATH", str(tmp_path / "cfg.json"))
    captured = []
    monkeypatch.setattr(rexmod.urllib.request, "urlopen", _fake_urlopen(captured))

    rexmod.submit_malware_report(str(sample_file), include_bytes=False)
    rexmod.submit_malware_report(str(sample_file), include_bytes=True)

    assert "sample" not in captured[0]
    assert "sample" in captured[1]
    import base64 as _b64
    assert _b64.b64decode(captured[1]["sample"]) == sample_file.read_bytes()


# --------------------------------------------------------------------------
# capabilities() contract surfaces
# --------------------------------------------------------------------------

def test_capabilities_documents_the_new_flags_and_exit_code():
    cap = rexmod.capabilities()
    flags = {c["flag"] for c in cap["commands"]}
    assert "--submit-report" in flags
    assert "--submit-sample" in flags
    assert str(rexmod.EXIT_NETWORK) in cap["exit_codes"]


def test_install_id_not_minted_by_capabilities_or_audit(monkeypatch, tmp_path):
    """Calling --capabilities or --audit must not write rex_install_id to
    config — only an explicit --submit-report/--submit-sample may."""
    cfg_path = tmp_path / "cfg.json"
    monkeypatch.setattr(rexmod, "CONFIG_PATH", str(cfg_path))

    rexmod._cli_main(["--capabilities", "--json"])
    assert not cfg_path.exists() or "rex_install_id" not in rexmod._load_config()

    rexmod._cli_main(["--audit", "--json"])
    assert "rex_install_id" not in rexmod._load_config()
