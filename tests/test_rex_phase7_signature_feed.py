"""PLAN.md Phase 7 — rex.py: consume the signature feed during a scan.

Covers the phase's "done when" list: a fetch timeout yields a normal
report with feed_status marked unavailable and the exit-code-driving
status unchanged; a fresh cache causes zero network calls; a cache older
than 24h is refetched; and the feed overlay invokes clamscan with an argv
list containing a -d variant, once, never a shell string. Also covers the
hard prerequisite from Phase 10: feed-sourced hits are tagged
SIGNATURE_SOURCE_FEED (or "mixed" alongside a local hit), never merged as
if they were local ClamAV findings.

Run with:  .venv/bin/python -m pytest tests/test_rex_phase7_signature_feed.py -v
"""
import os
import pathlib
import platform
import sys
import time

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import rex as rexmod  # noqa: E402

# platform.platform() lazily shells out to `uname -p` once per process and
# caches the result in the stdlib module itself. build_report() calls it
# (platform_detail). Warm that cache now, before any test below monkeypatches
# subprocess.Popen — otherwise whichever test happens to trigger the first
# real call does so with Popen mocked and breaks on an unrelated call.
platform.platform()


class _FakePopen:
    """Stand-in for the local clamscan/clamdscan subprocess.Popen in
    _run_section: an iterable .stdout and a no-op .wait()."""

    def __init__(self, lines):
        self.stdout = iter(lines)

    def wait(self):
        return 0


class _FakeResponse:
    def __init__(self, body: bytes):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._body


def _engine(tmp_path, monkeypatch, which_map=None):
    which_map = which_map or {"clamscan": "/fake/clamscan"}
    monkeypatch.setattr(rexmod.shutil, "which",
                         lambda name: which_map.get(name))
    return rexmod.AuditEngine(sections=[rexmod.VIRUS_SECTION], scan_path=str(tmp_path))


# --------------------------------------------------------------------------
# _fetch_extra_signatures: caching contract
# --------------------------------------------------------------------------

def test_fresh_cache_causes_zero_network_calls(monkeypatch, tmp_path):
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    hdb = cache_dir / "signatures.hdb"
    hdb.write_text("deadbeef:10:Rex.Reported.deadbeef\n")  # mtime = now, fresh

    called = []
    monkeypatch.setattr(rexmod.urllib.request, "urlopen",
                         lambda *a, **k: called.append(1))

    path, status = rexmod._fetch_extra_signatures(str(cache_dir))
    assert status == "fresh"
    assert path == str(hdb)
    assert not called


def test_stale_cache_is_refetched(monkeypatch, tmp_path):
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    hdb = cache_dir / "signatures.hdb"
    hdb.write_text("old content\n")
    stale = time.time() - rexmod.FEED_CACHE_MAX_AGE - 10
    os.utime(hdb, (stale, stale))

    calls = []
    monkeypatch.setattr(
        rexmod.urllib.request, "urlopen",
        lambda url, timeout=10: (calls.append(url),
                                  _FakeResponse(b"newsha:5:Rex.Reported.newsha\n"))[1],
    )

    path, status = rexmod._fetch_extra_signatures(str(cache_dir))
    assert status == "refetched"
    assert len(calls) == 1
    assert hdb.read_text() == "newsha:5:Rex.Reported.newsha\n"


def test_missing_cache_triggers_a_fetch(monkeypatch, tmp_path):
    cache_dir = tmp_path / "no-cache-yet"
    monkeypatch.setattr(rexmod.urllib.request, "urlopen",
                         lambda *a, **k: _FakeResponse(b"abc:1:x\n"))

    path, status = rexmod._fetch_extra_signatures(str(cache_dir))
    assert status == "refetched"
    assert os.path.exists(path)


def test_fetch_timeout_returns_unavailable_without_raising(monkeypatch, tmp_path):
    def _boom(*a, **k):
        raise TimeoutError("timed out")
    monkeypatch.setattr(rexmod.urllib.request, "urlopen", _boom)

    path, status = rexmod._fetch_extra_signatures(str(tmp_path / "cache"))
    assert path is None
    assert status == "unavailable"


# --------------------------------------------------------------------------
# virus-scan section: feed overlay invocation and merge
# --------------------------------------------------------------------------

def test_feed_threats_tagged_and_merged_with_local(monkeypatch, tmp_path):
    eng = _engine(tmp_path, monkeypatch)
    monkeypatch.setattr(
        rexmod.subprocess, "Popen",
        lambda *a, **k: _FakePopen([f"{tmp_path}/a.txt: Eicar-Test-Signature FOUND"]),
    )
    monkeypatch.setattr(rexmod, "_fetch_extra_signatures",
                         lambda *a, **k: ("/fake/signatures.hdb", "refetched"))

    cmd_calls = []

    def fake_cmd(args, timeout=10):
        cmd_calls.append(args)
        return f"{tmp_path}/b.txt: Rex.Reported.deadbeef FOUND"

    monkeypatch.setattr(rexmod.AuditEngine, "_cmd", staticmethod(fake_cmd))

    status, output = eng._run_section(rexmod.VIRUS_SECTION)

    assert status == "critical"
    assert f"[{rexmod.SIGNATURE_SOURCE_LOCAL}]" in output
    assert f"[{rexmod.SIGNATURE_SOURCE_FEED}]" in output
    assert "[feed_status:refetched]" in output

    assert len(cmd_calls) == 1, "the feed overlay must run exactly once"
    args = cmd_calls[0]
    assert isinstance(args, list), "clamscan must be invoked with an argv list, not a shell string"
    assert "-d" in args
    assert "/fake/signatures.hdb" in args
    assert args[args.index("-d") + 1] == "/fake/signatures.hdb"

    report = rexmod.build_report({rexmod.VIRUS_SECTION: (status, output)})
    finding = report["findings"][0]
    assert finding["signature_source"] == "mixed"
    assert finding["feed_status"] == "refetched"


def test_feed_only_hit_is_tagged_feed_confirmed_not_local(monkeypatch, tmp_path):
    eng = _engine(tmp_path, monkeypatch)
    monkeypatch.setattr(rexmod.subprocess, "Popen", lambda *a, **k: _FakePopen([]))
    monkeypatch.setattr(rexmod, "_fetch_extra_signatures",
                         lambda *a, **k: ("/fake/signatures.hdb", "refetched"))
    monkeypatch.setattr(
        rexmod.AuditEngine, "_cmd", staticmethod(
            lambda args, timeout=10: f"{tmp_path}/c.txt: Rex.Reported.feedhash FOUND"
        ),
    )

    status, output = eng._run_section(rexmod.VIRUS_SECTION)
    assert status == "critical"

    report = rexmod.build_report({rexmod.VIRUS_SECTION: (status, output)})
    finding = report["findings"][0]
    assert finding["signature_source"] == rexmod.SIGNATURE_SOURCE_FEED
    # never counted/merged as if it were a local ClamAV hit:
    assert f"[{rexmod.SIGNATURE_SOURCE_LOCAL}]" not in output


def test_feed_unavailable_does_not_fail_the_scan_and_skips_the_overlay(
    monkeypatch, tmp_path
):
    eng = _engine(tmp_path, monkeypatch)
    monkeypatch.setattr(rexmod.subprocess, "Popen", lambda *a, **k: _FakePopen([]))
    monkeypatch.setattr(rexmod, "_fetch_extra_signatures",
                         lambda *a, **k: (None, "unavailable"))

    called = []
    monkeypatch.setattr(
        rexmod.AuditEngine, "_cmd",
        staticmethod(lambda *a, **k: called.append(1) or ""),
    )

    status, output = eng._run_section(rexmod.VIRUS_SECTION)

    assert status == "ok", "a feed outage must not turn a clean scan into an error"
    assert "[feed_status:unavailable]" in output
    assert not called, "no feed file -> clamscan must never be invoked with -d"

    report = rexmod.build_report({rexmod.VIRUS_SECTION: (status, output)})
    finding = report["findings"][0]
    assert finding["feed_status"] == "unavailable"
    assert "signature_source" not in finding


def test_real_fetch_timeout_end_to_end_yields_ok_report_with_unavailable(
    monkeypatch, tmp_path
):
    """The literal 'done when' case: a fetch timeout (not a pre-mocked
    _fetch_extra_signatures) still yields a normal report."""
    eng = _engine(tmp_path, monkeypatch)
    monkeypatch.setattr(rexmod.subprocess, "Popen", lambda *a, **k: _FakePopen([]))

    def _boom(*a, **k):
        raise TimeoutError("timed out")
    monkeypatch.setattr(rexmod.urllib.request, "urlopen", _boom)
    monkeypatch.setattr(rexmod, "_feed_cache_dir", lambda: str(tmp_path / "cache"))

    cmd_calls = []
    monkeypatch.setattr(
        rexmod.AuditEngine, "_cmd",
        staticmethod(lambda args, timeout=10: cmd_calls.append(args) or ""),
    )

    status, output = eng._run_section(rexmod.VIRUS_SECTION)

    assert status == "ok"
    assert "[feed_status:unavailable]" in output
    assert not cmd_calls
    # exit-code-driving status is "ok" regardless of the feed outcome —
    # EXIT_CLEAN under the default --fail-on, same as if Phase 7 did not exist.
    report = rexmod.build_report({rexmod.VIRUS_SECTION: (status, output)})
    assert report["findings"][0]["status"] == "ok"


def test_no_clamscan_binary_skips_overlay_without_crashing(monkeypatch, tmp_path):
    eng = _engine(tmp_path, monkeypatch, which_map={})  # clamscan absent entirely
    # local scan path also finds no scanner -> warn, returned before any
    # feed logic runs; use clamdscan present instead so the local pass
    # proceeds and the feed overlay is the thing being exercised.
    monkeypatch.setattr(eng, "scan_path_explicit", True)
    monkeypatch.setattr(
        rexmod.shutil, "which",
        lambda name: "/fake/clamdscan" if name == "clamdscan" else None,
    )
    monkeypatch.setattr(rexmod, "_clamd_up", lambda: True)
    monkeypatch.setattr(rexmod.subprocess, "Popen", lambda *a, **k: _FakePopen([]))
    monkeypatch.setattr(rexmod, "_fetch_extra_signatures",
                         lambda *a, **k: ("/fake/signatures.hdb", "fresh"))

    called = []
    monkeypatch.setattr(
        rexmod.AuditEngine, "_cmd",
        staticmethod(lambda *a, **k: called.append(1) or ""),
    )

    status, output = eng._run_section(rexmod.VIRUS_SECTION)
    assert status == "ok"
    assert not called, "no clamscan binary anywhere -> the -d overlay cannot run"
