"""PLAN.md Phase 20 — ARTEX/BLOODALCHEMY campaign detection in rex.py.

Covers: the network-IOC feed's caching/fail-open contract (same vocabulary
as _fetch_extra_signatures, Phase 7); _network_ioc_alerts matching a live
connection's remote IP against the IOC list while leaving "domain" entries
informational-only; and _artex_process_alerts flagging known ARTEX artifact
names and the shell-spawned-by-web-server lineage pattern, without flagging
an ordinary shell with an unrelated parent.

Run with:  .venv/bin/python -m pytest tests/test_rex_artex_detection.py -v
"""
import os
import pathlib
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import rex as rexmod  # noqa: E402


class _FakeResponse:
    def __init__(self, body: bytes):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._body


# --------------------------------------------------------------------------
# _fetch_network_iocs: caching contract, mirrors _fetch_extra_signatures
# --------------------------------------------------------------------------

def test_fresh_cache_causes_zero_network_calls(monkeypatch, tmp_path):
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    cached = cache_dir / "network-iocs.json"
    cached.write_text('{"entries": [{"type": "ip", "value": "1.2.3.4", "campaign": "X"}]}')

    called = []
    monkeypatch.setattr(rexmod.urllib.request, "urlopen",
                         lambda *a, **k: called.append(1))

    entries, status = rexmod._fetch_network_iocs(str(cache_dir))
    assert status == "fresh"
    assert entries == [{"type": "ip", "value": "1.2.3.4", "campaign": "X"}]
    assert not called


def test_stale_cache_is_refetched(monkeypatch, tmp_path):
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    cached = cache_dir / "network-iocs.json"
    cached.write_text('{"entries": []}')
    stale = time.time() - rexmod.NETWORK_IOC_CACHE_MAX_AGE - 10
    os.utime(cached, (stale, stale))

    new_body = b'{"entries": [{"type": "ip", "value": "9.9.9.9", "campaign": "Y"}]}'
    calls = []
    monkeypatch.setattr(
        rexmod.urllib.request, "urlopen",
        lambda url, timeout=10: (calls.append(url), _FakeResponse(new_body))[1],
    )

    entries, status = rexmod._fetch_network_iocs(str(cache_dir))
    assert status == "refetched"
    assert len(calls) == 1
    assert entries == [{"type": "ip", "value": "9.9.9.9", "campaign": "Y"}]


def test_missing_cache_triggers_a_fetch(monkeypatch, tmp_path):
    cache_dir = tmp_path / "no-cache-yet"
    monkeypatch.setattr(rexmod.urllib.request, "urlopen",
                         lambda *a, **k: _FakeResponse(b'{"entries": []}'))

    entries, status = rexmod._fetch_network_iocs(str(cache_dir))
    assert status == "refetched"
    assert entries == []
    assert os.path.exists(os.path.join(str(cache_dir), "network-iocs.json"))


def test_fetch_failure_returns_unavailable_without_raising(monkeypatch, tmp_path):
    def _boom(*a, **k):
        raise TimeoutError("timed out")
    monkeypatch.setattr(rexmod.urllib.request, "urlopen", _boom)

    entries, status = rexmod._fetch_network_iocs(str(tmp_path / "no-cache"))
    assert status == "unavailable"
    assert entries == []


def test_malformed_cached_json_degrades_to_empty_entries(monkeypatch, tmp_path):
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    (cache_dir / "network-iocs.json").write_text("not json")

    entries, status = rexmod._fetch_network_iocs(str(cache_dir))
    assert status == "fresh"  # the cache *file* was fresh — just unparseable
    assert entries == []


# --------------------------------------------------------------------------
# _network_ioc_alerts: IP-only matching against live connections
# --------------------------------------------------------------------------

class _Addr:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port


class _Conn:
    def __init__(self, raddr):
        self.raddr = raddr


class _FakePsutilNet:
    def __init__(self, conns):
        self._conns = conns

    def net_connections(self, kind="inet"):
        return self._conns


IOC_ENTRIES = [
    {"type": "ip", "value": "38.244.50.120", "campaign": "ARTEX", "note": "ARTEX console/host"},
    {"type": "domain", "value": "xcai.pro", "campaign": "ARTEX", "note": ""},
]


def test_matching_remote_ip_is_flagged(monkeypatch):
    monkeypatch.setattr(rexmod, "psutil", _FakePsutilNet([_Conn(_Addr("38.244.50.120", 443))]))
    alerts = rexmod._network_ioc_alerts(IOC_ENTRIES)
    assert len(alerts) == 1
    assert "38.244.50.120:443" in alerts[0]
    assert "ARTEX" in alerts[0]


def test_non_matching_ip_is_not_flagged(monkeypatch):
    monkeypatch.setattr(rexmod, "psutil", _FakePsutilNet([_Conn(_Addr("8.8.8.8", 443))]))
    assert rexmod._network_ioc_alerts(IOC_ENTRIES) == []


def test_connection_with_no_remote_address_is_skipped(monkeypatch):
    monkeypatch.setattr(rexmod, "psutil", _FakePsutilNet([_Conn(None)]))
    assert rexmod._network_ioc_alerts(IOC_ENTRIES) == []


def test_domain_only_entries_never_match_anything(monkeypatch):
    # No "ip" entries at all -> short-circuits before ever calling psutil.
    monkeypatch.setattr(rexmod, "psutil", _FakePsutilNet([_Conn(_Addr("1.1.1.1", 1))]))
    domain_only = [{"type": "domain", "value": "xcai.pro", "campaign": "ARTEX"}]
    assert rexmod._network_ioc_alerts(domain_only) == []


def test_psutil_none_returns_no_alerts(monkeypatch):
    monkeypatch.setattr(rexmod, "psutil", None)
    assert rexmod._network_ioc_alerts(IOC_ENTRIES) == []


def test_net_connections_access_denied_degrades_quietly(monkeypatch):
    class _Denied:
        def net_connections(self, kind="inet"):
            raise PermissionError("denied")
    monkeypatch.setattr(rexmod, "psutil", _Denied())
    assert rexmod._network_ioc_alerts(IOC_ENTRIES) == []


# --------------------------------------------------------------------------
# _artex_process_alerts: artifact names + webshell process lineage
# --------------------------------------------------------------------------

def test_known_artex_artifact_name_is_flagged():
    info_by_pid = {100: {"pid": 100, "name": "artex-probe-04821", "ppid": 1}}
    alerts = rexmod._artex_process_alerts(info_by_pid)
    assert len(alerts) == 1
    assert "100" in alerts[0]


def test_shell_spawned_by_web_server_is_flagged():
    info_by_pid = {
        1: {"pid": 1, "name": "nginx", "ppid": 0},
        2: {"pid": 2, "name": "sh", "ppid": 1},
    }
    alerts = rexmod._artex_process_alerts(info_by_pid)
    assert len(alerts) == 1
    assert "nginx" in alerts[0] and "sh" in alerts[0]


def test_shell_spawned_by_ordinary_parent_is_not_flagged():
    info_by_pid = {
        1: {"pid": 1, "name": "bash", "ppid": 0},
        2: {"pid": 2, "name": "sh", "ppid": 1},
    }
    assert rexmod._artex_process_alerts(info_by_pid) == []


def test_unrelated_processes_produce_no_alerts():
    info_by_pid = {
        1: {"pid": 1, "name": "systemd", "ppid": 0},
        2: {"pid": 2, "name": "firefox", "ppid": 1},
    }
    assert rexmod._artex_process_alerts(info_by_pid) == []
