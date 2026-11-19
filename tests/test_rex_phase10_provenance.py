"""PLAN.md Phase 10 — feed-driven findings may never remediate.

Covers: signature_source is derived from the per-line [source] tags (not
hardcoded), a synthetic feed_confirmed finding — Phase 7 doesn't exist yet,
so this is deliberately constructed directly against build_report() rather
than through a real scan — carries that provenance through the JSON report,
no remediation code path exists anywhere in the file for a feed-sourced or
heuristic finding, and the local suppression list's CLI surface works.

Run with:  .venv/bin/python -m pytest tests/test_rex_phase10_provenance.py -v
"""
import json
import os
import pathlib
import sys
import tempfile

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
REX = ROOT / "rex.py"
VENV_PY = ROOT / ".venv" / "bin" / "python"
PY = str(VENV_PY) if VENV_PY.exists() else sys.executable

sys.path.insert(0, str(ROOT))
import rex as rexmod  # noqa: E402


def run(*args, env=None, timeout=60):
    e = dict(os.environ)
    if env:
        e.update(env)
    return __import__("subprocess").run(
        [PY, str(REX), *args], capture_output=True, text=True, timeout=timeout,
        env=e, cwd=str(ROOT),
    )


@pytest.fixture
def isolated_config(tmp_path):
    """Give the subprocess its own ~/.aegis_config.json by overriding HOME —
    CONFIG_PATH is computed from os.path.expanduser('~') at import time in
    the CHILD process, so this is the one override that actually reaches it
    (monkeypatching the parent's imported module has no effect on a
    subprocess, which re-imports rex.py fresh)."""
    cfg_path = tmp_path / ".aegis_config.json"
    return cfg_path, {"HOME": str(tmp_path)}


# --------------------------------------------------------------------------
# signature_source derivation
# --------------------------------------------------------------------------

def _virus_finding(report):
    return next(f for f in report["findings"] if f["section"] == rexmod.VIRUS_SECTION)


def test_local_only_threat_tagged_clamav_local():
    report = rexmod.build_report({
        rexmod.VIRUS_SECTION: ("critical",
                               f"⚠ 1 THREAT(S) FOUND\n\n[{rexmod.SIGNATURE_SOURCE_LOCAL}] /tmp/x: Eicar FOUND"),
    })
    assert _virus_finding(report)["signature_source"] == rexmod.SIGNATURE_SOURCE_LOCAL


def test_synthetic_feed_confirmed_finding_carries_source():
    """Phase 7 (real feed matching) doesn't exist yet — this constructs the
    finding build_report() would receive once it does, directly, which is
    exactly what this phase's own "Done when" calls for."""
    report = rexmod.build_report({
        rexmod.VIRUS_SECTION: ("critical",
                               f"⚠ 1 THREAT(S) FOUND\n\n[{rexmod.SIGNATURE_SOURCE_FEED}] "
                               f"/tmp/y: Rex.Reported.abcd1234 FOUND"),
    })
    finding = _virus_finding(report)
    assert finding["signature_source"] == rexmod.SIGNATURE_SOURCE_FEED
    assert finding["signature_source"] in rexmod.NO_REMEDIATION_SIGNATURE_SOURCES


def test_mixed_sources_reported_as_mixed_not_silently_picked():
    report = rexmod.build_report({
        rexmod.VIRUS_SECTION: ("critical",
                               f"[{rexmod.SIGNATURE_SOURCE_LOCAL}] a\n[{rexmod.SIGNATURE_SOURCE_FEED}] b"),
    })
    assert _virus_finding(report)["signature_source"] == "mixed"


def test_clean_scan_has_no_signature_source_field():
    report = rexmod.build_report({rexmod.VIRUS_SECTION: ("ok", "✓ Clean — 10 files scanned")})
    assert "signature_source" not in _virus_finding(report)


# --------------------------------------------------------------------------
# the hard rule: no remediation code path exists for a non-local source
# --------------------------------------------------------------------------

def test_no_destructive_filesystem_verbs_anywhere_in_rex():
    """Mirrors the manual check PLAN.md's rev 3 ran by hand: rex must contain
    no delete/quarantine/move verb at all. A regression here means a future PR
    added remediation without updating NO_REMEDIATION_SIGNATURE_SOURCES or
    this test — either way it needs eyes before it ships.

    The verb list is the full destructive set, not just the four rev 3 named:
    a remediation implemented as a move-to-quarantine (os.rename) or a
    truncation (os.truncate) is exactly as destructive as os.remove."""
    source = REX.read_text()
    # os.replace( is deliberately absent here, not forgotten: PLAN.md Phase 7
    # added one legitimate, reviewed use (the feed-cache atomic write in
    # _fetch_extra_signatures) — see _REVIEWED_WRITE_SITES below, which pins
    # its count instead of banning the verb outright.
    forbidden = (
        "os.remove(", "os.unlink(", ".unlink(", "shutil.rmtree(",
        "shutil.move(", "os.rename(", "os.rmdir(",
        "os.truncate(", "send2trash",
    )
    for verb in forbidden:
        assert verb not in source, (
            f"found {verb!r} — a destructive verb now exists in rex.py; it must "
            f"gate on NO_REMEDIATION_SIGNATURE_SOURCES before it may ship"
        )


# PLAN.md Phase 10 rule 2 enumerates delete, truncate, chmod, quarantine, move.
# The tests above cover delete/quarantine/move by verb. `chmod` and `open(...,"w")`
# DO legitimately exist in rex.py — but only on the config file and on paths the
# user named. Pinning their exact counts means a NEW one cannot appear without
# breaking this test and forcing review: that is the difference between asserting
# "these verbs are absent" and actually enforcing "no finding may drive a write".
_REVIEWED_WRITE_SITES = {
    # pattern: (expected count, every legitimate site)
    r'open\([^)]*,\s*["\'][wa]': (5, "_save_config; --output; GUI export; "
                                     "_fetch_extra_signatures feed cache (Phase 7); "
                                     "_fetch_network_iocs feed cache (Phase 20)"),
    r"os\.chmod\(": (3, "_save_config; --output; GUI export"),
    # PLAN.md Phase 7/20: both feed-cache writes are to a cache directory this
    # process owns, never to an audited/scanned path, and are not keyed on
    # any finding — the only two places os.replace() is allowed to exist.
    r"os\.replace\(": (2, "_fetch_extra_signatures feed cache (Phase 7); "
                          "_fetch_network_iocs feed cache (Phase 20)"),
}


def test_chmod_and_write_sites_are_exactly_the_reviewed_ones():
    import re

    source = REX.read_text()
    for pattern, (expected, where) in _REVIEWED_WRITE_SITES.items():
        hits = re.findall(pattern, source)
        assert len(hits) == expected, (
            f"{pattern!r} now appears {len(hits)}x (expected {expected}x, all on "
            f"{where}). A new chmod/truncating-write site needs review against "
            f"PLAN.md Phase 10 rule 2 before it may ship."
        )


def test_no_write_or_chmod_call_is_keyed_on_a_finding():
    """The counts above would still permit a write keyed on a finding if one
    of the three reviewed sites were *changed* rather than added. Assert the
    stronger invariant directly: signature_source is written into findings but
    never read to select a filesystem action."""
    source = REX.read_text()
    reads = [
        line for line in source.splitlines()
        if "signature_source" in line
        and "finding[\"signature_source\"] =" not in line
        and line.lstrip().startswith("#") is False
        and not line.lstrip().startswith('"""')
    ]
    # Everything that touches the field must be production/consumption of the
    # field itself; NO_REMEDIATION_SIGNATURE_SOURCES membership is the only
    # permitted *decision* made from it, and today nothing reads it at all.
    for line in reads:
        assert "NO_REMEDIATION_SIGNATURE_SOURCES" in line or "_signature_source" in line, (
            f"signature_source is read at {line.strip()!r} — if it now selects a "
            f"filesystem action, it must gate on NO_REMEDIATION_SIGNATURE_SOURCES"
        )


def test_no_remediation_signature_sources_excludes_local():
    assert rexmod.SIGNATURE_SOURCE_LOCAL not in rexmod.NO_REMEDIATION_SIGNATURE_SOURCES
    assert rexmod.SIGNATURE_SOURCE_FEED in rexmod.NO_REMEDIATION_SIGNATURE_SOURCES
    assert rexmod.SIGNATURE_SOURCE_HEURISTIC in rexmod.NO_REMEDIATION_SIGNATURE_SOURCES


def test_malicious_name_in_threat_line_never_reaches_subprocess(monkeypatch):
    """A Name field is attacker-influenced content once a feed exists
    (PLAN.md Phase 4 sanitizes it server-side too, as defence in depth) — a
    $(...) or backtick payload riding in the tagged line must stay inert
    text through build_report(), never interpolated into a command."""
    calls = []
    monkeypatch.setattr(rexmod.subprocess, "run", lambda *a, **k: calls.append((a, k)) or None)
    payload = f"[{rexmod.SIGNATURE_SOURCE_FEED}] /tmp/z: Rex.Reported.$(rm -rf /) FOUND"
    report = rexmod.build_report({rexmod.VIRUS_SECTION: ("critical", payload)})
    assert payload in _virus_finding(report)["output"], "payload must survive as inert text"
    assert not calls, "a malicious Name field triggered a subprocess call"


# --------------------------------------------------------------------------
# local suppression list CLI surface
# --------------------------------------------------------------------------

def test_suppressed_signatures_empty_by_default(isolated_config):
    _, env = isolated_config
    proc = run("--suppressed-signatures", "--json", env=env)
    assert proc.returncode == 0, proc.stderr
    body = json.loads(proc.stdout)
    assert body["suppressed_signatures"] == []


def test_unsuppress_unknown_hash_exits_usage(isolated_config):
    _, env = isolated_config
    proc = run("--unsuppress", "deadbeef", env=env)
    assert proc.returncode == rexmod.EXIT_USAGE


def test_unsuppress_round_trip(isolated_config):
    cfg_path, env = isolated_config
    cfg_path.write_text(json.dumps({"suppressed_signatures": ["a" * 64]}))

    proc = run("--suppressed-signatures", "--json", env=env)
    assert json.loads(proc.stdout)["suppressed_signatures"] == ["a" * 64]

    proc = run("--unsuppress", "a" * 64, env=env)
    assert proc.returncode == 0, proc.stderr

    proc = run("--suppressed-signatures", "--json", env=env)
    assert json.loads(proc.stdout)["suppressed_signatures"] == []


def test_suppression_flags_documented_in_capabilities():
    cap = rexmod.capabilities()
    flags = {c["flag"] for c in cap["commands"]}
    assert "--suppressed-signatures" in flags
    assert "--unsuppress" in flags
