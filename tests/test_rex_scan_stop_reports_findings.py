"""
Regression: stopping a ClamAV deep scan discarded its findings.

_run_section collected `threats` and `feed_threats` while the walk ran, but the
`if self._stop` branch returned "info" with only a file count. So a scan that
had already hit three infected files and was then stopped reported
"Cancelled — stopped after N file(s)" and nothing else — indistinguishable from
a stop on a clean tree, and the tagged FOUND lines were thrown away.

Two things had to hold in the fix:

  * whatever was already found survives the stop, still carrying its
    SIGNATURE_SOURCE_LOCAL / SIGNATURE_SOURCE_FEED tag so build_report keeps
    attributing it correctly;
  * a stopped scan that had found something is NOT "info", because "info" is in
    no --fail-on threshold — it would make a scan that already knew about
    malware exit 0 under `--fail-on warn`.

It also must stay fast: the feed overlay runs through _cmd, which holds no
process handle and cannot be terminated, so the stop path must not join that
thread for its full 600s timeout.

Run with:  .venv/bin/python -m pytest tests/test_rex_scan_stop_reports_findings.py -v
"""
import pathlib
import platform
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import rex as rexmod  # noqa: E402

# See test_rex_phase7_signature_feed.py: platform.platform() shells out lazily
# and caches in the stdlib, so warm it before Popen is monkeypatched.
platform.platform()


class _FakePopen:
    """Iterable .stdout plus the terminate/wait/kill surface the stop path uses.

    `stop_after` is how many lines to hand over before the stop is requested —
    request it too early and the loop breaks before recording a finding, which
    tests nothing (that mistake made two of these tests lie on the first run).
    """

    def __init__(self, lines, on_iter=None, stop_after=1):
        self._lines = list(lines)
        self._on_iter = on_iter
        self._stop_after = stop_after
        self.terminated = False
        self.killed = False
        self.stdout = self._gen()

    def _gen(self):
        for i, line in enumerate(self._lines):
            yield line
            if self._on_iter is not None and (i + 1) >= self._stop_after:
                self._on_iter()

    def poll(self):
        return None

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        return 0

    def kill(self):
        self.killed = True


def _engine(tmp_path, monkeypatch, scan_path=None):
    monkeypatch.setattr(rexmod.shutil, "which",
                        lambda name: "/fake/clamscan" if name == "clamscan" else None)
    return rexmod.AuditEngine([rexmod.VIRUS_SECTION],
                              scan_path=str(scan_path or tmp_path))


def _stop_after(engine, lines, threat_lines, monkeypatch, feed="unavailable",
                after=1):
    proc = _FakePopen(lines, on_iter=engine.stop, stop_after=after)
    monkeypatch.setattr(rexmod.subprocess, "Popen", lambda *a, **k: proc)
    monkeypatch.setattr(rexmod, "_fetch_extra_signatures",
                        lambda *a, **k: (None, feed))
    return engine._run_section(rexmod.VIRUS_SECTION), proc


# ── the regression itself ────────────────────────────────────

def test_stopped_scan_keeps_threats_already_found(monkeypatch, tmp_path):
    eng = _engine(tmp_path, monkeypatch)
    lines = [f"{tmp_path}/a.txt: Eicar-Test-Signature FOUND",
             f"{tmp_path}/b.txt: OK",
             f"{tmp_path}/c.txt: WIN.Trojan.Bloodalchemy FOUND"]
    # Stop after BOTH FOUND lines have been consumed, so the assertion below is
    # about preservation across the stop, not about how early the stop landed.
    (status, output), _ = _stop_after(eng, lines, lines[:1], monkeypatch,
                                      after=3)

    assert status == "critical", "a threat seen before the stop is still a finding"
    assert "THREAT(S) FOUND" in output
    assert "Eicar-Test-Signature" in output
    assert f"[{rexmod.SIGNATURE_SOURCE_LOCAL}]" in output
    assert "WIN.Trojan.Bloodalchemy" in output, "both FOUND lines survive, not just the first"
    assert "[scan_status:stopped]" in output


def test_stopped_scan_says_stopped_and_warns_about_unscanned(monkeypatch, tmp_path):
    """The partial caveat must be present whenever the run was stopped.

    It is deliberately NOT asserted that the output *starts* with "Stopped —":
    when a hit was already recorded the threat banner leads, and the stop note
    follows it. Both orderings are correct; only the note's presence, and the
    machine marker that survives either ordering, are contractual.
    """
    eng = _engine(tmp_path, monkeypatch)
    lines = [f"{tmp_path}/a.txt: Eicar-Test-Signature FOUND", f"{tmp_path}/b.txt: OK"]
    (status, output), _ = _stop_after(eng, lines, lines[:1], monkeypatch)

    assert status == "critical"
    assert "Stopped — " in output
    assert "NOT assessed" in output
    assert "re-run to completion" in output
    assert "[scan_status:stopped]" in output


def test_stopped_scan_with_nothing_found_is_info_not_critical(monkeypatch, tmp_path):
    eng = _engine(tmp_path, monkeypatch)
    lines = [f"{tmp_path}/a.txt: OK", f"{tmp_path}/b.txt: OK"]
    (status, output), _ = _stop_after(eng, lines, [], monkeypatch)

    assert status == "info", "an empty partial scan must not be scored as a finding"
    assert output.startswith("Stopped —")
    assert "1 file(s) scanned" in output or "2 file(s) scanned" in output


def test_stopped_scan_retains_feed_tagged_hits(monkeypatch, tmp_path):
    """Feed hits already merged before the stop keep their own tag."""
    eng = _engine(tmp_path, monkeypatch)
    lines = [f"{tmp_path}/a.txt: OK"]
    proc = _FakePopen(lines, on_iter=eng.stop)
    monkeypatch.setattr(rexmod.subprocess, "Popen", lambda *a, **k: proc)
    monkeypatch.setattr(rexmod, "_fetch_extra_signatures",
                        lambda *a, **k: ("/fake/signatures.hdb", "refetched"))
    # Feed overlay runs in its thread via _cmd; hand back a hit immediately.
    monkeypatch.setattr(rexmod.AuditEngine, "_cmd", staticmethod(
        lambda args, timeout=10: f"{tmp_path}/z.txt: Rex.Reported.feedhash FOUND"))

    status, output = eng._run_section(rexmod.VIRUS_SECTION)
    assert status == "critical"
    assert f"[{rexmod.SIGNATURE_SOURCE_FEED}]" in output


def test_stopped_scan_does_not_block_on_the_feed_thread(monkeypatch, tmp_path):
    """The feed overlay has no process handle, so the stop path must not join it.

    _run_feed_scan calls _cmd, whose real timeout is 600s. If the stop branch
    joined that thread, Stop would hang for minutes — the exact
    unresponsiveness stop() was fixed to remove.
    """
    import threading
    import time

    eng = _engine(tmp_path, monkeypatch)
    release = threading.Event()

    def _slow_cmd(args, timeout=10):
        release.wait(5)          # far longer than the assertion below allows
        return ""

    monkeypatch.setattr(rexmod.AuditEngine, "_cmd", staticmethod(_slow_cmd))
    monkeypatch.setattr(rexmod, "_fetch_extra_signatures",
                        lambda *a, **k: ("/fake/signatures.hdb", "refetched"))
    proc = _FakePopen([f"{tmp_path}/a.txt: OK"], on_iter=eng.stop)
    monkeypatch.setattr(rexmod.subprocess, "Popen", lambda *a, **k: proc)

    t0 = time.monotonic()
    status, output = eng._run_section(rexmod.VIRUS_SECTION)
    elapsed = time.monotonic() - t0
    release.set()

    assert elapsed < 3.0, f"stop path blocked {elapsed:.1f}s on the feed thread"
    assert "[feed_status:interrupted]" in output


# ── report and exit-code integrity ───────────────────────────

def test_stopped_scan_findings_reach_the_json_report(monkeypatch, tmp_path):
    eng = _engine(tmp_path, monkeypatch)
    lines = [f"{tmp_path}/a.txt: Eicar-Test-Signature FOUND", f"{tmp_path}/b.txt: OK"]
    (status, output), _ = _stop_after(eng, lines, lines[:1], monkeypatch)

    report = rexmod.build_report({rexmod.VIRUS_SECTION: (status, output)})
    finding = report["findings"][0]
    assert finding["signature_source"] == rexmod.SIGNATURE_SOURCE_LOCAL
    assert finding["status"] == "critical"


def test_partial_findings_are_not_counted_as_clean(monkeypatch, tmp_path):
    """The count a scoring front-end reads must not read as a pass."""
    eng = _engine(tmp_path, monkeypatch)
    lines = [f"{tmp_path}/a.txt: Eicar-Test-Signature FOUND"]
    (status, output), _ = _stop_after(eng, lines, lines[:1], monkeypatch)

    report = rexmod.build_report({rexmod.VIRUS_SECTION: (status, output)})
    summary = report["summary"]
    assert summary["clean"] == 0, "a partial scan with a hit must not score clean"
    assert summary["info"] == 0, "nor be filed as informational"
    assert summary["fixable"] == 1


# ── the grade ────────────────────────────────────────────────

def test_a_stopped_scan_cannot_earn_a_good_grade(monkeypatch, tmp_path):
    """A stopped scan found nothing — but it also did not finish.

    audit_score() returned GOOD for the stopped case because the arithmetic is
    honest (no findings, 100 points); the grade was not, because most of the
    tree was never looked at.
    """
    eng = _engine(tmp_path, monkeypatch)
    lines = [f"{tmp_path}/a.txt: OK", f"{tmp_path}/b.txt: OK"]
    (status, output), _ = _stop_after(eng, lines, [], monkeypatch)

    score = rexmod.audit_score({rexmod.VIRUS_SECTION: (status, output)})
    assert score["grade"] == "INCOMPLETE"
    assert score["partial_sections"] == [rexmod.VIRUS_SECTION]


def test_a_completed_scan_still_grades_normally(monkeypatch, tmp_path):
    """The INCOMPLETE grade must not leak into a run that finished."""
    score = rexmod.audit_score({rexmod.VIRUS_SECTION: ("ok", "✓ Clean — 12 files")})
    assert score["grade"] == "GOOD"
    assert score["partial_sections"] == []


def test_report_summary_carries_the_partial_count(monkeypatch, tmp_path):
    eng = _engine(tmp_path, monkeypatch)
    lines = [f"{tmp_path}/a.txt: OK"]
    (status, output), _ = _stop_after(eng, lines, [], monkeypatch)

    summary = rexmod.build_report({rexmod.VIRUS_SECTION: (status, output)})["summary"]
    assert summary["partial"] == 1
    assert summary["grade"] == "INCOMPLETE"


# ── the GUI label ────────────────────────────────────────────

def test_gui_labels_a_stopped_scan_as_stopped_not_raw_info():
    """_show_output had no "info" entry, so a stopped scan fell through to a raw
    "INFO" badge with no colour. Source-level check keeps Qt out of this suite."""
    src = rexmod.__file__
    text = pathlib.Path(src).read_text(encoding="utf-8")
    show = text.split("def _show_output", 1)[1].split("def _run_audit", 1)[0]
    assert '"info":' in show, "_show_output must label the info status explicitly"
    assert '"[scan_status:stopped]" in output' in text, \
        "the stopped-run label must key on the machine marker"
    assert '("Stopped —", "Cancelled —")' in text, \
        "legacy output prefix must still be recognised"
