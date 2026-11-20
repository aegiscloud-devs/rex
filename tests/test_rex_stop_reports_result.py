"""A stopped scan must report a result, not a clean bill of health.

Regression: AuditWorker.run() always emitted all_done, and _on_all_done
counted only the sections present in self.results as warnings. So stopping a
19-section audit after 3 sections reached the "no warnings" branch and rendered
"Audit complete — no issues found" with a 100/GOOD score — a verdict on 16
sections that never ran. Absence of evidence was being scored as a pass, which
is precisely the failure mode _sect_unassessed exists to prevent elsewhere.

Second regression, same root: Ctrl-C in the CLI audit path propagated to
main(), printed "interrupted", and exited 2 — discarding every section that had
already completed. The partial result existed only in the ThreadPoolExecutor's
loop and was thrown away with the stack unwind.
"""
import ast
import pathlib
import sys

import pytest

REX = pathlib.Path(__file__).resolve().parent.parent / "rex.py"


@pytest.fixture(scope="module")
def rex():
    sys.path.insert(0, str(REX.parent))
    import rex as _rex  # noqa: PLC0415
    return _rex


# ── engine keeps partials ────────────────────────────────────

def test_collect_records_partial_results(rex, monkeypatch):
    eng = rex.AuditEngine(["A", "B"])
    monkeypatch.setattr(eng, "_run_section", lambda s: ("ok", "out"))
    out = eng.collect()
    assert out == {"A": ("ok", "out"), "B": ("ok", "out")}
    assert eng.partial_results == out


def test_stopped_collect_retains_what_ran(rex, monkeypatch):
    """Stop mid-run: partial_results holds the sections that finished."""
    eng = rex.AuditEngine(["A", "B", "C"])

    def fake(section):
        eng.stop()  # request stop after the first section completes
        return "ok", "out"

    monkeypatch.setattr(eng, "_run_section", fake)
    out = eng.collect()
    assert list(out) == ["A"], out
    assert set(eng.partial_results) == {"A"}


def test_collect_parallel_records_partial_results(rex, monkeypatch):
    eng = rex.AuditEngine(["A", "B"])
    monkeypatch.setattr(eng, "_run_section", lambda s: ("warn", f"{s}-finding"))
    out = eng.collect_parallel()
    assert eng.partial_results == out


def test_stop_halts_parallel_collection(rex):
    """stop() during collect_parallel must actually stop it.

    With more sections than workers the loop drained every submitted future,
    so a stop (or Ctrl-C) only took effect once the slowest section finished.
    """
    import threading
    import time

    names = ["A", "B", "C", "D", "E", "F", "G", "H"]
    eng = rex.AuditEngine(names)
    eng._run_section = lambda s: (time.sleep(0.25), ("ok", f"done {s}"))[1]

    t = threading.Thread(target=lambda: eng.collect_parallel(workers=2))
    t.start()
    time.sleep(0.35)
    eng.stop()
    t.join(30)

    ran = len(eng.partial_results)
    assert ran < len(names), (
        f"stop did not take effect: all {ran} sections ran")
    assert ran > 0, "stop discarded every completed section"


def test_stop_keeps_completed_futures(rex):
    """Sections that finished before the stop are reported, not dropped."""
    import threading
    import time

    names = ["A", "B", "C", "D", "E", "F"]
    eng = rex.AuditEngine(names)
    eng._run_section = lambda s: (time.sleep(0.2), ("ok", s))[1]

    t = threading.Thread(target=lambda: eng.collect_parallel(workers=2))
    t.start()
    time.sleep(0.3)
    eng.stop()
    t.join(30)

    # Whatever is in partial_results must be real, completed work.
    for section, (status, out) in eng.partial_results.items():
        assert status == "ok" and out == section


# ── signal carries the stop flag ─────────────────────────────

def test_all_done_signal_carries_stop_flag():
    """all_done must be a bool-carrying signal now; the GUI reads it."""
    src = REX.read_text(encoding="utf-8")
    tree = ast.parse(src)
    found = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "AuditWorker":
            for item in node.body:
                if (isinstance(item, ast.Assign)
                        and getattr(item.targets[0], "id", "") == "all_done"):
                    found["all_done"] = ast.unparse(item.value)
    assert found, "AuditWorker.all_done assignment not found"
    assert "bool" in found["all_done"], found["all_done"]


def test_worker_emits_stop_state(rex):
    """The emit call must pass the engine's stop flag, not a bare emit()."""
    src = REX.read_text(encoding="utf-8")
    assert "self.all_done.emit(self._stop)" in src
    assert "self.all_done.emit()" not in src


# ── GUI must not grade an incomplete run ─────────────────────

def test_stopped_summary_has_no_grade():
    src = REX.read_text(encoding="utf-8")
    assert 'grade = "INCOMPLETE"' in src, \
        "a stopped run must not fall through to GOOD/FAIR/POOR"
    assert "not assessed, which is not the same as clean" in src


def test_stopped_never_claims_no_issues_found():
    """The literal string that was the bug, in the stopped branch."""
    src = REX.read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_on_all_done":
            body = ast.unparse(node)
            stopped_at = body.find("if stopped:")
            assert stopped_at != -1, "no stopped branch in _on_all_done"
            before_clean_claim = body.find("Audit complete — no issues found")
            assert before_clean_claim == -1 or before_clean_claim > stopped_at, \
                "the clean verdict is reachable before the stopped branch"
            return
    pytest.fail("_on_all_done not found")


def test_stop_audit_does_not_assert_verdict(rex):
    """Stop button says 'Stopping…' — the verdict comes from _on_all_done."""
    src = REX.read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_stop_audit":
            assert 'setText("Stopped")' not in ast.unparse(node)
            return
    pytest.fail("_stop_audit not found")


# ── CLI keeps the partial on interrupt ───────────────────────

def test_cli_audit_handles_keyboard_interrupt():
    src = REX.read_text(encoding="utf-8")
    assert "partial_results" in src
    assert "interrupted — {ran}/{expected_n} sections ran" in src
    assert "not assessed, " in src and "not passed" in src
