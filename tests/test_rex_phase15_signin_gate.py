"""PLAN.md Phase 15 — rex.py: sign-in gate UI.

The gate (SignInDialog, shown from main() before SecurityAuditWindow exists)
must never reach the headless CLI path, must only ever prompt once per
profile, and must never block the audit regardless of what the user picks.
These tests drive main() with QApplication/SecurityAuditWindow/SignInDialog
replaced by lightweight fakes — the point is main()'s own gating logic, not
re-testing Qt itself or needing a real display.

Run with:  .venv/bin/python -m pytest tests/test_rex_phase15_signin_gate.py -v
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import rex as rexmod  # noqa: E402


# --------------------------------------------------------------------------
# the gate must be unreachable from the headless CLI path
# --------------------------------------------------------------------------

def _reachable_names(func, seen=None):
    """Transitive closure of every name referenced by `func` and by every
    rexmod function `func` calls (by name) — a call-graph check, not just a
    read of where the `if` sits in main()."""
    if seen is None:
        seen = set()
    if func in seen:
        return set()
    seen.add(func)
    names = set(func.__code__.co_names)
    for name in list(names):
        callee = getattr(rexmod, name, None)
        if callable(callee) and hasattr(callee, "__code__"):
            names |= _reachable_names(callee, seen)
    return names


def test_signin_dialog_and_qapplication_unreachable_from_cli_main():
    names = _reachable_names(rexmod._cli_main)
    assert "SignInDialog" not in names
    assert "QApplication" not in names
    assert "SecurityAuditWindow" not in names


# --------------------------------------------------------------------------
# main()'s gating: shown once per profile, never blocks the audit window
# --------------------------------------------------------------------------

class _FakeFont:
    def setFamily(self, *a):
        pass

    def family(self):
        return "Fake"


class _FakeApp:
    def __init__(self, argv):
        pass

    def setApplicationName(self, *a):
        pass

    def setApplicationVersion(self, *a):
        pass

    # main() sets the app-wide window icon so dialogs and the taskbar inherit
    # the Rx seal. Same rule as font()/setFont() below: a stand-in QApplication
    # that cannot answer every call main() makes is not a faithful double.
    def setWindowIcon(self, *a):
        pass

    # main() sets the app-wide font so dialogs inherit Ubuntu instead of Qt's
    # generic default. A stand-in QApplication must answer font()/setFont() or
    # it is not a faithful double.
    def font(self):
        return _FakeFont()

    def setFont(self, *a):
        pass

    def exec(self):
        return 0


def test_onboarding_seen_written_once_and_dialog_skipped_on_second_call(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(rexmod, "CONFIG_PATH", str(tmp_path / "cfg.json"))
    monkeypatch.setattr(rexmod, "QApplication", _FakeApp)
    monkeypatch.setattr(rexmod, "SecurityAuditWindow",
                         type("_FakeWin", (), {"__init__": lambda self: None,
                                                "show": lambda self: None}))
    dialog_inits = []

    class _FakeDialog:
        def __init__(self):
            dialog_inits.append(1)

        def exec(self):
            return 0  # simulates Skip — no api_key ever set

    monkeypatch.setattr(rexmod, "SignInDialog", _FakeDialog)

    rexmod.main([])  # [] (not None) keeps main() on the GUI branch regardless of sys.argv
    assert dialog_inits == [1]
    assert rexmod._load_config().get("_onboarding_seen") is True

    rexmod.main([])
    assert dialog_inits == [1], "the gate must not be shown a second time for this profile"


def test_skip_leaves_no_api_key_and_the_audit_window_still_constructs(
    monkeypatch, tmp_path
):
    cfg_path = tmp_path / "cfg.json"
    monkeypatch.setattr(rexmod, "CONFIG_PATH", str(cfg_path))
    monkeypatch.setattr(rexmod, "QApplication", _FakeApp)

    win_inits = []
    monkeypatch.setattr(
        rexmod, "SecurityAuditWindow",
        type("_FakeWin", (), {"__init__": lambda self: win_inits.append(1),
                               "show": lambda self: None}),
    )
    monkeypatch.setattr(
        rexmod, "SignInDialog",
        type("_FakeDialogSkip", (), {"__init__": lambda self: None,
                                      "exec": lambda self: 0}),  # Skip: result stays unset
    )

    rc = rexmod.main([])

    assert rc == 0
    assert win_inits == [1], "SecurityAuditWindow must still be constructed after Skip"
    assert "aegis_api_key" not in rexmod._load_config()


def test_already_signed_in_also_skips_the_gate(monkeypatch, tmp_path):
    cfg_path = tmp_path / "cfg.json"
    cfg_path.write_text('{"aegis_api_key": "existing-key"}')
    monkeypatch.setattr(rexmod, "CONFIG_PATH", str(cfg_path))
    monkeypatch.setattr(rexmod, "QApplication", _FakeApp)
    monkeypatch.setattr(rexmod, "SecurityAuditWindow",
                         type("_FakeWin", (), {"__init__": lambda self: None,
                                                "show": lambda self: None}))
    dialog_inits = []
    monkeypatch.setattr(
        rexmod, "SignInDialog",
        type("_FakeDialog", (), {"__init__": lambda self: dialog_inits.append(1),
                                  "exec": lambda self: 0}),
    )

    rexmod.main([])

    assert dialog_inits == [], "a returning signed-in user must not see the gate at all"
