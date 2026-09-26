#!/usr/bin/env python3
# ============================================================
# ÆGIS Security Audit — rex.py
# Cross-platform: Windows · macOS · Linux
# ============================================================
#
# Resilience contract: rex is an audit tool that must never abort a whole run
# because one probe failed. Each check is therefore allowed to swallow its own
# failure and report it as a finding instead of raising. That intent is why
# `except Exception` (BLE001), the deliberate `pass`/`continue` handlers
# (S110/S112) and the local-time stamps (DTZ) below carry targeted noqa
# directives rather than being narrowed to exception classes — narrowing them
# would convert a reported finding into an unhandled traceback.

import contextlib
import datetime
import json
import math
import os
import platform
import random
import re
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import psutil
except ImportError:
    # Agent/CI containers routinely ship a bare python3. psutil is only
    # needed by 4 of the 16 audit sections, so a missing lib must not
    # make the CLI or the JSON contract unimportable.
    psutil = None

# ── Qt is optional ───────────────────────────────────────────
# rex is two things: a GUI, and an audit/fix engine. An AI agent running in
# a container has no display and no PyQt6, so a missing Qt must not be fatal
# at import time — `import rex`, the CLI, and the JSON contract all have to
# work on a bare python3. A hard sys.exit(1) here would make rex undriveable
# by exactly the thing it is supposed to be driveable by.
QT_MISSING_MSG = (
    "PyQt6 is required for the GUI.\n"
    "Install it with: pip install PyQt6 psutil\n"
    "Or drive rex headlessly: rex.py --audit --json  "
    "(see rex.py --capabilities)"
)

HAS_QT = False
try:
    from PyQt6.QtCore import Qt, QThread, QTimer, pyqtSignal
    from PyQt6.QtGui import QColor, QPainter, QPalette, QPen
    from PyQt6.QtWidgets import (
        QApplication,
        QDialog,
        QFileDialog,
        QFrame,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QListWidget,
        QListWidgetItem,
        QMainWindow,
        QProgressBar,
        QPushButton,
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )
    HAS_QT = True
except ImportError:
    # Placeholders. The GUI classes below still *parse and import*, so that
    # one file can serve both front-ends; they raise the moment anything
    # actually tries to build a window.
    class _QtUnavailable:
        def __init__(self, *a, **k):
            raise RuntimeError(QT_MISSING_MSG)

    QApplication = QMainWindow = QWidget = QVBoxLayout = QHBoxLayout = \
        QPushButton = QLabel = QTextEdit = QFrame = QListWidget = \
        QListWidgetItem = QProgressBar = QFileDialog = QDialog = QLineEdit = \
        QThread = QTimer = _QtUnavailable

    class _InertSignal:
        """pyqtSignal stand-in: connect()/emit() are no-ops, not AttributeError."""
        def connect(self, *a, **k):
            pass

        def emit(self, *a, **k):
            pass

    def pyqtSignal(*a, **k):
        return _InertSignal()

    class _Permissive:
        """Absorbs Qt.* / QColor(...) attribute chains harmlessly."""
        def __getattr__(self, name):
            return _Permissive()

        def __call__(self, *a, **k):
            return _Permissive()

    Qt = QColor = QPen = QPalette = QPainter = _Permissive()


# ============================================================
# PLATFORM DETECTION
# ============================================================
_OS      = platform.system()
IS_WIN   = _OS == "Windows"
IS_MAC   = _OS == "Darwin"
IS_LINUX = _OS == "Linux"

# ============================================================
# KONFIGURATION
# ============================================================
VERSION  = "1.6.1"
APP_NAME = "ÆGIS Security Audit"

# Lines emitted by find(1)/stat(1) *about* a path rather than *as a result*.
# _cmd() merges stderr into stdout, so an unreadable directory arrives mixed in
# with real hits — without this split, "Permission denied" is counted as a
# world-writable file that was never actually found.
_FIND_NOISE = re.compile(
    r"^(?:find|stat|ls|du|grep|getfacl|dpkg-query|rpm|pacman)\s*:\s", re.IGNORECASE
)

# _cmd() returns one of these instead of output when the probe itself failed.
# They are not findings and not a pass either: a probe that timed out proves
# nothing about the host, so the section must report "error" (unassessed).
# Before 1.6.0 the literal string "[timeout]" was fed to _split_noise, counted
# as a finding line, and published as a medium-severity *fixable* defect with
# no path — a load-induced timeout dressed up as a vulnerability.
_CMD_FAILED = re.compile(r"^\[(?:timeout|not found|error[:/]?.*)\]$", re.IGNORECASE)


def _probe_failed(out) -> bool:
    """True when _cmd() returned a failure sentinel rather than real output."""
    return bool(out) and all(
        not line.strip() or _CMD_FAILED.match(line.strip())
        for line in out.splitlines()
    )


# clamd keeps the signature database resident, so clamdscan starts scanning
# immediately where clamscan re-reads (and re-verifies) the whole database on
# every invocation — minutes of overhead on a cold page cache. It is only an
# improvement if a daemon is actually listening: clamdscan with no clamd just
# exits with a connection error.
CLAMD_SOCKETS = (
    "/var/run/clamav/clamd.ctl", "/run/clamav/clamd.ctl",
    "/tmp/clamd.socket", "/var/run/clamd.scan/clamd.sock",
)


def _clamd_up() -> bool:
    """True when a clamd daemon is reachable (systemd unit or live socket)."""
    # Probing is best-effort: a missing or uncooperative systemd must not raise,
    # it must fall through to the socket check below.
    with contextlib.suppress(Exception):
        if shutil.which("systemctl"):
            r = subprocess.run(["systemctl", "is-active", "clamav-daemon"],
                               capture_output=True, text=True, timeout=8,
                               check=False)
            if r.stdout.strip() == "active":
                return True
        if shutil.which("service"):
            r = subprocess.run(["service", "clamav-daemon", "status"],
                               capture_output=True, text=True, timeout=8,
                               check=False)
            if r.returncode == 0 and "running" in (r.stdout + r.stderr).lower():
                return True
    return any(os.path.exists(p) for p in CLAMD_SOCKETS)


def _freshclam_daemon_up() -> bool:
    """True when a long-lived freshclam owns UpdateLogFile and the DB lock.

    `clamav-freshclam.service` runs `freshclam -d --foreground=true`, which
    holds /var/log/clamav/freshclam.log open. A *manual* freshclam in that
    state cannot initialise libfreshclam at all — it fails to lock the log and
    aborts with a cryptic, easily-misread error:

        ERROR: Failed to lock the log file /var/log/clamav/freshclam.log:
               Resource temporarily unavailable
        ERROR: initialize: libfreshclam init failed.
        ERROR: Initialization error!

    Nothing is broken when that happens: the running service is already doing
    the update. So the service, not the binary, is the correct remediation —
    recommending a bare `freshclam` here sends the user into that error.
    """
    if IS_WIN:
        return False
    with contextlib.suppress(Exception):
        if shutil.which("systemctl"):
            r = subprocess.run(["systemctl", "is-active", "clamav-freshclam"],
                               capture_output=True, text=True, timeout=8,
                               check=False)
            if r.stdout.strip() == "active":
                return True
    # No systemd (container, WSL1, BSD): look for the daemon process itself.
    with contextlib.suppress(Exception):
        r = subprocess.run(["pgrep", "-af", "freshclam"], capture_output=True,
                           text=True, timeout=5, check=False)
        for line in (r.stdout or "").splitlines():
            parts = line.split()
            if "-d" in parts or "--daemon" in parts:
                return True
    return False


def _freshclam_hint() -> str:
    """The signature-update command that will actually work on this host."""
    if IS_WIN:
        return "freshclam"
    if _freshclam_daemon_up():
        return "sudo systemctl restart clamav-freshclam"
    return "sudo freshclam"


# A variable whose *name* marks it as a credential. Matched on segment
# boundaries, not as a bare substring: SSH_AUTH_SOCK and XAUTHORITY used to be
# reported as secrets because they contain "auth", and PWD because it contains
# "pwd" — neither holds a credential.
_SECRET_NAME_ANY = re.compile(
    r"(?:^|[_\-.0-9])(key|keys|token|secret|passwd|password|credential|"
    r"credentials|apikey|api_key|access_key|private_key|bearer|jwt|oauth|"
    r"webhook)(?:$|[_\-.0-9])",
    re.IGNORECASE,
)

# Weaker words that are only credential-ish as the *last* segment: MY_AUTH and
# MYSQL_PWD are secrets, SSH_AUTH_SOCK is a socket path.
_SECRET_NAME_TAIL = re.compile(r"(?:^|[_\-.0-9])(auth|pwd|private)$", re.IGNORECASE)

# Values that are credentials whatever the variable is called.
_SECRET_VALUE = re.compile(
    r"^sk-[A-Za-z0-9_\-]{16,}"           # OpenAI / Anthropic / DeepSeek
    r"|^whsec_[A-Za-z0-9]{16,}"           # Stripe webhook secret
    r"|^gsk_[A-Za-z0-9]{20,}"             # Groq
    r"|^ghp_|^ghs_|^github_pat_"          # GitHub tokens
    r"|^xox[bpoas]-"                      # Slack tokens
    r"|^[a-f0-9]{40,}$"                   # long hex digest
    r"|^[A-Za-z0-9+/]{40,}={0,2}$",       # long base64 blob
    re.IGNORECASE,
)

# Names that merely *contain* a credential-ish word but are paths, sockets or
# session identifiers, not secrets.
_BENIGN_VARS = frozenset({
    "PWD", "OLDPWD", "XAUTHORITY", "SSH_AUTH_SOCK", "SSH_ASKPASS",
    "DBUS_SESSION_BUS_ADDRESS", "XDG_SESSION_PATH", "XDG_SEAT_PATH",
    "XDG_RUNTIME_DIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CONFIG_DIRS",
    "GPG_AGENT_INFO", "HISTFILE", "KEYRING_PID",
})


def _looks_like_path(value):
    """True for filesystem/socket paths that merely resemble a long blob.

    /org/freedesktop/DisplayManager/Session0 is 38 characters drawn entirely
    from [A-Za-z0-9+/], so it satisfied the "long base64 blob" rule even
    though "/" is only in that class to allow real base64 padding.
    """
    return value.startswith(("/", "~", "./", "../")) or os.path.exists(value)


def _is_secret_var(name, value):
    """Decide whether one environment entry looks like a credential."""
    if name.upper() in _BENIGN_VARS:
        return False
    if _SECRET_NAME_ANY.search(name) or _SECRET_NAME_TAIL.search(name):
        return True
    if value and _SECRET_VALUE.search(value):
        # A value-only hit must not be a path, or XDG_SESSION_PATH and
        # XDG_SEAT_PATH come back as secrets.
        return not _looks_like_path(value)
    return False

# ============================================================
# AI PROVIDERS
# ============================================================
# DeepSeek exposes an OpenAI-compatible /chat/completions endpoint.
DEEPSEEK_URL   = "https://api.deepseek.com/v1"
DEEPSEEK_MODEL = "deepseek-flash"

# Remediation replies are a handful of shell commands, but the DeepSeek
# reasoning models bill hidden chain-of-thought against max_tokens — a small
# budget can be consumed entirely by reasoning and return an empty answer.
AI_MAX_TOKENS  = 8192

# Single source of truth for the AI-provider dropdown: the combo index must
# match the position of the provider id here, and the saved config value.
PROVIDER_IDS = ["ollama", "claude", "deepseek"]

# Same design tokens as the ÆGIS Desktop (Electron) app's
# desktop/renderer/style.css :root palette, so rex reads as the same product
# in a different shell. cyan/teal was already an exact match; everything else
# is now pulled onto the same navy-tinted bg/border/text scale.
COLORS = {
    "bg":        "#0a0e14",
    "bg2":       "#12161e",
    "bg3":       "#181e28",
    "border":    "#2a3342",
    "border2":   "#3d4a5e",
    "cyan":      "#00e5c0",
    "cyan_dim":  "#00b89a",
    "purple":    "#6b8fd4",
    "text":      "#d0dfee",
    "text2":     "#7e9ab8",
    "text3":     "#3a4a60",
    "green":     "#00ff88",
    "red":       "#ff1744",
    "orange":    "#ff9100",
    "white":     "#ffffff",
}

AUDIT_SECTIONS = [
    "System Info",
    "CPU & Memory",
    "Disk",
    "Network",
    "Open Ports",
    "Running Processes",
    "Startup Services",
    "Firewall",
    "Intrusion Prevention (fail2ban)",
    "Users & Groups",
    "Sudo / Privileges",
    "SSH Config",
    "Scheduled Tasks",
    "SUID/SGID Files",
    "World-Writable Files",
    "Environment Secrets",
    "Sensitive File Permissions",
    "Malware & Rootkit Scanners",
]

VIRUS_SECTION = "Virus Scan (ClamAV)"

# Sections that cannot be assessed at all without psutil — keep in sync with
# the `if psutil is None` guards in _run_section.
PSUTIL_GATED_SECTIONS = ("CPU & Memory", "Disk", "Network", "Running Processes")

PSUTIL_MISSING = (
    "psutil not installed - CPU & Memory, Disk, Network and Running "
    "Processes cannot be assessed.\nInstall: pip install psutil"
)
SECTIONS = AUDIT_SECTIONS + [VIRUS_SECTION]

CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".aegis_config.json")

def _load_config() -> dict:
    try:
        with open(CONFIG_PATH) as f:
            return json.load(f)
    except Exception:  # noqa: BLE001
        return {}

def _save_config(data: dict):
    try:
        existing = _load_config()
        existing.update(data)
        with open(CONFIG_PATH, "w") as f:
            json.dump(existing, f, indent=2)
        if not IS_WIN:
            os.chmod(CONFIG_PATH, 0o600)
    except Exception:  # noqa: BLE001, S110
        pass

# ============================================================
# LATTICE BAKGRUND (diamond lattice — upgraded)
# ============================================================
class LatticeWidget(QWidget):
    """Diamond lattice with breathing lines, traveling spark particles,
    and drifting intersection nodes."""

    _SPACING = 40

    def __init__(self, parent=None):
        super().__init__(parent)
        self._offset = 0.0
        self._frame  = 0
        # sparks: [progress 0→1, line_index, direction +1/-1]
        self._sparks: list = []
        self._timer  = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(33)  # ~30 FPS

    def _tick(self):
        s = self._SPACING
        self._offset = (self._offset + 0.9) % s
        self._frame += 1
        # Spawn a new spark roughly every 55 frames (max 5 simultaneous)
        if self._frame % 55 == 0 and len(self._sparks) < 5:
            w = max(self.width(), 1)
            h = max(self.height(), 1)
            n_lines = (w + h * 2) // s + 4
            self._sparks.append([0.0, random.randint(0, n_lines - 1),
                                  random.choice([-1, 1])])
        # Advance sparks; cull finished ones
        self._sparks = [[p + 0.011, i, d] for p, i, d in self._sparks if p < 1.0]
        self.update()

    def paintEvent(self, event):
        super().paintEvent(event)
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h  = self.width(), self.height()
        s     = self._SPACING
        off   = self._offset
        frame = self._frame

        origins = list(range(-w - int(h * 1.5), w + int(h * 1.5), s))

        # ── Per-line breathing alpha (sine wave, each line offset) ───────────
        for idx, i in enumerate(origins):
            a1 = max(2, int(5 + 5 * math.sin(frame * 0.018 + idx * 0.45)))
            a2 = max(2, int(5 + 5 * math.sin(frame * 0.018 + idx * 0.45 + 1.1)))
            p.setPen(QPen(QColor(0, 229, 192, a1), 1))
            p.drawLine(int(i + off), 0, int(i + h + off), h)
            p.setPen(QPen(QColor(0, 229, 192, a2), 1))
            p.drawLine(int(i - off), h, int(i + h - off), 0)

        # ── Drifting intersection nodes ──────────────────────────────────────
        dot_off = int(off) % s
        p.setPen(Qt.PenStyle.NoPen)
        for nx in range(-s + dot_off, w + s, s):
            for ny in range(-s + dot_off, h + s, s):
                p.setBrush(QColor(0, 229, 192, 20))
                p.drawEllipse(nx - 1, ny - 1, 3, 3)

        # ── Traveling spark particles ────────────────────────────────────────
        for progress, line_idx, direction in self._sparks:
            if line_idx >= len(origins):
                continue
            i  = origins[line_idx]
            t  = progress
            if direction == 1:   # \ direction
                sx, sy = int(i + off + t * h), int(t * h)
            else:                # / direction
                sx, sy = int(i + h - off - t * h), int(t * h)
            if not (0 <= sx <= w and 0 <= sy <= h):
                continue
            # Layered glow: outer halo → bright core
            for radius, alpha in ((10, 6), (5, 25), (2, 110), (1, 220)):
                p.setPen(Qt.PenStyle.NoPen)
                p.setBrush(QColor(0, 229, 192, alpha))
                p.drawEllipse(sx - radius, sy - radius, radius * 2, radius * 2)

        p.end()


# ============================================================
# AUDIT WORKER (bakgrundstråd)
# ============================================================
class AuditEngine:
    """The audit itself — no Qt anywhere.

    Split out of AuditWorker so the same section code runs in the GUI, in the
    CLI, and under `import rex`. One engine means a model applying fixes sees
    byte-identical findings to the ones the GUI shows: no second implementation
    to drift.
    """

    def __init__(self, sections=None, scan_path=None):
        self.sections = list(sections) if sections else list(SECTIONS)
        # A recursive ClamAV walk is a deliberate, hours-long operation — rex
        # schedules it weekly for exactly that reason — so it only runs when a
        # target was named explicitly. Without this, the moment ClamAV is
        # installed a plain `rex.py --audit` silently starts scanning the whole
        # home directory and looks like it has hung.
        self.scan_path_explicit = scan_path is not None
        if scan_path is None:
            scan_path = os.path.expanduser("~")
        self.scan_path = os.path.realpath(scan_path)
        self._stop = False
        # ClamAV progress hook. The GUI bridges this to its Qt signal; headless
        # callers pass their own callback (or nothing).
        self._on_progress = lambda label, count: None

    def stop(self):
        self._stop = True

    def _run_safe(self, section):
        try:
            return self._run_section(section)
        except Exception as e:  # noqa: BLE001
            return "error", str(e)

    def collect(self, sections=None, progress=None):
        """Run sections, return {section: (status, output)}. Blocking, no Qt."""
        if progress is not None:
            self._on_progress = progress
        out = {}
        for section in (sections if sections is not None else self.sections):
            if self._stop:
                break
            out[section] = self._run_safe(section)
        return out

    def collect_parallel(self, sections=None, workers=8):
        """Same result, threaded. Order-independent — keyed by section."""
        todo = list(sections if sections is not None else self.sections)
        out = {}
        with ThreadPoolExecutor(max_workers=min(workers, max(1, len(todo)))) as ex:
            futures = {ex.submit(self._run_safe, s): s for s in todo if not self._stop}
            for future in as_completed(futures):
                section = futures[future]
                try:
                    out[section] = future.result()
                except Exception as e:  # noqa: BLE001
                    out[section] = ("error", str(e))
        return out

    # ── helpers ──────────────────────────────────────────────
    @staticmethod
    def _cmd(args, timeout=10):
        """Safe command runner — no shell=True."""
        if isinstance(args, str):
            args = shlex.split(args)
        try:
            r = subprocess.run(
                args,
                shell=False,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return (r.stdout + r.stderr).strip()
        except FileNotFoundError:
            return "[not found]"
        except subprocess.TimeoutExpired:
            return "[timeout]"
        except Exception as e:  # noqa: BLE001
            return f"[error: {e}]"

    @staticmethod
    def _split_noise(out):
        """Split merged command output into (findings, diagnostics).

        Returns the lines that are actual results and the lines that merely
        report a skipped path. Callers decide status from the findings only.
        """
        findings, noise = [], []
        for line in (out or "").splitlines():
            stripped = line.strip()
            if _FIND_NOISE.match(stripped) or _CMD_FAILED.match(stripped):
                noise.append(stripped)
            elif stripped:
                findings.append(line)
        return findings, noise

    @staticmethod
    def _pkg_split(paths):
        """Partition paths into (hand-placed, installed-by-a-package-manager).

        The SUID section used to judge by *path* alone, so a setuid helper that
        shipped inside a .deb but unpacked to /opt/<App>/ was reported as if
        someone had placed it by hand. Asking the package manager is the honest
        test. If no package manager is available the paths stay on the
        hand-placed side — absence of evidence is not a pass.
        """
        if not paths:
            return [], []
        owned = set()
        for exe_name in ("dpkg-query", "rpm", "pacman"):
            exe = shutil.which(exe_name)
            if not exe:
                continue
            out = AuditEngine._cmd([exe, "-S"] + [str(p) for p in paths], timeout=20)
            real, _ = AuditEngine._split_noise(out)
            for line in real:
                if ":" not in line:
                    continue
                # "terminal-ds: /opt/Terminal DS/chrome-sandbox" — split on the
                # first colon only; the path itself may contain spaces.
                _, _, resolved = line.partition(":")
                resolved = resolved.strip()
                if resolved:
                    owned.add(resolved)
            break  # first package manager that exists is the right one
        hand = [p for p in paths if p not in owned]
        packaged = [p for p in paths if p in owned]
        return hand, packaged

    @staticmethod
    def _na(feature):
        return "ok", f"[N/A on {_OS}] {feature} is not applicable on this platform."

    @staticmethod
    def _sect_unassessed(section, out):
        """A failed probe is not a clean host — report it as unassessed.

        The default guess for a timed-out `find` used to be "ok, nothing
        found", which reads as a pass. It is not: nothing was scanned.
        """
        reason = (out or "").strip() or "unknown error"
        return "error", (
            f"{section} could not be assessed — the underlying command did not "
            f"complete ({reason}).\n"
            "This is absence of evidence, not a clean result. Re-run on an "
            "unloaded host (or raise the timeout) before treating it as passed."
        )

    # ── section dispatcher ────────────────────────────────────
    def _run_section(self, section):
        cmd = self._cmd

        # ── System Info (all platforms) ───────────────────────
        if section == "System Info":
            lines = [
                f"Hostname   : {socket.gethostname()}",
                f"OS         : {platform.platform()}",
                f"Kernel     : {platform.release()}",
                f"Arch       : {platform.machine()}",
                f"Python     : {platform.python_version()}",
                f"User       : {os.getenv('USERNAME') or os.getenv('USER', 'unknown')}",
                f"Date/Time  : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",  # noqa: DTZ005
            ]
            return "ok", "\n".join(lines)

        # ── CPU & Memory (all platforms via psutil) ───────────
        elif section == "CPU & Memory":
            if psutil is None:
                # Absence of evidence, not a finding: the check never ran.
                return "error", PSUTIL_MISSING
            cpu_pct = psutil.cpu_percent(interval=1)
            cpu_cnt = psutil.cpu_count(logical=True)
            mem     = psutil.virtual_memory()
            swap    = psutil.swap_memory()
            lines = [
                f"CPU Usage  : {cpu_pct}%",
                f"CPU Cores  : {cpu_cnt}",
                f"RAM Total  : {mem.total  // (1024**2)} MB",
                f"RAM Used   : {mem.used   // (1024**2)} MB ({mem.percent}%)",
                f"RAM Free   : {mem.available // (1024**2)} MB",
                f"Swap Total : {swap.total // (1024**2)} MB",
                f"Swap Used  : {swap.used  // (1024**2)} MB ({swap.percent}%)",
            ]
            status = "warn" if mem.percent > 85 or swap.percent > 50 else "ok"
            return status, "\n".join(lines)

        # ── Disk (all platforms via psutil) ───────────────────
        elif section == "Disk":
            if psutil is None:
                # Absence of evidence, not a finding: the check never ran.
                return "error", PSUTIL_MISSING
            out = []
            warn = False
            for part in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    pct = usage.percent
                    out.append(
                        f"{part.device} → {part.mountpoint}  "
                        f"{usage.used // (1024**3)}G / {usage.total // (1024**3)}G ({pct}%)"
                    )
                    if pct > 90:
                        warn = True
                except Exception:  # noqa: BLE001, S110
                    pass
            return ("warn" if warn else "ok"), "\n".join(out) or "No partitions found"

        # ── Network (all platforms via psutil) ────────────────
        elif section == "Network":
            if psutil is None:
                # Absence of evidence, not a finding: the check never ran.
                return "error", PSUTIL_MISSING
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            out = []
            for iface, addr_list in addrs.items():
                st = stats.get(iface)
                up = "UP" if st and st.isup else "DOWN"
                for a in addr_list:
                    if a.family == socket.AF_INET:
                        out.append(f"{iface} [{up}]  {a.address}")
            return "ok", "\n".join(out) or "No network interfaces"

        # ── Open Ports ────────────────────────────────────────
        elif section == "Open Ports":
            suspicious = ["4444", "1337", "31337", "6666", "9999"]
            if IS_WIN:
                out = cmd(["netstat", "-ano"], timeout=10)
            elif IS_MAC:
                out = cmd(["netstat", "-an", "-p", "tcp"], timeout=10)
                if not out or "[not found]" in out:
                    out = cmd(["lsof", "-iTCP", "-sTCP:LISTEN", "-n", "-P"], timeout=10)
            else:  # Linux
                out = cmd(["ss", "-tlnp"], timeout=8)
                if not out or "[not found]" in out:
                    out = cmd(["netstat", "-tlnp"], timeout=8)
            # A port is only "open" off-host if it is bound to a non-loopback
            # address, and that is independent of how innocuous the number
            # looks — a container publishing 0.0.0.0:4007 is reachable from the
            # LAN however arbitrary 4007 is. ss and netstat both put the local
            # address in field 4 of a LISTEN row, so one parser covers both.
            #
            # A handful of services are *expected* to bind LAN-wide on a
            # desktop; reporting those would make the section warn on every
            # machine, and a check that always warns is a check nobody reads.
            # They are listed in the output but do not drive the status.
            EXPECTED_LAN = {"22", "53", "139", "445", "631", "5353"}
            lan, unexpected = [], []
            for line in (out or "").splitlines():
                if "LISTEN" not in line:
                    continue
                parts = line.split()
                if len(parts) < 4:
                    continue
                host, _, port = parts[3].rpartition(":")
                if not host or not port.isdigit():
                    continue
                if host.startswith("127.") or host in ("[::1]", "::1", "localhost"):
                    continue  # loopback-only: not reachable off-host
                lan.append(f"{parts[3]:<26} {parts[-1]}")
                if port not in EXPECTED_LAN:
                    unexpected.append(f"{parts[3]:<26} {parts[-1]}")

            status = "warn" if any(p in out for p in suspicious) else "ok"
            if unexpected:
                status = "warn"
            if lan and not _probe_failed(out):
                out = (out or "").rstrip() + "\n\nNon-loopback listeners " \
                    "(reachable off-host):\n  " + "\n  ".join(lan)
            return status, out or "No open ports found"

        # ── Running Processes (psutil — all platforms) ────────
        elif section == "Running Processes":
            if psutil is None:
                # Absence of evidence, not a finding: the check never ran.
                return "error", PSUTIL_MISSING
            procs = []
            for p in psutil.process_iter(["pid", "name", "username", "cpu_percent"]):
                try:
                    procs.append(
                        f"{p.info['pid']:>6}  {p.info['username'] or ''!s:<15}  {p.info['name']}"
                    )
                except Exception:  # noqa: BLE001, S110
                    pass
            suffix = "\n[truncated...]" if len(procs) > 60 else ""
            return "ok", "\n".join(procs[:60]) + suffix

        # ── Startup Services ──────────────────────────────────
        elif section == "Startup Services":
            if IS_WIN:
                out = cmd(
                    ["sc", "query", "type=", "all", "state=", "running"],
                    timeout=12,
                )
                if not out or "[not found]" in out:
                    out = cmd(
                        ["powershell", "-NoProfile", "-Command",
                         ("Get-Service | Where-Object {$_.StartType -eq 'Automatic'} | "
                          "Select-Object Name,Status | Format-Table -AutoSize")],
                        timeout=15,
                    )
            elif IS_MAC:
                out = cmd(["launchctl", "list"], timeout=10)
                if out:
                    out = "\n".join(out.splitlines()[:50])
            else:
                out = cmd(
                    ["systemctl", "list-unit-files", "--type=service", "--state=enabled"],
                    timeout=10,
                )
                if out:
                    out = "\n".join(out.splitlines()[:40])
            return "ok", out or "Could not retrieve startup services"

        # ── Firewall ──────────────────────────────────────────
        elif section == "Firewall":
            if IS_WIN:
                out = cmd(
                    ["netsh", "advfirewall", "show", "allprofiles"],
                    timeout=10,
                )
                status = "ok"
                if "State                                 OFF" in out:
                    status = "warn"
                return status, out or "Could not query Windows Firewall"

            elif IS_MAC:
                # Application-level firewall (socketfilterfw)
                fw_bin = "/usr/libexec/ApplicationFirewall/socketfilterfw"
                if os.path.exists(fw_bin):
                    state  = cmd([fw_bin, "--getglobalstate"], timeout=6)
                    blocks = cmd([fw_bin, "--getblockall"],    timeout=6)
                    stealth = cmd([fw_bin, "--getstealthmode"], timeout=6)
                    out = "\n".join([
                        f"Global state : {state}",
                        f"Block all    : {blocks}",
                        f"Stealth mode : {stealth}",
                    ])
                    status = "warn" if "disabled" in state.lower() else "ok"
                    return status, out
                # Fallback: pf
                out = cmd(["pfctl", "-s", "rules"], timeout=8)
                return "ok", out or "pf rules empty or permission denied"

            else:  # Linux
                # `ufw status` needs root. Unprivileged it prints "ERROR: You
                # need to be root to run this script" and exits non-zero — so
                # the failure arrives as ordinary-looking text, NOT as a
                # _CMD_FAILED sentinel, and the old "[error" test never matched
                # it. The result was a section reporting ok while its own
                # output was an error message.
                #
                # Try the non-prompting sudo path first (the fail2ban and
                # AppArmor probes use the same idiom), then fall back to the
                # config files, which are world-readable and carry the
                # authoritative ENABLED / DEFAULT_*_POLICY keys. Only if all of
                # that fails is the section "error" — never "ok".
                ufw = cmd(["sudo", "-n", "ufw", "status", "verbose"], timeout=8)
                if ("need to be root" in ufw.lower()
                        or "password is required" in ufw.lower()
                        or _probe_failed(ufw)):
                    ufw = ""

                policies = {}
                for conf in ("/etc/ufw/ufw.conf", "/etc/default/ufw"):
                    try:
                        with open(conf, encoding="utf-8", errors="replace") as fh:
                            body = fh.read()
                    except OSError:
                        continue
                    for key, val in re.findall(
                        r"^\s*(ENABLED|DEFAULT_INPUT_POLICY|DEFAULT_FORWARD_POLICY"
                        r"|DEFAULT_OUTPUT_POLICY)\s*=\s*\"?([A-Za-z]+)",
                        body, re.MULTILINE,
                    ):
                        policies[key] = val.upper()

                # Docker creates its own FORWARD/DOCKER-USER chains ahead of
                # ufw's, so a published container port stays reachable even
                # with DEFAULT_INPUT_POLICY=DROP and no matching ufw profile.
                # ufw being "on" says nothing about it; read the publishes.
                exposed, docker_note = [], ""
                if shutil.which("docker"):
                    ps = cmd(["docker", "ps", "--format",
                              "{{.Names}}\t{{.Ports}}"], timeout=10)
                    if not _probe_failed(ps):
                        for line in ps.splitlines():
                            if "->" not in line:
                                continue
                            # The leading-context alternative must include
                            # whitespace, not just ",". docker ps emits
                            # "<name>\t<ports>", so the FIRST publish in a field
                            # is preceded by a tab, not a comma — and a bare
                            # IPv4 publish ("127.0.0.1:4007->5000/tcp") starts a
                            # token with nothing before it. Matching only ","
                            # made this blind to exactly the IPv4 exposures it
                            # exists to find (it looked fine only because docker
                            # rewrites 0.0.0.0 publishes to [::]).
                            pubs = re.findall(
                                r"(?:^|[\s,])(\[?[\w:.]*?\]?):(\d+)->", line)
                            hosts = [h for h, _ in pubs]
                            if any(h not in ("127.0.0.1", "[::1]", "::1")
                                   for h in hosts):
                                exposed.append(line.split("\t")[0])
                        if exposed:
                            docker_note = (
                                "\n\nDocker publishes bypass ufw (its FORWARD/"
                                "DOCKER-USER rules run first). Reachable off-host:"
                                + "".join(f"\n  - {name}" for name in exposed))

                enabled = policies.get("ENABLED")
                in_pol = policies.get("DEFAULT_INPUT_POLICY")

                if ufw:
                    status = "warn" if "inactive" in ufw.lower() else "ok"
                    detail = ufw
                elif enabled is None:
                    # An unparseable probe is absence of evidence, not a finding
                    # (the same rule rex applies to a failed LAN-listen probe).
                    # Returning the neutral "info" status keeps a host with no
                    # ufw installed from turning the whole audit into an error; a
                    # genuine unexpected exception is still caught upstream by
                    # _run_safe() and reported as "error".
                    return "info", (
                        "Could not determine firewall state: `ufw status` needs "
                        "root (tried sudo -n) and /etc/ufw/*.conf were unreadable "
                        "(ufw may not be installed).")
                else:
                    detail = "\n".join([
                        f"ENABLED               : {enabled}",
                        f"DEFAULT_INPUT_POLICY  : {in_pol or '?'}",
                        f"DEFAULT_FORWARD_POLICY: {policies.get('DEFAULT_FORWARD_POLICY', '?')}",
                        ("(from /etc/ufw/ufw.conf + /etc/default/ufw — per-rule "
                         "detail and `iptables -L` need root)"),
                    ])
                    if enabled != "YES":
                        status = "warn"
                    elif in_pol in ("DROP", "REJECT"):
                        status = "ok"
                    else:
                        status = "warn"

                if exposed:
                    status = "warn"
                return status, (detail + docker_note).strip()

        # ── Intrusion Prevention (fail2ban) ───────────────────
        elif section == "Intrusion Prevention (fail2ban)":
            if IS_WIN:
                return self._na("fail2ban (use Windows Defender Firewall rules "
                                "or 'netsh advfirewall' lockout instead)")

            client = shutil.which("fail2ban-client")
            lines = []

            if not client:
                # On macOS the equivalent job is sshguard / pf, so name that
                # rather than telling a Mac user to apt-get.
                if IS_MAC:
                    return "warn", (
                        "fail2ban not installed.\n"
                        "macOS alternatives: sudo pfctl + sshguard, or "
                        "'brew install fail2ban' (needs a launchd plist to stay up).")
                hint = "sudo apt install fail2ban   # then: sudo systemctl enable --now fail2ban"
                # A host can also be protected by an alternative IP-banner; if
                # one is present, say so instead of claiming zero protection.
                alts = [t for t in ("sshguard", "crowdsec", "f2b", "denyhosts")
                        if shutil.which(t)]
                note = (f"\nAlternative ban tool(s) present: {', '.join(alts)}"
                        if alts else
                        "\nNo alternative IP-banner (sshguard/crowdsec/denyhosts) found "
                        "either — SSH brute-force attempts are only bounded by sshd's "
                        "own MaxAuthTries.")
                return "warn", f"fail2ban not installed.\nInstall: {hint}{note}"

            ver = cmd([client, "--version"], timeout=8)
            lines.append(f"Client version : {ver.splitlines()[0] if ver else 'unknown'}")

            if IS_MAC:
                # No systemd; a launchd job is what keeps it resident.
                active = bool(cmd(["launchctl", "list"], timeout=8).find("fail2ban") >= 0)
            else:
                unit = cmd(["systemctl", "is-active", "fail2ban"], timeout=8)
                enabled = cmd(["systemctl", "is-enabled", "fail2ban"], timeout=8)
                active = unit.strip() == "active"
                lines.append(f"Service        : {unit.strip()} (boot: {enabled.strip()})")

            # Jail detail lives behind the fail2ban socket, which is root-only
            # on a stock install. Probe as the invoking user first, then with
            # `sudo -n` (never prompts), and be explicit when neither worked.
            status_out = cmd([client, "status"], timeout=10)
            need_root = _probe_failed(status_out) or "permission" in status_out.lower() \
                or "Failed to access socket" in status_out
            if need_root:
                sudo_out = cmd(["sudo", "-n", client, "status"], timeout=10)
                if not _probe_failed(sudo_out) and "Failed to access socket" not in sudo_out:
                    status_out = sudo_out
                    need_root = False

            jails, jails_readable = [], False
            if not need_root and "Jail list:" in status_out:
                jails_readable = True
                tail = status_out.split("Jail list:", 1)[1].strip()
                jails = [j.strip() for j in tail.split(",") if j.strip()]

            lines.append("Jails          : "
                         + (", ".join(jails) if jails else
                            "none reported" if jails_readable else
                            "unknown (needs root to read the fail2ban socket)"))

            for jail in jails[:5]:
                detail = cmd([client, "status", jail], timeout=8)
                if _probe_failed(detail) or "Failed to access socket" in detail:
                    continue
                banned = total = failed = ""
                for line in detail.splitlines():
                    key, _, val = line.partition(":")
                    key, val = key.strip(), val.strip()
                    if key.endswith("Currently banned"):
                        banned = val
                    elif key.endswith("Total banned"):
                        total = val
                    elif key.endswith("Total failed"):
                        failed = val
                if banned or total or failed:
                    lines.append(
                        f"  ├─ {jail:<12} banned now {banned or '?'} / "
                        f"total {total or '?'} / failed attempts {failed or '?'}")

            # Effective ban policy, if the local overrides are readable.
            policy = {}
            for path in ("/etc/fail2ban/jail.local", "/etc/fail2ban/jail.conf"):
                if not os.path.isfile(path):
                    continue
                try:
                    with open(path) as fh:
                        for raw in fh:
                            line = raw.split("#", 1)[0].strip()
                            key, sep, val = line.partition("=")
                            if sep and key.strip() in ("bantime", "findtime",
                                                       "maxretry", "backend"):
                                policy.setdefault(key.strip(), val.strip())
                except OSError:
                    continue
                if policy:
                    lines.append("Policy         : "
                                 + ", ".join(f"{k}={v}" for k, v in policy.items())
                                 + f"   (from {path})")
                    break

            if not active:
                lines.append("")
                lines.append("⚠  fail2ban is installed but the service is NOT running — "
                             "jail policy above is inert.")
                lines.append("   Fix: sudo systemctl enable --now fail2ban")
                return "warn", "\n".join(lines)

            if jails_readable and not jails:
                lines.append("")
                lines.append("⚠  Service is running but no jail is enabled — nothing is "
                             "being blocked. Enable [sshd] in /etc/fail2ban/jail.local.")
                return "warn", "\n".join(lines)

            if need_root:
                lines.append("")
                lines.append("(Jail/banned-IP detail needs root; run with sudo for the "
                             "full picture. Service state above is authoritative.)")
            return "ok", "\n".join(lines)

        # ── Users & Groups ────────────────────────────────────
        elif section == "Users & Groups":
            if IS_WIN:
                out = cmd(["net", "user"], timeout=8)
                return "ok", out or "Could not list users"

            elif IS_MAC:
                out = cmd(["dscl", ".", "-list", "/Users"], timeout=8)
                if out and "[not found]" not in out:
                    # filter hidden system users (start with _)
                    filtered = [line for line in out.splitlines() if not line.startswith("_")]
                    return "ok", "\n".join(filtered)
                # fallback
                try:
                    lines = []
                    with open("/etc/passwd") as f:
                        for line in f:
                            parts = line.strip().split(":")
                            if len(parts) >= 7 and parts[6] not in ("/usr/bin/false", "/sbin/nologin"):
                                lines.append(f"{parts[0]:<20} uid={parts[2]:<6} home={parts[5]}")
                    return "ok", "\n".join(lines) or "No login users found"
                except Exception as e:  # noqa: BLE001
                    return "error", str(e)

            else:  # Linux
                try:
                    lines = []
                    with open("/etc/passwd") as f:
                        for line in f:
                            parts = line.strip().split(":")
                            if len(parts) >= 7 and parts[6] not in (
                                "/usr/sbin/nologin", "/bin/false", "/sbin/nologin"
                            ):
                                lines.append(f"{parts[0]:<20} uid={parts[2]:<6} home={parts[5]}")
                    return "ok", "\n".join(lines) or "No login users found"
                except Exception as e:  # noqa: BLE001
                    return "error", f"Could not read /etc/passwd: {e}"

        # ── Sudo / Privileges ─────────────────────────────────
        elif section == "Sudo / Privileges":
            if IS_WIN:
                # Show token privileges and whether we're in an elevated context
                out = cmd(["whoami", "/all"], timeout=8)
                if not out or "[not found]" in out:
                    out = cmd(["whoami", "/priv"], timeout=8)
                status = "warn" if "SeDebugPrivilege" in out or "Enabled" in out else "ok"
                return status, out or "Could not query privileges"

            else:  # Linux + macOS
                out = cmd(["sudo", "-l"], timeout=8)
                if not out or "[error" in out or "[not found]" in out:
                    return "warn", "Could not retrieve sudo rules (sudo -l failed)"
                status = "warn" if "NOPASSWD" in out else "ok"
                return status, out

        # ── SSH Config ────────────────────────────────────────
        elif section == "SSH Config":
            if IS_WIN:
                paths = [
                    r"C:\ProgramData\ssh\sshd_config",
                    os.path.expandvars(r"%WINDIR%\System32\OpenSSH\sshd_config"),
                ]
            else:
                paths = ["/etc/ssh/sshd_config"]

            cfg_path = next((p for p in paths if os.path.exists(p)), None)
            if cfg_path is None:
                return "ok", "sshd_config not found — SSH server may not be installed"
            try:
                with open(cfg_path) as f:
                    raw = f.read()
                active = [line for line in raw.splitlines() if line.strip() and not line.strip().startswith("#")]
                out = "\n".join(active)
            except PermissionError:
                return "warn", "Permission denied reading sshd_config (run as admin/root for full audit)"
            except Exception as e:  # noqa: BLE001
                return "error", str(e)

            warnings = []
            if "PermitRootLogin yes" in out:
                warnings.append("⚠  PermitRootLogin yes")
            if "PasswordAuthentication yes" in out:
                warnings.append("⚠  PasswordAuthentication yes")
            if "PermitEmptyPasswords yes" in out:
                warnings.append("⚠  PermitEmptyPasswords yes")
            status = "warn" if warnings else "ok"
            header = "\n".join(warnings) + "\n\n" if warnings else ""
            return status, (header + out).strip() or "SSH config empty"

        # ── Scheduled Tasks / Cron ────────────────────────────
        elif section == "Scheduled Tasks":
            if IS_WIN:
                out = cmd(["schtasks", "/query", "/fo", "LIST", "/v"], timeout=15)
                if out:
                    # Trim to first 60 lines to avoid wall of text
                    out = "\n".join(out.splitlines()[:60])
                    if len(out.splitlines()) == 60:
                        out += "\n[truncated...]"
                return "ok", out or "No scheduled tasks found"

            elif IS_MAC:
                parts = []
                user_cron = cmd(["crontab", "-l"], timeout=5)
                if user_cron and "[error" not in user_cron and "[not found]" not in user_cron:
                    parts.append("=== User crontab ===\n" + user_cron)
                # LaunchAgents
                for d in [
                    os.path.expanduser("~/Library/LaunchAgents"),
                    "/Library/LaunchAgents",
                    "/Library/LaunchDaemons",
                ]:
                    if os.path.isdir(d):
                        files = os.listdir(d)
                        if files:
                            parts.append(f"=== {d} ===\n" + "\n".join(files))
                return "ok", "\n\n".join(parts) or "No scheduled tasks found"

            else:  # Linux
                parts = []
                user_cron = cmd(["crontab", "-l"], timeout=5)
                if user_cron and "[error" not in user_cron and "[not found]" not in user_cron:
                    parts.append("=== User crontab ===\n" + user_cron)
                cron_d = cmd(["ls", "/etc/cron.d"], timeout=5)
                if cron_d and "[error" not in cron_d:
                    parts.append("=== /etc/cron.d ===\n" + cron_d)
                try:
                    with open("/etc/crontab") as f:
                        active = [line for line in f.read().splitlines() if line.strip() and not line.startswith("#")]
                    if active:
                        parts.append("=== /etc/crontab ===\n" + "\n".join(active))
                except Exception:  # noqa: BLE001, S110
                    pass
                return "ok", "\n\n".join(parts) or "No cron jobs found"

        # ── SUID/SGID Files ───────────────────────────────────
        elif section == "SUID/SGID Files":
            if IS_WIN:
                # Windows equivalent: files with Everyone:FullControl
                out = cmd(
                    ["powershell", "-NoProfile", "-Command",
                     (r"Get-ChildItem 'C:\Windows\System32' -File | "
                      r"ForEach-Object { $acl = Get-Acl $_.FullName; "
                      r"$acl.Access | Where-Object {$_.IdentityReference -match 'Everyone' "
                      r"-and $_.FileSystemRights -match 'FullControl'} | "
                      r"ForEach-Object { $_.Path } } | Select-Object -First 30")],
                    timeout=30,
                )
                status = "warn" if out and "[error" not in out and out.strip() else "ok"
                return status, out or "No world-accessible binaries found in System32"

            else:  # Linux + macOS
                # Where a distro's package manager is allowed to drop a
                # SUID/SGID binary. A stock Ubuntu box carries ~30 helpers in
                # /usr/bin and /usr/lib (sudo, passwd, mount, su, pkexec …);
                # reporting that inventory as a defect buries the one binary
                # that was actually put there by hand. So the bit itself is
                # inventoried, and only *where* it was found decides the status.
                managed_dirs = (
                    "/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/lib32/",
                    "/usr/lib64/", "/usr/libexec/", "/bin/", "/sbin/",
                    "/lib/", "/lib32/", "/lib64/",
                )
                if IS_MAC:
                    managed_dirs = ("/usr/bin/", "/usr/sbin/", "/usr/lib/",
                                    "/usr/libexec/", "/bin/", "/sbin/", "/System/")
                # /home is deliberately absent: a recursive scan of home dirs
                # exceeded 120s on a real machine, and an audit that stalls is
                # worse than one with a stated scope. The remaining roots are
                # sub-second.
                scan_roots = ["/usr", "/bin", "/sbin", "/lib", "/lib64",
                              "/usr/local", "/opt", "/tmp", "/var/tmp"]
                existing = [p for p in scan_roots if os.path.isdir(p)]
                out = cmd(["find"] + existing + ["-perm", "/6000", "-type", "f"], timeout=25)
                if _probe_failed(out):
                    return self._sect_unassessed(section, out)
                real, noise = self._split_noise(out)
                managed = [f for f in real if f.startswith(managed_dirs)]
                unexpected = [f for f in real if not f.startswith(managed_dirs)]
                # Ruling by path alone reported /opt/Terminal DS/chrome-sandbox
                # as hand-placed; it belongs to the terminal-ds package. Only a
                # binary that neither the distro nor a package shipped is a
                # finding.
                hand, packaged = self._pkg_split(unexpected)
                inventory = len(managed) + len(packaged)
                suffix = f"\n({len(noise)} path(s) not readable, skipped)" if noise else ""
                if hand:
                    lines = hand[:30]
                    body = "\n".join(lines)
                    if len(hand) > 30:
                        body += f"\n[truncated at 30 of {len(hand)} results]"
                    if inventory:
                        body += (f"\n({inventory} SUID/SGID binary(ies) under distro- or "
                                 f"package-managed locations, expected inventory)")
                    return "warn", body + suffix
                if inventory:
                    return "ok", (f"{inventory} SUID/SGID binaries found, all under distro- "
                                  f"or package-managed locations (expected inventory)" + suffix)
                return "ok", "No SUID/SGID files found in scanned paths" + suffix

        # ── World-Writable Files ──────────────────────────────
        elif section == "World-Writable Files":
            if IS_WIN:
                # Check world-writable dirs in common system paths
                out = cmd(
                    ["icacls", r"C:\Windows\Temp"],
                    timeout=10,
                )
                return "ok", out or "Could not check world-writable paths"

            else:  # Linux + macOS
                check_paths = ["/etc", "/usr", "/bin", "/sbin"]
                if IS_MAC:
                    check_paths = ["/etc", "/usr", "/bin"]
                out = cmd(
                    ["find"] + check_paths + ["-perm", "-o+w", "-type", "f"],
                    timeout=15,
                )
                if _probe_failed(out):
                    return self._sect_unassessed(section, out)
                real, noise = self._split_noise(out)
                if real:
                    out = "\n".join(real[:20])
                    if noise:
                        out += f"\n({len(noise)} path(s) not readable, skipped)"
                    return "warn", out
                note = "No world-writable files found in critical dirs"
                if noise:
                    note += f" ({len(noise)} path(s) not readable, skipped)"
                return "ok", note

        # ── Malware & Rootkit Scanners ────────────────────────
        # Availability/freshness audit only — the actual file scan is the
        # separate Virus Scan (ClamAV) section, which needs a path and can
        # run for hours. This section answers "is this host even equipped to
        # notice malware, and is that equipment current?"
        elif section == "Malware & Rootkit Scanners":
            scanners = [
                ("ClamAV (clamscan)",  ["clamscan"]),
                ("ClamAV daemon",      ["clamdscan", "clamd"]),
                ("freshclam updater",  ["freshclam"]),
                ("rkhunter",           ["rkhunter"]),
                ("chkrootkit",         ["chkrootkit"]),
                ("Lynis",              ["lynis"]),
                ("AIDE (integrity)",   ["aide", "aide.wrapper"]),
                ("YARA",               ["yara"]),
                ("unhide",             ["unhide", "unhide-tcp"]),
                ("debsums (pkg verify)", ["debsums"]),
            ]
            present, absent = [], []
            for label, bins in scanners:
                hit = next((shutil.which(b) for b in bins if shutil.which(b)), None)
                (present if hit else absent).append((label, hit))

            lines = ["Installed scanners:"]
            if present:
                for label, path in present:
                    lines.append(f"  ✓ {label:<24} {path}")
            else:
                lines.append("  (none)")

            reasons = []

            # ── signature freshness ───────────────────────────
            # A scanner with year-old definitions is a false sense of security,
            # so age is reported even when the binary is present and healthy.
            sig_dirs = ["/var/lib/clamav", "/var/lib/clamav-unofficial-sigs",
                        "/usr/local/var/lib/clamav", "/opt/homebrew/var/lib/clamav",
                        r"C:\Program Files\ClamAV\database"]
            sig_files = []
            for d in sig_dirs:
                if not os.path.isdir(d):
                    continue
                try:
                    for name in os.listdir(d):
                        if name.endswith((".cvd", ".cld", ".hdb", ".ndb", ".ldb")):
                            p = os.path.join(d, name)
                            sig_files.append((os.path.getmtime(p), p))
                except OSError:
                    continue
            if sig_files:
                newest_mtime, newest_path = max(sig_files)
                age_days = (time.time() - newest_mtime) / 86400.0
                stamp = datetime.datetime.fromtimestamp(
                    newest_mtime,
                    tz=datetime.timezone.utc).astimezone().strftime("%Y-%m-%d")
                lines.append("")
                lines.append(f"ClamAV definitions : {len(sig_files)} file(s), newest "
                             f"{stamp} ({age_days:.1f} days old)")
                lines.append(f"                     {newest_path}")
                if age_days > 7:
                    if _freshclam_daemon_up():
                        # Stale definitions *while* the updater runs means the
                        # updater is failing, not absent. Point at its journal:
                        # a manual freshclam could not even take the log lock.
                        reasons.append(
                            f"ClamAV definitions are {age_days:.0f} days old and the "
                            f"freshclam service IS running — the updater is failing, "
                            f"not missing. Check: journalctl -u clamav-freshclam")
                    else:
                        reasons.append(
                            f"ClamAV definitions are {age_days:.0f} days old — signatures "
                            f"do not cover recent malware. Fix: {_freshclam_hint()}")
            elif any(label.startswith("ClamAV") for label, _ in present):
                lines.append("")
                lines.append("ClamAV definitions : none found in "
                             + ", ".join(sig_dirs[:2]))
                if _freshclam_daemon_up():
                    reasons.append("ClamAV is installed and the updater is running, but "
                                   "no signature database is present — the update is "
                                   "failing. Check: journalctl -u clamav-freshclam")
                else:
                    reasons.append("ClamAV is installed but no signature database is "
                                   f"present. Fix: {_freshclam_hint()}")

            # ── updater boot-enablement ───────────────────────
            # A running-but-not-enabled updater keeps signatures current right
            # up until the next reboot, then silently stops forever. Only
            # fail2ban's is-enabled was ever checked, so this went unreported
            # and the section could claim "all current and scheduled" while the
            # database quietly froze. is-enabled is the only way to see it.
            if any(label.startswith("ClamAV") for label, _ in present):
                fc_state = ""
                st = cmd(["systemctl", "is-enabled", "clamav-freshclam"], timeout=8)
                if not _probe_failed(st):
                    fc_state = (st.strip().splitlines() or [""])[0].strip()
                if fc_state in ("disabled", "masked", "masked-runtime"):
                    lines.append(f"Updates at boot: {fc_state} — updates stop after reboot")
                    reasons.append(
                        f"clamav-freshclam is {fc_state} at boot — signature updates "
                        "stop after the next reboot even though the updater is running "
                        "now. Fix: sudo systemctl enable --now clamav-freshclam")
                elif fc_state and fc_state != "not-found":
                    lines.append(f"Updates at boot: {fc_state}")

            # ── scheduled scanning ────────────────────────────
            sched = []
            for cron_dir in ("/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.d",
                             "/etc/cron.hourly"):
                if not os.path.isdir(cron_dir):
                    continue
                try:
                    for name in os.listdir(cron_dir):
                        if any(k in name.lower() for k in
                               ("rkhunter", "chkrootkit", "clam", "lynis", "aide")):
                            sched.append(os.path.join(cron_dir, name))
                except OSError:
                    continue
            timers = cmd(["systemctl", "list-timers", "--all", "--no-pager"], timeout=10)
            if not _probe_failed(timers):
                for line in timers.splitlines():
                    low = line.lower()
                    if any(k in low for k in
                           ("rkhunter", "chkrootkit", "clamav", "freshclam",
                            "lynis", "aide")):
                        sched.append(f"systemd timer: {line.split()[-1]}")
            lines.append("")
            lines.append("Scheduled scans : "
                         + ("; ".join(sorted(set(sched))[:5]) if sched else "none found"))
            if present and not sched:
                reasons.append(
                    "No recurring scan is scheduled (no cron entry or systemd timer "
                    "for any installed scanner), so detection depends on someone "
                    "running it by hand.")

            # ── kernel-level malware defence (MAC) ────────────
            mac_state, mac_ok = "not detected", None
            if IS_MAC:
                sip = cmd(["csrutil", "status"], timeout=8)
                mac_state = sip.strip() or "unknown"
                mac_ok = "enabled" in mac_state.lower()
            elif IS_WIN:
                av = cmd(["powershell", "-NoProfile", "-Command",
                          ("Get-MpComputerStatus | Select-Object -ExpandProperty "
                           "RealTimeProtectionEnabled")], timeout=20)
                mac_state = f"Defender real-time protection: {av.strip() or 'unknown'}"
                mac_ok = av.strip().lower().startswith("true")
            elif shutil.which("aa-status"):
                aa = cmd(["aa-status"], timeout=15)
                # Without root aa-status exits 0 but prints "You do not have
                # enough privilege to read the profile set." — reading the
                # counts out of that yields 0/0, which would be published as
                # "AppArmor: 0 enforcing" and scored as a hardening failure.
                # It is not a failure, it is an unread count.
                needs_root = ("enough privilege" in aa.lower()
                              or "operation not permitted" in aa.lower())
                if needs_root:
                    sudo_aa = cmd(["sudo", "-n", "aa-status"], timeout=15)
                    retry_ok = (not _probe_failed(sudo_aa)
                                and "enough privilege" not in sudo_aa.lower()
                                and "password is required" not in sudo_aa.lower())
                    if retry_ok:
                        aa, needs_root = sudo_aa, False
                if needs_root or _probe_failed(aa):
                    mac_state = ("AppArmor loaded; profile set needs root to read "
                                 "(re-run with sudo for counts)")
                else:
                    enforce = complain = loaded = None
                    for line in aa.splitlines():
                        s = line.strip()
                        if s.endswith("profiles are loaded."):
                            loaded = int(s.split()[0])
                        elif s.endswith("profiles are in enforce mode."):
                            enforce = int(s.split()[0])
                        elif s.endswith("profiles are in complain mode."):
                            complain = int(s.split()[0])
                    if loaded is None:
                        mac_state = "AppArmor present (unparsable status output)"
                    else:
                        mac_state = (f"AppArmor: {loaded} loaded, "
                                     f"{enforce or 0} enforcing, "
                                     f"{complain or 0} complain")
                        mac_ok = (enforce or 0) > 0
            elif shutil.which("getenforce"):
                se = cmd(["getenforce"], timeout=8)
                mac_state = f"SELinux: {se.strip()}"
                mac_ok = se.strip().lower() == "enforcing"
            lines.append("")
            lines.append(f"MAC / live AV   : {mac_state}")
            if mac_ok is False:
                reasons.append(
                    f"Kernel-level malware defence is not enforcing ({mac_state}) — "
                    "rootkits that tamper with system binaries face no policy check.")

            if not present:
                if IS_WIN:
                    hint = "winget install ClamAV   # then run: freshclam"
                elif IS_MAC:
                    hint = "brew install clamav rkhunter && sudo freshclam"
                else:
                    # Installing clamav on Debian/Ubuntu starts clamav-freshclam,
                    # which downloads the database itself. Chaining a manual
                    # `freshclam` here would collide with it over the log file
                    # and abort with "Resource temporarily unavailable".
                    hint = ("sudo apt install clamav rkhunter chkrootkit lynis aide "
                            "&& sudo systemctl enable --now clamav-freshclam")
                lines.append("")
                lines.append(f"⚠  No malware or rootkit scanner is installed.\n"
                             f"   Install: {hint}")
                return "warn", "\n".join(lines)

            if reasons:
                lines.append("")
                for r in reasons:
                    lines.append(f"⚠  {r}")
                return "warn", "\n".join(lines)

            lines.append("")
            lines.append("All installed scanners are current and scheduled.")
            return "ok", "\n".join(lines)

        # ── Virus Scan (ClamAV) ───────────────────────────────
        elif section == "Virus Scan (ClamAV)":
            scan_path = os.path.realpath(self.scan_path)
            if not os.path.exists(scan_path):
                return "error", f"Scan path does not exist: {scan_path}"
            if not os.access(scan_path, os.R_OK):
                return "error", f"No read permission for: {scan_path}"

            # Prefer the daemon-backed client when clamd is up (see _clamd_up).
            # Arguments differ: --max-filesize/--max-scansize are clamscan-only
            # flags read from clamd.conf by the daemon, so passing them to
            # clamdscan makes it exit with a usage error.
            scanner = shutil.which("clamscan")
            scan_args = ["--recursive", "--stdout", "--no-summary",
                         "--max-filesize=100M", "--max-scansize=500M"]
            tool = "clamscan"
            if not IS_WIN:
                clamdscan = shutil.which("clamdscan")
                if clamdscan and _clamd_up():
                    scanner = clamdscan
                    tool = "clamdscan"
                    # --fdpass dodges permission errors on files the daemon
                    # cannot read; --multiscan uses several scanner threads.
                    # Deliberately NOT --infected: that suppresses the per-file
                    # "OK" lines this loop counts, so the scanned-file total and
                    # the progress ticker would both read zero.
                    scan_args = ["--multiscan", "--fdpass", "--stdout"]
            if IS_WIN and not scanner:
                # Try common Windows install path
                win_path = r"C:\Program Files\ClamAV\clamscan.exe"
                if os.path.exists(win_path):
                    scanner = win_path

            if not scanner:
                if IS_WIN:
                    install_hint = "winget install ClamAV  or  choco install clamav"
                elif IS_MAC:
                    install_hint = "brew install clamav && sudo freshclam"
                else:
                    # See the apt note above: the service is the update path, and
                    # a manual freshclam alongside it cannot take the log lock.
                    install_hint = ("sudo apt install clamav "
                                    "&& sudo systemctl enable --now clamav-freshclam")
                install_hint += "\nOr let rex do it: rex.py --harden clamav"
                return "warn", f"ClamAV not installed.\nInstall: {install_hint}"

            if not self.scan_path_explicit:
                # Readiness only. Status "info" is neutral in the score, which is
                # the honest reading: nothing was scanned, and nothing failed.
                return "info", (
                    f"Engine      : {tool}  ({scanner})\n"
                    f"Target      : none requested (would default to {scan_path})\n"
                    "Deep scan   : not run — a recursive ClamAV walk takes hours on "
                    "a populated tree,\n"
                    "              so it is opt-in rather than part of a routine "
                    "audit.\n"
                    "Run it now  : rex.py --audit --scan-path DIR\n"
                    "Or schedule : rex.py --harden clamav   "
                    "(weekly systemd timer, Sun 03:00)")

            files_scanned = 0
            threats = []
            last_file = ""
            try:
                proc = subprocess.Popen(
                    [scanner] + scan_args + [scan_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    bufsize=1,
                )
                for line in proc.stdout:
                    line = line.strip()
                    if not line:
                        continue
                    if "FOUND" in line:
                        threats.append(line)
                    # every non-empty line is a scanned file path
                    files_scanned += 1
                    last_file = line.split(":")[0]
                    short = last_file[-40:] if len(last_file) > 40 else last_file
                    self._on_progress(
                        f"Scanning {files_scanned} files… {short}", files_scanned
                    )
                proc.wait()
                if threats:
                    summary = f"⚠  {len(threats)} THREAT(S) FOUND\n\n" + "\n".join(threats)
                    return "critical", summary
                return "ok", (f"✓ Clean — {files_scanned} files scanned\n"
                              f"Engine: {tool}\nPath: {scan_path}")
            except Exception as e:  # noqa: BLE001
                return "error", str(e)

        # ── Environment Secrets ───────────────────────────────
        elif section == "Environment Secrets":
            suspicious, clean = [], []
            for k, v in os.environ.items():
                if _is_secret_var(k, v):
                    masked = (v[:4] + "****" + v[-2:]) if len(v) > 6 else "****"
                    suspicious.append(f"⚠  {k} = {masked}")
                else:
                    clean.append(k)
            out_parts = []
            if suspicious:
                out_parts.append(
                    f"=== Potential secrets ({len(suspicious)}) ===\n"
                    + "\n".join(suspicious[:40])
                    + ("\n[truncated…]" if len(suspicious) > 40 else "")
                )
            out_parts.append(
                f"=== Clean variables ({len(clean)}) ===\n"
                + ("None detected." if not clean else f"{len(clean)} variables — no suspicious names or values.")
            )
            return ("warn" if suspicious else "ok"), "\n\n".join(out_parts)

        # ── Sensitive File Permissions ────────────────────────
        elif section == "Sensitive File Permissions":
            if IS_WIN:
                return "ok", "[N/A on Windows] Unix file-mode checks not applicable."
            HOME = os.path.expanduser("~")
            checks = [
                (os.path.join(HOME, ".ssh"),                    0o700, "~/.ssh/"),
                (os.path.join(HOME, ".ssh", "id_rsa"),          0o600, "~/.ssh/id_rsa"),
                (os.path.join(HOME, ".ssh", "id_ed25519"),      0o600, "~/.ssh/id_ed25519"),
                (os.path.join(HOME, ".ssh", "authorized_keys"), 0o600, "~/.ssh/authorized_keys"),
                (os.path.join(HOME, ".ssh", "config"),          0o600, "~/.ssh/config"),
                (os.path.join(HOME, ".gnupg"),                  0o700, "~/.gnupg/"),
                (os.path.join(HOME, ".aws", "credentials"),     0o600, "~/.aws/credentials"),
                (os.path.join(HOME, ".netrc"),                  0o600, "~/.netrc"),
            ]
            # Scan home dir (depth ≤ 2) for .env / credentials files
            for root, dirs, files in os.walk(HOME):
                depth = root[len(HOME):].count(os.sep)
                if depth > 2:
                    dirs[:] = []
                    continue
                for fname in files:
                    if fname in (".env", ".env.local", ".env.production",
                                 "credentials.json", "secrets.json", ".envrc"):
                        checks.append((os.path.join(root, fname), 0o600, fname))
            issues, ok_items = [], []
            for path, required, label in checks:
                if not os.path.exists(path):
                    continue
                try:
                    mode = stat.S_IMODE(os.stat(path).st_mode)
                    if mode & ~required:
                        issues.append(
                            f"⚠  {label}: {oct(mode)} (should be ≤ {oct(required)})"
                        )
                    else:
                        ok_items.append(f"✓  {label}: {oct(mode)}")
                except Exception as e:  # noqa: BLE001
                    issues.append(f"?  {label}: {e}")
            out = ("\n".join(issues) + "\n\n" if issues else "") + "\n".join(ok_items)
            return ("warn" if issues else "ok"), out.strip() or "No sensitive files found"

        return "ok", "Section not implemented"

class AuditWorker(QThread, AuditEngine):
    """Qt front-end for AuditEngine: same code, emits signals as it goes."""

    section_done  = pyqtSignal(str, str, str)
    scan_progress = pyqtSignal(str, int)
    all_done      = pyqtSignal()

    def __init__(self, sections, scan_path=None):
        QThread.__init__(self)
        AuditEngine.__init__(self, sections, scan_path)
        # Bridge the Qt-free progress hook onto the Qt signal.
        self._on_progress = lambda label, count: self.scan_progress.emit(label, count)

    def run(self):
        max_workers = min(8, len(self.sections))
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(self._run_safe, s): s
                       for s in self.sections if not self._stop}
            for future in as_completed(futures):
                if self._stop:
                    break
                section = futures[future]
                try:
                    status, output = future.result()
                except Exception as e:  # noqa: BLE001
                    status, output = "error", str(e)
                self.section_done.emit(section, status, output)
        self.all_done.emit()




# ============================================================
# OLLAMA REMEDIATION
# ============================================================
REMEDIATION_PROMPT = """You are a {os} security hardening expert. A security audit found this issue:

Section: {section}
Finding:
{finding}

Output ONLY the exact shell commands needed to fix this specific finding. Follow these rules strictly:
- Raw commands only — no explanation, no markdown, no code fences, no backticks, no bullets, no numbers
- One command per line
- Commands must be real, standard {os} commands that exist on this system
- Do NOT invent commands — only use well-known tools (chmod, chown, systemctl, ufw, sysctl, sed, etc.)
- Do NOT include ssh-agent, xauth, dbus, session management or unrelated daemon commands
- If the fix requires editing a config file, use sed or echo with a redirect
- If nothing can be fixed with a shell command, output exactly: NO_FIX_AVAILABLE
- Do NOT output anything else"""



# ============================================================
# AI PROVIDER CORE  (Qt-free)
# ============================================================
# Everything below runs with no PyQt6 and no display. The GUI dialogs and the
# CLI both call these, so a fix generated via `--fix` is produced by the exact
# same prompt and parsing as a fix generated by the AI Fix button. Two
# implementations would drift; there is one.
#
# Defaults mirror the RemediationDialog signature defaults. A test asserts
# they stay in sync.

OLLAMA_URL   = "http://localhost:11434"
OLLAMA_MODEL = "llama3.2"
CLAUDE_URL   = "https://api.anthropic.com/v1/messages"
CLAUDE_MODEL = "claude-haiku-4-5-20251001"


def build_prompt(section: str, finding: str) -> str:
    """The exact remediation prompt. `--print-prompt` hands this to a model
    that would rather do the reasoning itself than have rex call an API."""
    return REMEDIATION_PROMPT.format(os=_OS, section=section, finding=finding)


# ── Ollama ───────────────────────────────────────────────────
def ollama_model_exists(model: str, base_url: str = OLLAMA_URL) -> bool:
    try:
        url = base_url.rstrip("/") + "/api/tags"
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.loads(resp.read())
        names = [m.get("name", "").split(":")[0] for m in data.get("models", [])]
        return model.split(":")[0] in names
    except Exception:  # noqa: BLE001
        return False


def ollama_pull_model(model: str, base_url: str = OLLAMA_URL, on_status=None):
    """Pull `model` if absent. Returns (ok, message)."""
    status = on_status or (lambda m: None)
    status(f"Pulling model '{model}'… (first run only)")
    url     = base_url.rstrip("/") + "/api/pull"
    payload = json.dumps({"name": model, "stream": False}).encode()
    req = urllib.request.Request(
        url, data=payload, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            data = json.loads(resp.read())
        if data.get("status") == "success":
            return True, ""
        return False, f"[Pull returned unexpected status: {data.get('status')}]"
    except Exception as e:  # noqa: BLE001
        return False, f"[Pull failed: {e}]"


def _sse_lines(resp):
    """Yield the payload of each `data: ` line from an SSE stream."""
    for raw_line in resp:
        line = raw_line.decode("utf-8", errors="replace").strip()
        if not line or not line.startswith("data: "):
            continue
        data = line[6:]
        if data == "[DONE]":
            return
        yield data


def provider_stream(provider: str, prompt: str, cfg: dict,
                    on_token=None, on_status=None):
    """Stream a remediation suggestion.

    Returns (text, error). error is None on success — so a caller gets a
    machine-checkable failure instead of having to sniff for "[...]" in prose.
    The GUI renders `error or text`, which preserves its previous output
    byte-for-byte.
    """
    emit   = on_token  or (lambda t: None)
    status = on_status or (lambda m: None)

    if provider == "ollama":
        model = cfg.get("ollama_model") or OLLAMA_MODEL
        base  = cfg.get("ollama_url") or OLLAMA_URL
        if not ollama_model_exists(model, base):
            ok, msg = ollama_pull_model(model, base, status)
            if not ok:
                return "", msg
        status(f"Querying {model}…")
        url     = base.rstrip("/") + "/api/generate"
        payload = json.dumps({
            "model":  model,
            "prompt": prompt,
            "stream": True,
        }).encode()
        req = urllib.request.Request(
            url, data=payload, headers={"Content-Type": "application/json"}
        )
        try:
            full = []
            with urllib.request.urlopen(req, timeout=120) as resp:
                for raw_line in resp:
                    line = raw_line.strip()
                    if not line:
                        continue
                    try:
                        chunk = json.loads(line)
                    except Exception:  # noqa: BLE001, S112
                        continue
                    token = chunk.get("response", "")
                    if token:
                        full.append(token)
                        emit(token)
                    if chunk.get("done"):
                        break
            return "".join(full).strip(), None
        except urllib.error.URLError as e:
            return "", f"[Ollama unreachable: {e.reason}]"
        except Exception as e:  # noqa: BLE001
            return "", f"[Error: {e}]"

    if provider == "claude":
        model = cfg.get("claude_model") or CLAUDE_MODEL
        key   = cfg.get("claude_api_key") or ""
        if not key:
            return "", "[Claude API error: no API key configured]"
        status(f"Querying {model}…")
        payload = json.dumps({
            "model":      model,
            "max_tokens": 1024,
            "stream":     True,
            "messages":   [{"role": "user", "content": prompt}],
        }).encode()
        req = urllib.request.Request(CLAUDE_URL, data=payload, headers={
            "Content-Type":      "application/json",
            "x-api-key":         key,
            "anthropic-version": "2023-06-01",
        })
        try:
            full = []
            with urllib.request.urlopen(req, timeout=120) as resp:
                for data in _sse_lines(resp):
                    try:
                        chunk = json.loads(data)
                    except Exception:  # noqa: BLE001, S112
                        continue
                    if chunk.get("type") == "content_block_delta":
                        token = chunk.get("delta", {}).get("text", "")
                        if token:
                            full.append(token)
                            emit(token)
                    elif chunk.get("type") == "message_stop":
                        break
            return "".join(full).strip(), None
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            return "", f"[Claude API error {e.code}: {body[:300]}]"
        except urllib.error.URLError as e:
            return "", f"[Claude unreachable: {e.reason}]"
        except Exception as e:  # noqa: BLE001
            return "", f"[Error: {e}]"

    if provider == "deepseek":
        model = cfg.get("deepseek_model") or DEEPSEEK_MODEL
        key   = cfg.get("deepseek_api_key") or ""
        base  = cfg.get("deepseek_url") or DEEPSEEK_URL
        if not key:
            return "", "[DeepSeek API error 401: no API key configured]"
        status(f"Querying {model}…")
        url = base.rstrip("/") + "/chat/completions"
        payload = json.dumps({
            "model":       model,
            "max_tokens":  AI_MAX_TOKENS,
            "stream":      True,
            "messages": [
                {"role": "system",
                 "content": "You output only raw shell commands. Never explain, "
                            "never use markdown or code fences."},
                {"role": "user", "content": prompt},
            ],
        }).encode()
        req = urllib.request.Request(url, data=payload, headers={
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {key}",
            "Accept":        "text/event-stream",
        })
        try:
            full = []
            with urllib.request.urlopen(req, timeout=180) as resp:
                for data in _sse_lines(resp):
                    try:
                        chunk = json.loads(data)
                    except Exception:  # noqa: BLE001, S112
                        continue
                    choices = chunk.get("choices") or []
                    if not choices:
                        continue
                    delta = choices[0].get("delta") or {}
                    # reasoning_content is the hidden chain-of-thought — the
                    # caller wants the commands, not the working-out.
                    token = delta.get("content") or ""
                    if token:
                        full.append(token)
                        emit(token)
                    if choices[0].get("finish_reason"):
                        break
            text = "".join(full).strip()
            if not text:
                return "", ("[DeepSeek returned no content — the model may have "
                            "spent the entire token budget on reasoning. "
                            "Try deepseek-v4-pro.]")
            return text, None
        except urllib.error.HTTPError as e:
            if e.code == 401:
                return "", "[DeepSeek API error 401: invalid API key]"
            if e.code == 402:
                return "", "[DeepSeek API error 402: insufficient balance]"
            body = e.read().decode("utf-8", errors="replace")
            return "", f"[DeepSeek API error {e.code}: {body[:300]}]"
        except urllib.error.URLError as e:
            return "", f"[DeepSeek unreachable: {e.reason}]"
        except Exception as e:  # noqa: BLE001
            return "", f"[Error: {e}]"

    return "", f"[Unknown provider: {provider}]"


def load_provider_config(provider: str | None = None, **overrides) -> dict:
    """Config file, then environment, then explicit overrides.

    Same store the GUI writes, so a key entered in the Settings panel is
    visible to the CLI and vice versa.
    """
    cfg = _load_config()
    out = {
        "ollama_url":        cfg.get("ollama_url")        or OLLAMA_URL,
        "ollama_model":      cfg.get("ollama_model")      or OLLAMA_MODEL,
        "claude_model":      cfg.get("claude_model")      or CLAUDE_MODEL,
        "deepseek_model":    cfg.get("deepseek_model")    or DEEPSEEK_MODEL,
        "deepseek_url":      cfg.get("deepseek_url")      or DEEPSEEK_URL,
        "claude_api_key":    cfg.get("claude_api_key")    or os.environ.get("ANTHROPIC_API_KEY", ""),
        "deepseek_api_key":  cfg.get("deepseek_api_key")  or os.environ.get("DEEPSEEK_API_KEY", ""),
    }
    if provider:
        out["provider"] = provider
    for k, v in overrides.items():
        if v:
            out[k] = v
    return out


# ============================================================
# COMMAND SAFETY  (Qt-free — shared by the dialog and --apply)
# ============================================================
# Patterns that indicate a command is too dangerous to auto-run.
# Each entry is (regex_pattern, human_reason).
DANGER_PATTERNS = [
    (r"sudoers",                  "modifies sudoers — use visudo"),
    (r"/etc/shadow",              "modifies shadow password file"),
    (r"/etc/passwd",              "modifies passwd file"),
    (r"rm\s+-[a-z]*r[a-z]*f?\s+/(?!\S)",  "rm -rf on root"),
    (r"rm\s+-[a-z]*f?[a-z]*r\s+/(?!\S)",  "rm -rf on root"),
    (r">\s*/dev/sd[a-z]",         "overwrites block device"),
    (r"dd\s+.*of=/dev/",          "dd to block device"),
    (r"mkfs",                     "formats a filesystem"),
    (r":\s*\(\)\s*\{",            "fork bomb"),
    (r"chmod\s+[0-9]*[0-7][0-7][0-7]\s+/etc/(?:passwd|shadow|sudoers|ssh)", "unsafe chmod on critical file"),
    (r">\s*/etc/(?:passwd|shadow|sudoers|crontab|hosts)(?:\s|$)", "overwrites critical config"),
    # Any download piped straight into a shell — not just the "-O -" spelling.
    # `wget -qO- url | bash` is the same attack as `curl url | sh`.
    (r"(?:wget|curl)\b[^|]*\|\s*(?:ba|z|da|k)?sh\b", "remote code execution via pipe"),
    (r"base64\s+.*\|\s*(?:ba)?sh\b", "obfuscated remote execution"),
    (r"!!!", "invalid sudoers syntax"),
]

# Too dangerous to auto-execute even with sudo — always leave to a human.
BLOCKED_PATHS = (
    "/etc/sudoers",
    "/etc/sudoers.d/",
    "/etc/shadow",
    "/etc/passwd",
    "/etc/ssh/sshd_config",
    "/etc/crontab",
    "/etc/cron.d/",
    "/etc/hosts",
)

# Need root but safe to auto-sudo (`sudo -n`, so it never hangs on a prompt).
SUDO_PATHS = (
    "/etc/",
    "/usr/",
    "/var/",
    "/sys/",
    "/boot/",
    "/lib/",
    "/lib64/",
    "/sbin/",
    "/bin/",
)


def danger_reason(cmd: str) -> str:
    """Return a human-readable reason if cmd is dangerous, else empty string."""
    if not cmd or cmd.startswith("#"):
        return ""
    for pattern, reason in DANGER_PATTERNS:
        if re.search(pattern, cmd, re.IGNORECASE):
            return reason
    return ""


def clean_commands(raw: str) -> list:
    """Strip LLM formatting noise and return executable command lines."""
    cmds = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        # skip parenthetical notes and explanations
        if line.startswith(("(", "#")):
            continue
        # strip leading "1." "2." "- " bullet formatting
        line = re.sub(r"^\d+\.\s*", "", line)
        line = re.sub(r"^[-*]\s*", "", line)
        # strip surrounding backticks
        line = line.strip("`").strip()
        if not line or line == "NO_FIX_AVAILABLE":
            continue

        # Fix unquoted echo content that contains shell metacharacters.
        # Example: echo neo ALL=(ALL) NOPASSWD: ... >> /etc/sudoers
        #   → echo 'neo ALL=(ALL) NOPASSWD: ...' >> /etc/sudoers
        # /bin/sh (dash) treats bare (...) in argument position as a
        # compound command — wrapping in single quotes prevents this.
        echo_m = re.match(r'^(echo\s+)(.*?)(\s*>>?\s*\S+.*)$', line, re.DOTALL)
        if echo_m:
            prefix, content, redirect = echo_m.groups()
            already_quoted = (
                (content.startswith("'") and content.endswith("'")) or
                (content.startswith('"') and content.endswith('"'))
            )
            if not already_quoted and re.search(r"[()!$`\\]", content):
                # Escape any single quotes inside content, then wrap
                content = "'" + content.replace("'", "'\\''") + "'"
                line = prefix + content + redirect

        cmds.append(line)
    return cmds


def classify_commands(cmds) -> dict:
    """Split commands into executable / blocked-before-sudo / needs-sudo.

    This is the decision a model needs to make before applying anything, so it
    is exposed as data rather than only as coloured text in a dialog.
    """
    executable, blocked, need_sudo = [], [], []
    for cmd in cmds:
        reason = danger_reason(cmd)
        hit = reason or next((f"sensitive path {p}" for p in BLOCKED_PATHS if p in cmd), "")
        if hit:
            blocked.append({"command": cmd, "reason": hit})
            continue
        entry = {"command": cmd}
        if not cmd.startswith("sudo ") and any(p in cmd for p in SUDO_PATHS):
            entry["run_as"] = "sudo -n " + cmd
            need_sudo.append(cmd)
        executable.append(entry)
    return {"executable": executable, "blocked": blocked, "needs_sudo": need_sudo}


def apply_commands(cmds, on_progress=None, timeout=30,
                   blocked_paths=None, sudo_paths=None) -> tuple:
    """Execute commands with the same guard the GUI applies. Returns
    (all_ok, results) where results is a list of per-command dicts."""
    blocked_paths = BLOCKED_PATHS if blocked_paths is None else blocked_paths
    sudo_paths    = SUDO_PATHS    if sudo_paths    is None else sudo_paths
    progress = on_progress or (lambda line: None)
    results  = []
    all_ok   = True
    for cmd in cmds:
        # Hard safety net — catches anything that slipped past the validator
        reason = danger_reason(cmd)
        if reason or any(p in cmd for p in blocked_paths):
            all_ok = False
            results.append({
                "command": cmd, "executed": False, "ok": False,
                "blocked": reason or "sensitive path", "output": "",
            })
            continue

        run_cmd = cmd
        if not cmd.startswith("sudo ") and any(p in cmd for p in sudo_paths):
            run_cmd = "sudo -n " + cmd  # -n: fail immediately if password needed

        progress(f"$ {cmd}")
        try:
            r = subprocess.run(
                run_cmd, shell=True, check=False,
                capture_output=True, text=True, timeout=timeout,
            )
            out = (r.stdout + r.stderr).strip() or "(no output)"
            ok  = r.returncode == 0
            if not ok:
                all_ok = False
            entry = {
                "command": cmd, "executed": True, "ok": ok,
                "exit_code": r.returncode, "output": out,
                "ran_as": "sudo -n" if run_cmd != cmd else "shell",
            }
            if not ok and ("password is required" in out or "a password is required" in out):
                # Suggest something a human can actually paste. The command may
                # already carry its own `sudo -n`, and blindly prefixing another
                # `sudo` produced the nonsense `sudo sudo -n tee …`; drop the
                # `-n` too, since the whole point is that a prompt is allowed.
                manual = cmd
                if manual.startswith("sudo -n "):
                    manual = manual[len("sudo -n "):]
                elif manual.startswith("sudo "):
                    manual = manual[len("sudo "):]
                entry["needs_manual_sudo"] = f"sudo {manual}"
            results.append(entry)
        except Exception as e:  # noqa: BLE001
            all_ok = False
            results.append({
                "command": cmd, "executed": True, "ok": False,
                "error": str(e), "output": "",
            })
    return all_ok, results


# ============================================================
# HARDENING — deterministic remediation for fail2ban / ClamAV
# ============================================================
# The audit sections above can only *report* that fail2ban is absent, or that
# ClamAV has no signature refresh and no scan schedule. Handing that text to an
# LLM yields a plausible `apt install` line and little else — no jail policy,
# no recurring scan, no idempotence, and a different answer every run. These
# planners are the offline, reviewed alternative: a fixed command plan per
# target that goes through the same apply_commands() guard as AI-suggested
# fixes, or exports as a shell script for a human to run under a real sudo.
#
# Two sudo spellings matter. The apply form uses `sudo -n` so an unattended run
# fails fast instead of blocking forever on a password prompt (the host we
# tested on needs one). The exported script uses plain `sudo` because a human
# is sitting in front of it.

HARDEN_TARGETS = ("fail2ban", "clamav")

HARDEN_ALIASES = {
    "fail2ban": "fail2ban", "f2b": "fail2ban", "intrusion": "fail2ban",
    "clamav": "clamav", "clam": "clamav", "antivirus": "clamav", "av": "clamav",
}

# Written to /etc/fail2ban/jail.local — deliberately not jail.conf, so package
# upgrades never clobber the policy. `bantime.increment` is the part a default
# install lacks: repeat offenders get exponentially longer bans instead of
# starting from scratch every findtime window.
FAIL2BAN_JAIL_TEMPLATE = """\
# Managed by rex (ÆGIS) {version} — generated hardening baseline.
# Local overrides live here so upgrades to jail.conf never clobber them.
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
# Escalating bans: a host banned N times is banned for factor^N, capped at 1w.
bantime.increment = true
bantime.factor    = 2
bantime.maxtime   = 1w
banaction = {banaction}
backend   = systemd
ignoreip  = 127.0.0.1/8 ::1

[sshd]
enabled  = true
mode     = aggressive
maxretry = 3
"""

CLAMAV_SCAN_SERVICE = """\
[Unit]
Description=rex (ÆGIS) weekly malware scan
Documentation=man:clamdscan(1) man:clamscan(1)
After=clamav-daemon.service
Wants=clamav-daemon.service

[Service]
Type=oneshot
Nice=10
IOSchedulingClass=idle
# clamdscan talks to the daemon (with the signature DB already resident) and is
# far faster than clamscan, which reloads the database on every invocation.
ExecStart=/bin/sh -c 'if command -v clamdscan >/dev/null 2>&1; then clamdscan --multiscan --fdpass --infected {target}; else clamscan -r -i {target}; fi'
"""

CLAMAV_SCAN_TIMER = """\
[Unit]
Description=rex (ÆGIS) weekly malware scan schedule

[Timer]
OnCalendar=Sun 03:00
Persistent=true
RandomizedDelaySec=30m

[Install]
WantedBy=timers.target
"""


def _install_cmd(packages, sudo_prefix):
    """Non-interactive package install for this platform, or None."""
    if IS_WIN:
        return None
    if IS_MAC:
        # Homebrew refuses to run as root, so no sudo prefix here.
        return f"brew install {' '.join(packages)}"
    pkgs = " ".join(packages)
    if shutil.which("apt-get"):
        return (f"{sudo_prefix} env DEBIAN_FRONTEND=noninteractive "
                f"apt-get install -y {pkgs}")
    if shutil.which("dnf"):
        return f"{sudo_prefix} dnf install -y {pkgs}"
    if shutil.which("pacman"):
        return f"{sudo_prefix} pacman -S --noconfirm {pkgs}"
    if shutil.which("zypper"):
        return f"{sudo_prefix} zypper --non-interactive install {pkgs}"
    return None


def _step(command, summary, why="", mutating=True):
    return {"command": command, "summary": summary, "why": why,
            "mutating": mutating,
            "blocked": danger_reason(command) or ""}


def _write_file_step(path, content, sudo_prefix, summary, why=""):
    """A heredoc write. Quoted delimiter keeps the shell from expanding the
    config, which matters for jail.local's `%`-free but brace-heavy content."""
    cmd = (f"{sudo_prefix} tee {path} > /dev/null <<'REX_EOF'\n"
           f"{content}REX_EOF")
    return _step(cmd, summary, why)


def _harden_fail2ban(sudo_prefix="sudo -n") -> dict:
    """Install fail2ban and give it an SSH policy that actually bans."""
    if IS_WIN:
        return {"target": "fail2ban", "supported": False, "steps": [], "notes": [
            ("fail2ban is Unix-only. Windows equivalent: Defender Firewall plus an "
             "account lockout policy (secpol.msc → Account Lockout Policy).")]}

    # banaction picks the firewall fail2ban drives. ufw and nftables both ship
    # on modern Ubuntu; bare iptables is the last resort.
    if shutil.which("ufw"):
        banaction = "ufw"
    elif shutil.which("nft"):
        banaction = "nftables-multiport"
    else:
        banaction = "iptables-multiport"

    notes = [f"banaction = {banaction} (chosen from the firewalls present on PATH)"]
    steps, packages = [], ["fail2ban"]

    if shutil.which("apt-get") and shutil.which("systemctl"):
        # backend = systemd (set in the jail policy) reads the journal through
        # these bindings; without them fail2ban falls back with a warning.
        packages.append("python3-systemd")

    install = _install_cmd(packages, sudo_prefix)
    if install is None:
        return {"target": "fail2ban", "supported": False, "steps": [], "notes": [
            ("no supported package manager found — install fail2ban manually, then "
             "re-run `rex.py --harden fail2ban` to get the jail policy.")]}

    steps.append(_step(install, "Install fail2ban",
                       "the package ships the daemon and its default jails"))
    steps.append(_write_file_step(
        "/etc/fail2ban/jail.local",
        FAIL2BAN_JAIL_TEMPLATE.format(banaction=banaction, version=VERSION),
        sudo_prefix,
        "Write the SSH jail policy",
        "1h ban after 3 failed SSH logins in 10m, escalating for repeat offenders; "
        "localhost is never banned"))
    steps.append(_step(f"{sudo_prefix} systemctl enable --now fail2ban",
                       "Start fail2ban now and at every boot",
                       "an installed-but-inactive fail2ban blocks nothing — the "
                       "audit section reports exactly that as a warning"))
    steps.append(_step(f"{sudo_prefix} fail2ban-client status sshd",
                       "Verify the sshd jail is active", "", mutating=False))
    notes.append("After applying, re-run `rex.py --audit --sections "
                 "intrusion-prevention-fail2ban` to confirm the jail reports active.")
    return {"target": "fail2ban", "supported": True, "steps": steps,
            "notes": notes, "banaction": banaction}


def _harden_clamav(sudo_prefix="sudo -n", target: str = "/home") -> dict:
    """Install ClamAV, refresh signatures, and schedule a recurring scan."""
    if IS_WIN:
        return {"target": "clamav", "supported": False, "steps": [], "notes": [
            ("On Windows, prefer Defender (already resident) over ClamAV. If you "
             "want ClamAV anyway: winget install ClamAV, then run freshclam.")]}

    packages = ["clamav"]
    # clamav-daemon provides clamd, which clamdscan needs. Only Debian/Ubuntu
    # split it out; on other distros the single package covers it.
    if shutil.which("apt-get"):
        packages.append("clamav-daemon")

    install = _install_cmd(packages, sudo_prefix)
    if install is None:
        return {"target": "clamav", "supported": False, "steps": [], "notes": [
            ("no supported package manager found — install ClamAV manually "
             "(see the installer hint in the audit section).")]}

    if IS_MAC:
        updater = "freshclam"
    else:
        updater = f"{sudo_prefix} freshclam"

    steps = [
        _step(install, "Install ClamAV" + (" + clamd" if len(packages) > 1 else ""),
              "clamdscan (daemon-backed) is far faster than clamscan for repeat scans"),
        # freshclam refuses to update while the freshclam service holds the
        # lock, so stop it first. Non-fatal if the unit does not exist yet.
        _step(f"{sudo_prefix} systemctl stop clamav-freshclam",
              "Pause the signature-refresh service",
              "freshclam cannot take the database lock while the service holds it"),
        _step(updater, "Download the signature database",
              "a fresh install ships stale or empty definitions"),
        _write_file_step("/etc/systemd/system/rex-clamav-scan.service",
                         CLAMAV_SCAN_SERVICE.format(target=target),
                         sudo_prefix, "Define the weekly scan unit",
                         "a one-off scan finds threats once; a timer finds them weekly"),
        _write_file_step("/etc/systemd/system/rex-clamav-scan.timer",
                         CLAMAV_SCAN_TIMER, sudo_prefix,
                         "Schedule the weekly scan",
                         "Sunday 03:00 with a 30m jitter, catching up if the host "
                         "was asleep (Persistent=true)"),
        _step(f"{sudo_prefix} systemctl daemon-reload",
              "Reload systemd", "the two new unit files are not visible until this runs"),
        _step(f"{sudo_prefix} systemctl enable --now clamav-freshclam",
              "Enable daily signature updates", "stale definitions miss recent malware"),
        _step(f"{sudo_prefix} systemctl enable --now rex-clamav-scan.timer",
              "Enable the weekly scan timer",
              "enabling the timer (not the service) is what creates the schedule"),
    ]
    return {"target": "clamav", "supported": True, "steps": steps,
            "notes": [f"Scan target: {target}",
                      "Inspect results with: journalctl -u rex-clamav-scan"]}


HARDEN_BUILDERS = {
    "fail2ban": _harden_fail2ban,
    "clamav":   _harden_clamav,
}


def resolve_harden_targets(spec: str) -> tuple:
    """'all', 'clam', 'fail2ban,clamav' → (resolved, unknown)."""
    if not spec or not spec.strip():
        return [], []
    if spec.strip().lower() in ("all", "*"):
        return list(HARDEN_TARGETS), []
    resolved, unknown = [], []
    for raw in spec.split(","):
        name = raw.strip().lower()
        if not name:
            continue
        target = HARDEN_ALIASES.get(name)
        if target is None:
            unknown.append(raw.strip())
        elif target not in resolved:
            resolved.append(target)
    return resolved, unknown


def build_harden_plan(spec: str, sudo_prefix="sudo -n", scan_target="/home") -> dict:
    """Deterministic plan for the requested targets — never touches the host."""
    resolved, unknown = resolve_harden_targets(spec)
    plans = []
    for target in resolved:
        builder = HARDEN_BUILDERS[target]
        if target == "clamav":
            plans.append(builder(sudo_prefix=sudo_prefix, target=scan_target))
        else:
            plans.append(builder(sudo_prefix=sudo_prefix))
    return {"schema": SCHEMA_HARDEN, "tool": APP_NAME, "version": VERSION,
            "platform": _OS, "requested": spec, "targets": plans,
            "unknown_targets": unknown,
            "steps": [s for p in plans for s in p["steps"]]}


def harden_script(plan: dict) -> str:
    """Render a plan as a reviewable, human-runnable shell script.

    Step generation is parametrised on the sudo prefix, so the script is built
    from a fresh plan with plain `sudo` rather than by string-rewriting `-n`
    out of the apply form.
    """
    lines = ["#!/bin/sh",
             "# Generated by rex (ÆGIS) — review before running.",
             "# Regenerate with: rex.py --harden-script",
             "set -u",
             ""]
    for t in plan["targets"]:
        if not t["supported"]:
            lines.append(f"# {t['target']}: unsupported on this platform")
            for note in t["notes"]:
                lines.append(f"#   {note}")
            lines.append("")
            continue
        lines.append(f"# ---- {t['target']} ----")
        for note in t["notes"]:
            lines.append(f"# {note}")
        lines.append("")
        for step in t["steps"]:
            if step["why"]:
                lines.append(f"# {step['summary']}: {step['why']}")
            lines.append(step["command"])
            lines.append("")
    return "\n".join(lines)


# ============================================================
# MACHINE CONTRACT
# ============================================================
# Stable identifiers so an agent can assert on them across rex versions.
SCHEMA_AUDIT        = "aegis.rex.audit/1"
SCHEMA_FIX          = "aegis.rex.fix/1"
SCHEMA_CAPABILITIES = "aegis.rex.capabilities/1"
SCHEMA_HARDEN       = "aegis.rex.harden/1"

EXIT_CLEAN    = 0   # audit ran, nothing at or above the --fail-on threshold
EXIT_FINDINGS = 1   # audit ran, findings at or above the threshold
EXIT_USAGE    = 2   # bad arguments / bad input file
EXIT_PROVIDER = 3   # AI provider unreachable, unauthorized, or out of budget
EXIT_APPLY    = 4   # --apply ran and at least one command failed

SEVERITY_BY_STATUS = {
    "critical": "critical",
    "error":    "high",
    "warn":     "medium",
    "ok":       "none",
    "info":     "none",
}

# Matches SecurityAuditWindow's export: these hold credentials and account data.
REDACTED_SECTIONS = ("Sudo / Privileges", "SSH Config", "Users & Groups")

# The one placeholder the report/export uses in place of a sensitive section's
# output, so an agent can detect redaction by string comparison.
REDACTED_SENSITIVE = "[REDACTED — sensitive data omitted from report]"

# The GUI enables AI Fix for exactly these (see btn_ai_fix.setEnabled).
FIXABLE_STATUSES = ("warn", "critical", "error")


def section_id(section: str) -> str:
    """Stable slug for a section name: 'SSH Config' -> 'ssh-config'."""
    return re.sub(r"[^a-z0-9]+", "-", section.lower()).strip("-")


def audit_score(results: dict) -> dict:
    """Same formula the GUI's summary panel uses, so the CLI and the window
    never disagree about whether a host passed."""
    warnings = [(s, st) for s, (st, _out) in results.items()
                if st in FIXABLE_STATUSES]
    warn_count = sum(1 for _, st in warnings if st == "warn")
    crit_count = sum(1 for _, st in warnings if st in ("critical", "error"))
    score = max(0, 100 - warn_count * 5 - crit_count * 15)
    grade = "GOOD" if score >= 80 else "FAIR" if score >= 50 else "POOR"
    return {"score": score, "grade": grade,
            "warnings": warn_count, "critical": crit_count}


def build_report(results: dict, scan_path: str | None = None, include_output: bool = True,
                 redact: bool = True) -> dict:
    """Turn {section: (status, output)} into the stable audit document."""
    findings = []
    for idx, section in enumerate(SECTIONS):
        if section not in results:
            continue
        status, output = results[section]
        output = output or ""
        is_redacted = redact and section in REDACTED_SECTIONS
        findings.append({
            "id":         section_id(section),
            "section":    section,
            "index":      idx,
            "status":     status,
            "severity":   SEVERITY_BY_STATUS.get(status, "unknown"),
            "fixable":    status in FIXABLE_STATUSES,
            "redacted":   is_redacted,
            # "[N/A on Windows] ..." means the check does not apply here, which
            # is different from passing — models must not read it as a pass.
            "applicable": not output.startswith("[N/A on"),
            "line_count": len(output.splitlines()),
            "output":     (REDACTED_SENSITIVE
                           if is_redacted else (output if include_output else None)),
        })

    score = audit_score(results)
    return {
        "schema":          SCHEMA_AUDIT,
        "tool":            APP_NAME,
        "version":         VERSION,
        "platform":        _OS,
        "platform_detail": platform.platform(),
        "timestamp":       datetime.datetime.now().isoformat(),  # noqa: DTZ005
        "hostname":        socket.gethostname(),
        "scan_path":       scan_path,
        "summary": {
            "sections_expected": len(SECTIONS),
            "sections_run":      len(results),
            "clean":             sum(1 for f in findings if f["status"] == "ok"),
            "fixable":           sum(1 for f in findings if f["fixable"]),
            "not_applicable":    sum(1 for f in findings if not f["applicable"]),
            "unassessed":        sum(1 for f in findings if f["status"] == "error"),
            **score,
        },
        "redacted_sections": list(REDACTED_SECTIONS) if redact else [],
        # Ids whose status is "error": the check did not complete, so their
        # absence from the clean count is not a pass. Cause is usually a
        # missing module (pip install psutil) or an unreadable file.
        "unassessed":        [f["id"] for f in findings if f["status"] == "error"],
        "findings":          findings,
    }


def capabilities() -> dict:
    """Self-description. This is the contract an agent reads first: it can
    discover every command, schema, exit code and provider without scraping
    --help prose or reading this file's source."""
    return {
        "schema":  SCHEMA_CAPABILITIES,
        "tool":    APP_NAME,
        "version": VERSION,
        "entrypoint": "python3 rex.py",
        "headless": True,
        "gui_available": HAS_QT,
        "requires": {
            "python":  ">=3.10",
            "modules": {"psutil": f"optional - without it {len(PSUTIL_GATED_SECTIONS)} "
                                  f"of {len(SECTIONS)} sections report status error",
                        "PyQt6": "GUI only - not needed for --audit"},
            "display": "not required for any -- command",
        },
        "commands": [
            {"flag": "--capabilities", "summary": "Print this document as JSON and exit.",
             "args": [], "exit_codes": [EXIT_CLEAN]},
            {"flag": "--list-checks", "summary": "List audit sections and their stable ids.",
             "args": ["--json"], "exit_codes": [EXIT_CLEAN]},
            {"flag": "--audit", "summary": "Run the audit and emit a report.",
             "args": ["--json", "--sections ID,ID", "--scan-path DIR", "--output FILE",
                      "--fail-on none|warn|critical", "--sequential"],
             "emits": SCHEMA_AUDIT,
             "exit_codes": [EXIT_CLEAN, EXIT_FINDINGS, EXIT_USAGE]},
            {"flag": "--fix", "summary": "Ask a provider for the fix to one finding. "
                                         "Never applies anything without --apply.",
             "args": ["SECTION_OR_ID", "--provider", "--model", "--report FILE",
                      "--print-prompt", "--apply", "--yes", "--json"],
             "emits": SCHEMA_FIX,
             "exit_codes": [EXIT_CLEAN, EXIT_FINDINGS, EXIT_USAGE, EXIT_PROVIDER, EXIT_APPLY]},
        ],
        "schemas": {"audit": SCHEMA_AUDIT, "fix": SCHEMA_FIX,
                    "capabilities": SCHEMA_CAPABILITIES},
        "exit_codes": {
            str(EXIT_CLEAN):    "success — audit ran (or nothing met an explicit --fail-on threshold)",
            str(EXIT_FINDINGS): "audit ran and findings met the explicit --fail-on threshold",
            str(EXIT_USAGE):    "bad arguments or unreadable input",
            str(EXIT_PROVIDER): "provider unreachable/unauthorized/out of budget",
            str(EXIT_APPLY):    "a fix was applied and at least one command failed",
        },
        "default_fail_on": "none",
        "status_vocabulary": {
            "ok":       "check passed",
            "warn":     "issue worth fixing",
            "critical": "active threat (ClamAV found malware)",
            "error":    "check could not complete — absence of evidence, not a pass",
            "info":     "informational",
        },
        "severity_map": SEVERITY_BY_STATUS,
        "fixable_statuses": list(FIXABLE_STATUSES),
        "checks": [{"id": section_id(s), "section": s, "index": i}
                   for i, s in enumerate(SECTIONS)],
        "providers": {
            "ollama":   {"requires": ["ollama serve"],
                         "config_keys": ["ollama_url", "ollama_model"],
                         "env": [], "default_model": OLLAMA_MODEL,
                         "auto_pulls_model": True},
            "claude":   {"requires": ["api key"],
                         "config_keys": ["claude_api_key", "claude_model"],
                         "env": ["ANTHROPIC_API_KEY"], "default_model": CLAUDE_MODEL},
            "deepseek": {"requires": ["api key"],
                         "config_keys": ["deepseek_api_key", "deepseek_model", "deepseek_url"],
                         "env": ["DEEPSEEK_API_KEY"], "default_model": DEEPSEEK_MODEL,
                         "note": "reasoning models bill hidden chain-of-thought against "
                                 f"max_tokens ({AI_MAX_TOKENS}); an empty reply means the "
                                 "budget went on reasoning."},
        },
        "config_file": CONFIG_PATH,
        "safety": {
            "applies_by_default": False,
            "apply_requires": "--apply --yes",
            "blocked_paths": list(BLOCKED_PATHS),
            "danger_patterns": [{"pattern": p, "reason": r} for p, r in DANGER_PATTERNS],
            "sensitive_sections_redacted_in_reports": list(REDACTED_SECTIONS),
        },
        "examples": [
            "rex.py --capabilities",
            "rex.py --audit --json",
            "rex.py --audit --json --sections ssh-config,firewall --fail-on critical",
            "rex.py --audit --json --output /tmp/report.json",
            "rex.py --fix ssh-config --provider deepseek --json",
            "rex.py --fix 'SSH Config' --provider deepseek --print-prompt --json",
            "rex.py --fix ssh-config --report /tmp/report.json --provider deepseek --json",
        ],
    }


# ============================================================
# CLI
# ============================================================
def _resolve_section(name: str):
    """Accept a stable id ('ssh-config') or an exact/partial section name."""
    if not name:
        return None
    slug = section_id(name)
    for s in SECTIONS:
        if section_id(s) == slug:
            return s
    lowered = name.strip().lower()
    matches = [s for s in SECTIONS if lowered in s.lower()]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise ValueError(f"ambiguous section {name!r} matches: {matches}")
    return None


def _build_argparser():
    import argparse
    p = argparse.ArgumentParser(
        prog="rex.py",
        description=f"{APP_NAME} v{VERSION} — security audit + AI remediation.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run with no arguments for the GUI.\n"
               "Machine contract: rex.py --capabilities",
    )
    p.add_argument("--gui", action="store_true", help="force the GUI")
    p.add_argument("--version", action="version", version=f"{APP_NAME} {VERSION}")
    p.add_argument("--capabilities", action="store_true",
                   help="print the machine-readable capability document and exit")
    p.add_argument("--list-checks", action="store_true",
                   help="list audit sections (ids usable with --sections/--fix)")
    p.add_argument("--audit", action="store_true", help="run a headless audit")
    p.add_argument("--json", action="store_true",
                   help="emit JSON on stdout (stable; see --capabilities)")
    p.add_argument("--sections", metavar="ID,ID",
                   help="comma-separated section ids or names (default: all)")
    p.add_argument("--scan-path", metavar="DIR",
                   help="opt in to the recursive ClamAV malware scan of DIR "
                        "(long-running; skipped unless you name a directory)")
    p.add_argument("--output", metavar="FILE", help="write the report to FILE as well")
    p.add_argument("--fail-on", choices=["none", "warn", "critical"], default="none",
                   help="exit-code threshold for CI gating (default: none — the audit "
                        "always exits 0 when it ran; pass --fail-on warn|critical to "
                        "exit 1 when findings meet the threshold)")
    p.add_argument("--sequential", action="store_true",
                   help="run checks one at a time (easier to follow in a log)")
    p.add_argument("--fix", metavar="SECTION",
                   help="ask a provider for the remediation of one finding")
    p.add_argument("--provider", choices=PROVIDER_IDS, help="AI provider for --fix")
    p.add_argument("--model", help="override the provider's model")
    p.add_argument("--api-key", help="override the provider's API key")
    p.add_argument("--ollama-url", help=f"Ollama base URL (default: {OLLAMA_URL})")
    p.add_argument("--report", metavar="FILE",
                   help="reuse findings from a previous --audit --json report")
    p.add_argument("--print-prompt", action="store_true",
                   help="emit the exact remediation prompt instead of calling a provider")
    p.add_argument("--apply", action="store_true",
                   help="execute the suggested commands (dry-run without --yes)")
    p.add_argument("--yes", action="store_true",
                   help="confirm execution for --apply")
    p.add_argument("--harden", metavar="TARGET",
                   help="deterministic install+harden plan for " +
                        "/".join(HARDEN_TARGETS) + " (or 'all'); never runs "
                        "anything unless --apply --yes is also given")
    p.add_argument("--harden-script", action="store_true",
                   help="with --harden: emit a reviewable shell script for a "
                        "human to run under a real sudo")
    p.add_argument("--scan-target", metavar="DIR", default="/home",
                   help="directory the scheduled ClamAV timer scans "
                        "(default: /home)")
    return p


def _emit(payload, as_json: bool, text: str = ""):
    if as_json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    elif text:
        print(text)


def _provider_for(args, cfg) -> str:
    provider = args.provider or cfg.get("provider") or _load_config().get("ai_provider")
    if provider not in PROVIDER_IDS:
        provider = "ollama"
    return provider


def _cli_main(argv) -> int:
    args = _build_argparser().parse_args(argv)

    # ── discovery ────────────────────────────────────────────
    if args.capabilities:
        _emit(capabilities(), True)
        return EXIT_CLEAN

    if args.list_checks:
        checks = [{"id": section_id(s), "section": s,
                   "index": i, "platform": _OS} for i, s in enumerate(SECTIONS)]
        text = "\n".join(f"{c['id']:<28} {c['section']}" for c in checks)
        _emit({"schema": SCHEMA_CAPABILITIES, "version": VERSION, "checks": checks},
              args.json, text)
        return EXIT_CLEAN

    if args.harden:
        resolved, unknown = resolve_harden_targets(args.harden)
        if unknown:
            print(f"unknown hardening target(s): {', '.join(unknown)} "
                  f"(known: {', '.join(HARDEN_TARGETS)}, all)", file=sys.stderr)
            return EXIT_USAGE
        if not resolved:
            print("--harden needs at least one target", file=sys.stderr)
            return EXIT_USAGE

        prefix = "sudo" if args.harden_script else "sudo -n"
        plan = build_harden_plan(args.harden, sudo_prefix=prefix,
                                 scan_target=args.scan_target)

        if args.harden_script:
            script = harden_script(plan)
            # Every other --harden exit path reports `applied`, so a consumer
            # asserting `applied is False` would KeyError on this one. The
            # script is never executed here — say so explicitly.
            plan["applied"] = False
            if args.json:
                plan["script"] = script
                _emit(plan, True)
            else:
                print(script)
            return EXIT_CLEAN

        unsupported = [t["target"] for t in plan["targets"] if not t["supported"]]
        blocked = [s for s in plan["steps"] if s["blocked"]]

        if args.apply:
            if not args.yes:
                plan["applied"] = False
                plan["dry_run"] = True
                _emit(plan, args.json,
                      f"Dry run — {len(plan['steps'])} step(s) planned. Re-run with "
                      f"--apply --yes to execute.")
                return EXIT_CLEAN
            if blocked:
                plan["applied"] = False
                plan["error"] = "plan contains blocked commands"
                _emit(plan, args.json,
                      "Refusing to apply — the plan contains blocked command(s).")
                return EXIT_USAGE
            ok, applied = apply_commands(
                [s["command"] for s in plan["steps"]],
                on_progress=lambda m: None if args.json else print(m, file=sys.stderr),
                timeout=600,   # apt install + a full signature download
            )
            plan["applied"] = True
            plan["apply_results"] = applied
            plan["apply_ok"] = ok
            manual = [r for r in applied if r.get("needs_manual_sudo")]
            plan["needs_manual_sudo"] = [r["needs_manual_sudo"] for r in manual]
            if manual:
                plan["apply_summary"] = (
                    "sudo needs a password on this host — nothing was changed. "
                    "Re-run `rex.py --harden "
                    f"{args.harden} --harden-script` and run that with sudo.")
            else:
                plan["apply_summary"] = ("all steps succeeded" if ok
                                         else "some steps failed")
            plan["applied"] = ok
            _emit(plan, args.json, plan["apply_summary"])
            return EXIT_CLEAN if ok else EXIT_APPLY

        plan["applied"] = False
        lines = []
        for t in plan["targets"]:
            head = f"{t['target']} — " + ("plan" if t["supported"]
                                          else "unsupported on this platform")
            lines.append(head)
            for note in t["notes"]:
                lines.append(f"  note: {note}")
            for step in t["steps"]:
                lines.append(f"  - {step['summary']}")
                lines.append(f"      $ {step['command'].splitlines()[0]}"
                             + (" …" if "\n" in step["command"] else ""))
            lines.append("")
        if unsupported:
            lines.append(f"unsupported here: {', '.join(unsupported)}")
        lines.append(f"{len(plan['steps'])} step(s). Nothing has been run. "
                     "Apply with --apply --yes, or export a script with "
                     "--harden-script.")
        _emit(plan, args.json, "\n".join(lines))
        return EXIT_CLEAN

    if not (args.audit or args.fix):
        print("Nothing to do. Try --audit, --fix, --capabilities, or run without "
              "arguments for the GUI.", file=sys.stderr)
        return EXIT_USAGE

    # ── section selection ────────────────────────────────────
    sections = list(SECTIONS)
    if args.sections:
        sections = []
        for raw in args.sections.split(","):
            raw = raw.strip()
            if not raw:
                continue
            resolved = _resolve_section(raw)
            if resolved is None:
                print(f"unknown section: {raw!r} (see --list-checks)", file=sys.stderr)
                return EXIT_USAGE
            if resolved not in sections:
                sections.append(resolved)

    # Deliberately NOT defaulted to $HOME here: the engine reads a None scan
    # path as "no target was requested", which is what keeps the long recursive
    # ClamAV walk out of a routine audit. See AuditEngine.__init__.
    scan_path = args.scan_path

    # ── audit ────────────────────────────────────────────────
    results = None
    if args.audit:
        engine = AuditEngine(sections, scan_path=scan_path)
        if args.sequential:
            results = engine.collect(progress=None)
        else:
            results = engine.collect_parallel()
        report = build_report(results,
                              scan_path=scan_path or os.path.expanduser("~"))

        if args.output:
            try:
                with open(args.output, "w", encoding="utf-8") as f:
                    json.dump(report, f, indent=2, ensure_ascii=False)
                if not IS_WIN:
                    os.chmod(args.output, 0o600)
            except OSError as e:
                print(f"could not write {args.output}: {e}", file=sys.stderr)
                return EXIT_USAGE

        if args.json:
            print(json.dumps(report, indent=2, ensure_ascii=False))
        else:
            s = report["summary"]
            print(f"{APP_NAME} v{VERSION} — {report['hostname']} ({report['platform']})")
            print(f"score {s['score']} ({s['grade']}) — {s['fixable']} finding(s), "
                  f"{s['clean']} clean, {s['not_applicable']} n/a")
            for f in report["findings"]:
                if f["fixable"]:
                    print(f"  {f['severity']:<8} {f['id']:<28} {f['section']}")

    # ── fix ──────────────────────────────────────────────────
    if args.fix:
        section = _resolve_section(args.fix)
        if section is None:
            print(f"unknown section: {args.fix!r} (see --list-checks)", file=sys.stderr)
            return EXIT_USAGE

        finding  = ""
        redacted = False
        if args.report:
            try:
                with open(args.report, encoding="utf-8") as f:
                    prior = json.load(f)
            except (OSError, ValueError) as e:
                print(f"could not read report {args.report}: {e}", file=sys.stderr)
                return EXIT_USAGE
            hit = next((f for f in prior.get("findings", [])
                        if f.get("id") == section_id(section)), None)
            if hit is None:
                print(f"section {section!r} not present in {args.report}",
                      file=sys.stderr)
                return EXIT_USAGE
            finding  = hit.get("output") or ""
            redacted = bool(hit.get("redacted"))
            if redacted and not args.yes:
                print(f"{section!r} is redacted in that report — re-run without "
                      f"--report to audit it live, or pass --yes to send the "
                      f"placeholder text.", file=sys.stderr)
                return EXIT_USAGE
        else:
            engine  = AuditEngine([section], scan_path=scan_path)
            _status, finding = engine.collect([section])[section]

        prompt = build_prompt(section, finding)
        cfg    = load_provider_config(
            args.provider,
            ollama_url=args.ollama_url,
            deepseek_api_key=args.api_key if args.provider == "deepseek" else None,
            claude_api_key=args.api_key if args.provider == "claude" else None,
            deepseek_model=args.model if args.provider == "deepseek" else None,
            claude_model=args.model if args.provider == "claude" else None,
            ollama_model=args.model if args.provider == "ollama" else None,
        )
        provider = _provider_for(args, cfg)
        model    = cfg.get(f"{provider}_model")

        if args.print_prompt:
            payload = {
                "schema": SCHEMA_FIX, "tool": APP_NAME, "version": VERSION,
                "section": section, "section_id": section_id(section),
                "provider": provider, "model": model,
                "redacted_finding": redacted, "prompt": prompt,
                "error": None, "commands": [], "blocked": [], "needs_sudo": [],
                # No provider was called and nothing was executed, but the key
                # is present so every fix/1 document has the same shape.
                "applied": False, "apply_results": None,
            }
            _emit(payload, args.json, prompt)
            return EXIT_CLEAN

        def _status(msg):
            if not args.json:
                print(msg, file=sys.stderr)

        def _token(tok):
            if not args.json:
                sys.stdout.write(tok)
                sys.stdout.flush()

        text, err = provider_stream(provider, prompt, cfg,
                                    on_token=_token, on_status=_status)
        if not args.json and text:
            print()

        plan = classify_commands(clean_commands(text or ""))
        payload = {
            "schema": SCHEMA_FIX, "tool": APP_NAME, "version": VERSION,
            "section": section, "section_id": section_id(section),
            "provider": provider, "model": model,
            "status": (results or {}).get(section, ("", ""))[0] if results else None,
            "redacted_finding": redacted,
            "error": err,
            "raw_response": text or "",
            "commands": [c["command"] for c in plan["executable"]],
            "blocked": plan["blocked"],
            "needs_sudo": plan["needs_sudo"],
            "applied": False,
            "apply_results": None,
        }

        if err:
            if args.json:
                print(json.dumps(payload, indent=2, ensure_ascii=False))
            else:
                print(err, file=sys.stderr)
            return EXIT_PROVIDER

        if args.apply:
            if not args.yes:
                payload["applied"] = False
                payload["dry_run"] = True
                _emit(payload, args.json,
                      "Dry run — re-run with --apply --yes to execute.")
                return EXIT_CLEAN
            ok, applied = apply_commands(
                [c["command"] for c in plan["executable"]],
                on_progress=_status,
            )
            payload["applied"]     = True
            payload["apply_results"] = applied
            payload["apply_ok"]    = ok
            payload["apply_summary"] = ("all commands succeeded" if ok
                                        else "some commands failed or were blocked")
            _emit(payload, args.json, payload["apply_summary"])
            return EXIT_CLEAN if ok else EXIT_APPLY

        _emit(payload, args.json, "\n".join(payload["commands"])
              or "No executable commands in the model's reply.")
        return EXIT_CLEAN

    # ── exit code from the audit ─────────────────────────────
    if results is None:
        return EXIT_CLEAN
    threshold = {"none": (), "warn": ("warn", "critical", "error"),
                 "critical": ("critical",)}[args.fail_on]
    hit = any(st in threshold for st, _ in results.values())
    return EXIT_FINDINGS if hit else EXIT_CLEAN

class _ProviderWorker(QThread):
    """Qt wrapper around provider_stream(). The Qt-free function does the work;
    this only turns callbacks into signals, so the dialog and the CLI run the
    same prompt through the same parser."""

    result_ready  = pyqtSignal(str)   # final full text (or error string)
    token_ready   = pyqtSignal(str)   # each streaming token
    status_update = pyqtSignal(str)

    def __init__(self, prompt: str, provider: str, cfg: dict):
        QThread.__init__(self)
        self.prompt   = prompt
        self.provider = provider
        self.cfg      = cfg
        self._abort   = False

    def stop(self):
        self._abort = True

    def run(self):
        text, err = provider_stream(
            self.provider, self.prompt, self.cfg,
            on_token=lambda t: None if self._abort else self.token_ready.emit(t),
            on_status=self.status_update.emit,
        )
        self.result_ready.emit(err or text)


class OllamaWorker(_ProviderWorker):
    def __init__(self, prompt: str, model: str, base_url: str):
        super().__init__(prompt, "ollama",
                         {"ollama_model": model, "ollama_url": base_url})


class ClaudeWorker(_ProviderWorker):
    def __init__(self, prompt: str, model: str, api_key: str):
        super().__init__(prompt, "claude",
                         {"claude_model": model, "claude_api_key": api_key})


class DeepSeekWorker(_ProviderWorker):
    """Streams a remediation suggestion from DeepSeek's OpenAI-compatible API."""

    def __init__(self, prompt: str, model: str, api_key: str,
                 base_url: str = DEEPSEEK_URL):
        super().__init__(prompt, "deepseek",
                         {"deepseek_model": model, "deepseek_api_key": api_key,
                          "deepseek_url": base_url})



class ApplyWorker(QThread):
    progress = pyqtSignal(str)
    finished = pyqtSignal(str, str)  # summary, full output

    def __init__(self, cmds, blocked_paths, sudo_paths):
        QThread.__init__(self)
        self.cmds          = cmds
        self.blocked_paths = blocked_paths
        self.sudo_paths    = sudo_paths

    def run(self):
        ok, results = apply_commands(
            self.cmds,
            on_progress=self.progress.emit,
            blocked_paths=self.blocked_paths,
            sudo_paths=self.sudo_paths,
        )
        lines = []
        for r in results:
            if r.get("blocked"):
                lines.append(f"⛔  $ {r['command']}\n"
                             f"[Blocked: {r['blocked']} — not executed]")
            elif r.get("needs_manual_sudo"):
                lines.append(f"⚠  $ {r['command']}\n"
                             f"[Needs sudo password — run manually:\n"
                             f"  {r['needs_manual_sudo']}]")
            elif r.get("error"):
                lines.append(f"✖  $ {r['command']}\nError: {r['error']}")
            else:
                mark = "✓" if r["ok"] else f"✖ (exit {r.get('exit_code')})"
                disp = (("sudo " + r["command"]) if r.get("ran_as") == "sudo -n"
                        else r["command"])
                lines.append(f"{mark}  $ {disp}\n{r['output']}")
        summary = ("✓ All commands succeeded" if ok
                   else "⚠ Some commands need manual review")
        self.finished.emit(summary, "\n\n".join(lines))



class RemediationDialog(QDialog):
    def __init__(self, parent, section: str, finding: str,
                 provider: str = "ollama",
                 ollama_url: str = "http://localhost:11434",
                 ollama_model: str = "llama3.2",
                 claude_api_key: str = "",
                 claude_model: str = "claude-haiku-4-5-20251001",
                 deepseek_api_key: str = "",
                 deepseek_model: str = DEEPSEEK_MODEL,
                 deepseek_url: str = DEEPSEEK_URL):
        super().__init__(parent)
        self.setWindowTitle(f"AI Fix — {section}")
        self.resize(700, 520)
        self.setStyleSheet(f"""
            QDialog   {{ background:{COLORS['bg2']}; color:{COLORS['text']}; }}
            QLabel    {{ color:{COLORS['text']}; font-size:12px; }}
            QTextEdit {{ background:{COLORS['bg3']}; color:{COLORS['text']};
                         border:1px solid {COLORS['border']}; border-radius:6px;
                         font-family:'JetBrains Mono','Fira Mono',monospace;
                         font-size:12px; padding:8px; }}
            QPushButton {{ background:{COLORS['bg3']}; color:{COLORS['text']};
                           border:1px solid {COLORS['border']}; border-radius:6px;
                           padding:7px 18px; font-size:12px; }}
            QPushButton#apply {{ background:{COLORS['cyan']}; color:#04140f;
                                 font-weight:bold; border:none; }}
            QPushButton:hover  {{ border-color:{COLORS['cyan']}; color:{COLORS['cyan']}; }}
            QPushButton#apply:hover {{ background:{COLORS['cyan_dim']}; color:#04140f; }}
            QPushButton:disabled {{ color:{COLORS['text3']}; border-color:{COLORS['bg3']}; }}
        """)

        self.applied_output = None
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(16, 16, 16, 16)


        layout.addWidget(QLabel(f"<b style='color:{COLORS['cyan']}'>Section:</b> {section}"))

        lbl_f = QLabel("Finding:")
        lbl_f.setStyleSheet(f"color:{COLORS['text2']};")
        layout.addWidget(lbl_f)
        finding_view = QTextEdit()
        finding_view.setReadOnly(True)
        finding_view.setPlainText(finding[:900] + ("…" if len(finding) > 900 else ""))
        finding_view.setFixedHeight(120)
        layout.addWidget(finding_view)

        provider_label = {
            "claude": "Claude", "deepseek": "DeepSeek",
        }.get(provider, "Ollama")
        lbl_fix = QLabel(f"🤖  {provider_label} suggestion  (you can edit before applying):")
        lbl_fix.setStyleSheet(f"color:{COLORS['cyan']};font-weight:bold;")
        layout.addWidget(lbl_fix)

        self.lbl_ai_status = QLabel(f"⏳  Connecting to {provider_label}…")
        self.lbl_ai_status.setStyleSheet(f"color:{COLORS['text2']};font-size:11px;")
        layout.addWidget(self.lbl_ai_status)

        self.fix_view = QTextEdit()
        self.fix_view.setPlaceholderText("Response will appear here…")
        layout.addWidget(self.fix_view)

        lbl_warn = QLabel("⚠  Always review the command before applying.")
        lbl_warn.setStyleSheet(f"color:{COLORS['orange']};font-size:11px;")
        layout.addWidget(lbl_warn)

        btn_row = QHBoxLayout()
        self.btn_apply = QPushButton("▶  Apply Fix")
        self.btn_apply.setObjectName("apply")
        self.btn_apply.setEnabled(False)
        btn_skip = QPushButton("Close")
        btn_row.addWidget(self.btn_apply)
        btn_row.addStretch()
        btn_row.addWidget(btn_skip)
        layout.addLayout(btn_row)

        self.btn_apply.clicked.connect(self._apply)
        btn_skip.clicked.connect(self.reject)

        # Start AI query in background QThread
        prompt = REMEDIATION_PROMPT.format(
            os=_OS, section=section, finding=finding[:1200]
        )
        if provider == "claude":
            self._worker = ClaudeWorker(prompt, claude_model, claude_api_key)
        elif provider == "deepseek":
            self._worker = DeepSeekWorker(prompt, deepseek_model,
                                          deepseek_api_key, deepseek_url)
        else:
            self._worker = OllamaWorker(prompt, ollama_model, ollama_url)
        self._worker.status_update.connect(self._on_status)
        self._worker.token_ready.connect(self._on_token)
        self._worker.result_ready.connect(self._on_result)
        self._worker.start()

    def _on_status(self, msg: str):
        self.lbl_ai_status.setText(f"⏳  {msg}")

    def _on_token(self, token: str):
        self.lbl_ai_status.setText("✍  Generating…")
        cursor = self.fix_view.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        cursor.insertText(token)
        self.fix_view.setTextCursor(cursor)

    def _on_result(self, text: str):
        if text.startswith("["):
            self.lbl_ai_status.setText(f"✖  {text}")
            self.fix_view.setPlainText(text)
            return

        if not text or text == "NO_FIX_AVAILABLE":
            self.lbl_ai_status.setText("ℹ  No automated fix available for this finding.")
            self.fix_view.setPlainText(text or "NO_FIX_AVAILABLE")
            return

        # Validate every command and annotate dangerous ones in-place
        lines     = text.splitlines()
        annotated = []
        has_danger = False
        for line in lines:
            danger = self._check_danger(line.strip())
            if danger:
                has_danger = True
                annotated.append(f"# ⛔ BLOCKED — {danger}\n# {line}")
            else:
                annotated.append(line)

        self.fix_view.setPlainText("\n".join(annotated))

        if has_danger:
            self.lbl_ai_status.setText(
                "⚠  Dangerous commands detected (blocked with # ⛔) — review before applying"
            )
            self.lbl_ai_status.setStyleSheet(f"color:{COLORS['orange']};font-size:11px;font-weight:bold;")
        else:
            self.lbl_ai_status.setText("✓  Done — review and edit before applying")
        self.btn_apply.setEnabled(True)

    # Kept as class attributes for compatibility. The definitions live at
    # module level so that `--apply` and this dialog cannot disagree about
    # what is safe to run — one classifier, two front-ends.
    _DANGER_PATTERNS = DANGER_PATTERNS
    _BLOCKED_PATHS   = BLOCKED_PATHS
    _SUDO_PATHS      = SUDO_PATHS

    @classmethod
    def _check_danger(cls, cmd: str) -> str:
        """Return a human-readable reason if cmd is dangerous, else empty string."""
        return danger_reason(cmd)

    @staticmethod
    def _clean_commands(raw: str) -> list:
        """Strip LLM formatting noise and return executable command lines."""
        return clean_commands(raw)


    def _apply(self):
        raw = self.fix_view.toPlainText().strip()
        if not raw:
            return
        cmds = self._clean_commands(raw)
        if not cmds:
            self.applied_output = "No executable commands found in suggestion."
            self.accept()
            return

        self.btn_apply.setEnabled(False)
        self.btn_apply.setText("⏳  Running…")
        self.lbl_ai_status.setText("⏳  Applying fix…")

        self._apply_worker = ApplyWorker(cmds, self._BLOCKED_PATHS, self._SUDO_PATHS)
        self._apply_worker.progress.connect(self._on_apply_progress)
        self._apply_worker.finished.connect(self._on_apply_done)
        self._apply_worker.start()

    def _on_apply_progress(self, line: str):
        self.lbl_ai_status.setText(f"⏳  {line}")

    def _on_apply_done(self, summary: str, output: str):
        self.applied_output = f"{summary}\n\n{output}"
        self.accept()


# ============================================================
# HUVUD FÖNSTER
# ============================================================
class SecurityAuditWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} v{VERSION}")
        self.resize(1200, 800)
        self.results  = {}
        self.worker   = None
        self._apply_theme()
        self._build_ui()
        self._restore_config()

    def _restore_config(self):
        cfg = _load_config()
        if cfg.get("ollama_url"):
            self.ollama_url.setText(cfg["ollama_url"])
        if cfg.get("ollama_model"):
            self.ollama_model.setText(cfg["ollama_model"])
        if cfg.get("claude_api_key"):
            self.claude_api_key.setText(cfg["claude_api_key"])
        if cfg.get("claude_model"):
            self.claude_model.setText(cfg["claude_model"])
        if cfg.get("deepseek_api_key"):
            self.deepseek_api_key.setText(cfg["deepseek_api_key"])
        elif os.environ.get("DEEPSEEK_API_KEY"):
            # Convenience: a key already exported in the shell just works.
            self.deepseek_api_key.setText(os.environ["DEEPSEEK_API_KEY"])
        if cfg.get("deepseek_model"):
            self.deepseek_model.setText(cfg["deepseek_model"])
        if cfg.get("ai_provider") in PROVIDER_IDS:
            self.provider_combo.setCurrentIndex(PROVIDER_IDS.index(cfg["ai_provider"]))

    def _apply_theme(self):
        self.setStyleSheet(f"""
            QMainWindow, QWidget {{
                background-color: {COLORS['bg']};
                color: {COLORS['text']};
                font-family: 'JetBrains Mono', 'Fira Mono', 'Courier New', monospace;
                font-size: 12px;
            }}
            QScrollBar:vertical {{
                background: {COLORS['bg2']};
                width: 6px;
                border: none;
            }}
            QScrollBar::handle:vertical {{
                background: {COLORS['border']};
                min-height: 20px;
                border-radius: 3px;
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
            QListWidget {{
                background: {COLORS['bg2']};
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
                outline: none;
            }}
            QListWidget::item {{
                padding: 6px 10px;
                border-bottom: 1px solid {COLORS['bg3']};
                border-left: 2px solid transparent;
            }}
            QListWidget::item:selected {{
                background: rgba(0, 229, 192, 36);
                border-left: 2px solid {COLORS['cyan']};
                color: {COLORS['cyan']};
            }}
            QListWidget::item:hover {{
                background: {COLORS['bg3']};
            }}
            QPushButton {{
                background: {COLORS['bg3']};
                color: {COLORS['text']};
                border: 1px solid {COLORS['border']};
                border-radius: 6px;
                padding: 6px 14px;
                font-size: 11px;
            }}
            QPushButton:hover {{
                border-color: {COLORS['cyan']};
                color: {COLORS['cyan']};
            }}
            QPushButton:disabled {{
                color: {COLORS['text3']};
                border-color: {COLORS['bg3']};
            }}
            QPushButton#btn_run {{
                background: {COLORS['cyan']};
                color: #04140f;
                font-weight: bold;
                border: none;
            }}
            QPushButton#btn_run:hover {{
                background: {COLORS['cyan_dim']};
                color: #04140f;
            }}
            QTextEdit {{
                background: {COLORS['bg2']};
                color: {COLORS['text']};
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
                padding: 10px;
                font-family: 'JetBrains Mono', 'Fira Mono', 'Courier New', monospace;
                font-size: 13px;
                line-height: 1.5;
            }}
            QProgressBar {{
                background: {COLORS['bg3']};
                border: 1px solid {COLORS['border']};
                border-radius: 3px;
                height: 6px;
                text-align: center;
            }}
            QProgressBar::chunk {{
                background: {COLORS['cyan']};
                border-radius: 3px;
            }}
            QLabel#title {{
                color: {COLORS['cyan']};
                font-size: 16px;
                font-weight: bold;
                letter-spacing: 2px;
            }}
            QLabel#subtitle {{
                color: {COLORS['text3']};
                font-size: 10px;
            }}
            QFrame#sidebar {{
                background: {COLORS['bg2']};
                border-right: 1px solid {COLORS['border']};
            }}
        """)

    def _build_ui(self):
        central = LatticeWidget()
        central.setAutoFillBackground(True)
        pal = central.palette()
        pal.setColor(QPalette.ColorRole.Window, QColor(COLORS["bg"]))
        central.setPalette(pal)
        self.setCentralWidget(central)

        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── SIDEBAR ──────────────────────────────────────────
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(220)
        sb = QVBoxLayout(sidebar)
        sb.setContentsMargins(12, 16, 12, 12)
        sb.setSpacing(8)

        lbl_title = QLabel("ÆGIS")
        lbl_title.setObjectName("title")
        sb.addWidget(lbl_title)

        lbl_sub = QLabel(f"Security Audit  v{VERSION}  [{_OS}]")
        lbl_sub.setObjectName("subtitle")
        sb.addWidget(lbl_sub)

        sb.addSpacing(12)

        self.section_list = QListWidget()
        for s in SECTIONS:
            item = QListWidgetItem(f"  {s}")
            item.setForeground(QColor(COLORS["text2"]))
            self.section_list.addItem(item)
        self.section_list.currentRowChanged.connect(self._on_section_select)
        sb.addWidget(self.section_list)

        sb.addSpacing(8)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, len(AUDIT_SECTIONS))
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        sb.addWidget(self.progress_bar)

        self.lbl_status = QLabel("Ready")
        self.lbl_status.setStyleSheet(f"color: {COLORS['text3']}; font-size: 10px;")
        sb.addWidget(self.lbl_status)

        sb.addSpacing(8)

        btn_run = QPushButton("▶  Run Audit")
        btn_run.setObjectName("btn_run")
        btn_run.clicked.connect(self._run_audit)
        sb.addWidget(btn_run)
        self.btn_run = btn_run

        btn_export = QPushButton("↓  Export JSON")
        btn_export.clicked.connect(self._export)
        btn_export.setEnabled(False)
        sb.addWidget(btn_export)
        self.btn_export = btn_export

        btn_stop = QPushButton("■  Stop")
        btn_stop.clicked.connect(self._stop_audit)
        btn_stop.setEnabled(False)
        sb.addWidget(btn_stop)
        self.btn_stop = btn_stop

        sb.addSpacing(8)

        # ── AI Provider settings ──────────────────────────────
        from PyQt6.QtWidgets import QComboBox

        lbl_ai = QLabel("AI Provider")
        lbl_ai.setStyleSheet(f"color:{COLORS['text3']};font-size:10px;letter-spacing:1px;")
        sb.addWidget(lbl_ai)

        self.provider_combo = QComboBox()
        self.provider_combo.addItems(["Ollama", "Claude", "DeepSeek"])
        self.provider_combo.setStyleSheet(
            f"background:{COLORS['bg3']};color:{COLORS['text2']};border:1px solid {COLORS['border']};"
            f"border-radius:6px;padding:3px 6px;font-size:10px;"
        )
        sb.addWidget(self.provider_combo)

        # Ollama fields
        self._ollama_widget = QWidget()
        ollama_layout = QVBoxLayout(self._ollama_widget)
        ollama_layout.setContentsMargins(0, 0, 0, 0)
        ollama_layout.setSpacing(4)

        self.ollama_url = QLineEdit("http://localhost:11434")
        self.ollama_url.setPlaceholderText("Ollama URL")
        self.ollama_url.setStyleSheet(
            f"background:{COLORS['bg3']};color:{COLORS['text2']};border:1px solid {COLORS['border']};"
            f"border-radius:6px;padding:3px 6px;font-size:10px;"
        )
        ollama_layout.addWidget(self.ollama_url)

        self.ollama_model = QLineEdit("llama3.2")
        self.ollama_model.setPlaceholderText("model name")
        self.ollama_model.setStyleSheet(
            f"background:{COLORS['bg3']};color:{COLORS['text2']};border:1px solid {COLORS['border']};"
            f"border-radius:6px;padding:3px 6px;font-size:10px;"
        )
        ollama_layout.addWidget(self.ollama_model)
        sb.addWidget(self._ollama_widget)

        # Claude fields
        self._claude_widget = QWidget()
        claude_layout = QVBoxLayout(self._claude_widget)
        claude_layout.setContentsMargins(0, 0, 0, 0)
        claude_layout.setSpacing(4)

        self.claude_api_key = QLineEdit()
        self.claude_api_key.setPlaceholderText("sk-ant-… API key")
        self.claude_api_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.claude_api_key.setStyleSheet(
            f"background:{COLORS['bg3']};color:{COLORS['text2']};border:1px solid {COLORS['border']};"
            f"border-radius:6px;padding:3px 6px;font-size:10px;"
        )
        claude_layout.addWidget(self.claude_api_key)

        self.claude_model = QLineEdit("claude-haiku-4-5-20251001")
        self.claude_model.setPlaceholderText("Claude model")
        self.claude_model.setStyleSheet(
            f"background:{COLORS['bg3']};color:{COLORS['text2']};border:1px solid {COLORS['border']};"
            f"border-radius:6px;padding:3px 6px;font-size:10px;"
        )
        claude_layout.addWidget(self.claude_model)
        self._claude_widget.setVisible(False)
        sb.addWidget(self._claude_widget)

        # DeepSeek fields
        self._deepseek_widget = QWidget()
        deepseek_layout = QVBoxLayout(self._deepseek_widget)
        deepseek_layout.setContentsMargins(0, 0, 0, 0)
        deepseek_layout.setSpacing(4)

        self.deepseek_api_key = QLineEdit()
        self.deepseek_api_key.setPlaceholderText("sk-… DeepSeek API key")
        self.deepseek_api_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.deepseek_api_key.setStyleSheet(
            f"background:{COLORS['bg3']};color:{COLORS['text2']};border:1px solid {COLORS['border']};"
            f"border-radius:6px;padding:3px 6px;font-size:10px;"
        )
        deepseek_layout.addWidget(self.deepseek_api_key)

        self.deepseek_model = QLineEdit(DEEPSEEK_MODEL)
        self.deepseek_model.setPlaceholderText("DeepSeek model")
        self.deepseek_model.setStyleSheet(
            f"background:{COLORS['bg3']};color:{COLORS['text2']};border:1px solid {COLORS['border']};"
            f"border-radius:6px;padding:3px 6px;font-size:10px;"
        )
        deepseek_layout.addWidget(self.deepseek_model)

        lbl_ds_hint = QLabel("falls back to $DEEPSEEK_API_KEY")
        lbl_ds_hint.setStyleSheet(f"color:{COLORS['text3']};font-size:9px;")
        deepseek_layout.addWidget(lbl_ds_hint)

        self._deepseek_widget.setVisible(False)
        sb.addWidget(self._deepseek_widget)

        self.provider_combo.currentIndexChanged.connect(self._on_provider_change)

        btn_ai_fix = QPushButton("🤖  AI Fix")
        btn_ai_fix.clicked.connect(self._ai_fix_current)
        btn_ai_fix.setEnabled(False)
        btn_ai_fix.setToolTip("Ask AI to suggest a fix for the selected section")
        sb.addWidget(btn_ai_fix)
        self.btn_ai_fix = btn_ai_fix

        sb.addStretch()
        root.addWidget(sidebar)

        # ── MAIN AREA ─────────────────────────────────────────
        main_area = QWidget()
        main_layout = QVBoxLayout(main_area)
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(8)

        self.lbl_section = QLabel("Select a section →")
        self.lbl_section.setStyleSheet(
            f"color: {COLORS['cyan']}; font-size: 14px; font-weight: bold;"
        )
        main_layout.addWidget(self.lbl_section)

        self.lbl_section_status = QLabel("")
        self.lbl_section_status.setStyleSheet(f"color: {COLORS['text3']}; font-size: 10px;")
        main_layout.addWidget(self.lbl_section_status)

        # ── Virus scan toolbar (only visible for Virus Scan) ──

        self.scan_toolbar = QWidget()
        scan_tb_layout = QHBoxLayout(self.scan_toolbar)
        scan_tb_layout.setContentsMargins(0, 0, 0, 4)
        scan_tb_layout.setSpacing(6)

        lbl_path = QLabel("Path:")
        lbl_path.setStyleSheet(f"color:{COLORS['text2']};font-size:12px;")
        scan_tb_layout.addWidget(lbl_path)

        self.scan_path_input = QLineEdit(os.path.expanduser("~"))
        self.scan_path_input.setStyleSheet(
            f"background:{COLORS['bg3']};color:{COLORS['text']};border:1px solid {COLORS['border']};"
            f"border-radius:6px;padding:5px 8px;font-size:12px;"
        )
        scan_tb_layout.addWidget(self.scan_path_input, stretch=1)

        btn_browse = QPushButton("Browse…")
        btn_browse.setFixedWidth(80)
        btn_browse.clicked.connect(self._browse_scan_path)
        scan_tb_layout.addWidget(btn_browse)

        self.btn_run_scan = QPushButton("▶  Run Virus Scan")
        self.btn_run_scan.setObjectName("btn_run")
        self.btn_run_scan.setFixedWidth(150)
        self.btn_run_scan.clicked.connect(self._run_virus_scan)
        scan_tb_layout.addWidget(self.btn_run_scan)

        self.btn_stop_scan = QPushButton("■  Stop")
        self.btn_stop_scan.setFixedWidth(70)
        self.btn_stop_scan.setEnabled(False)
        self.btn_stop_scan.clicked.connect(self._stop_virus_scan)
        scan_tb_layout.addWidget(self.btn_stop_scan)

        self.scan_toolbar.setVisible(False)
        main_layout.addWidget(self.scan_toolbar)

        self.output_view = QTextEdit()
        self.output_view.setReadOnly(True)
        self.output_view.setPlaceholderText("Run audit to populate results...")
        main_layout.addWidget(self.output_view)

        root.addWidget(main_area)

        self.section_list.setCurrentRow(0)

    def _on_provider_change(self, index: int):
        self._ollama_widget.setVisible(index == 0)
        self._claude_widget.setVisible(index == 1)
        self._deepseek_widget.setVisible(index == 2)
        _save_config({"ai_provider": PROVIDER_IDS[index]})

    def _browse_scan_path(self):
        path = QFileDialog.getExistingDirectory(self, "Select scan directory",
                                                self.scan_path_input.text())
        if path:
            self.scan_path_input.setText(path)

    def _on_section_select(self, row):
        if row < 0:
            return
        section = SECTIONS[row]
        self.lbl_section.setText(section)
        is_virus = section == VIRUS_SECTION
        self.scan_toolbar.setVisible(is_virus)
        if section in self.results:
            status, output = self.results[section]
            self._show_output(status, output)
            self.btn_ai_fix.setEnabled(status in ("warn", "critical", "error"))
        else:
            self.output_view.clear()
            if is_virus:
                self.lbl_section_status.setText("Choose a path and click Run Virus Scan")
            else:
                self.lbl_section_status.setText("Not yet scanned")
            self.btn_ai_fix.setEnabled(False)

    def _show_output(self, status, output):
        colors = {
            "ok":       COLORS["green"],
            "warn":     COLORS["orange"],
            "critical": COLORS["red"],
            "error":    COLORS["red"],
        }
        labels = {
            "ok":       "✓ OK",
            "warn":     "⚠  WARNING",
            "critical": "✖ CRITICAL",
            "error":    "✖ ERROR",
        }
        c = colors.get(status, COLORS["text2"])
        label = labels.get(status, status.upper())
        self.lbl_section_status.setText(label)
        self.lbl_section_status.setStyleSheet(f"color:{c};font-size:11px;font-weight:bold;")
        escaped = output.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        html_lines = []
        for line in escaped.splitlines():
            if line.startswith("⚠") or "WARNING" in line or "FOUND" in line:
                html_lines.append(f'<span style="color:{COLORS["orange"]}">{line}</span>')
            elif line.startswith("✖") or "ERROR" in line or "CRITICAL" in line:
                html_lines.append(f'<span style="color:{COLORS["red"]}">{line}</span>')
            elif line.startswith("✓") or "OK" in line or "Clean" in line:
                html_lines.append(f'<span style="color:{COLORS["green"]}">{line}</span>')
            else:
                html_lines.append(f'<span style="color:{COLORS["text"]}">{line}</span>')
        html = (
            f'<div style="font-family:\'JetBrains Mono\',\'Fira Mono\',monospace;'
            f'font-size:13px;line-height:1.7;background:{COLORS["bg2"]};'
            f'color:{COLORS["text"]};padding:4px">'
            + "<br>".join(html_lines)
            + "</div>"
        )
        self.output_view.setHtml(html)

    def _run_audit(self):
        self.results = {}
        self._scan_log = []
        self.progress_bar.setRange(0, len(AUDIT_SECTIONS))
        self.progress_bar.setValue(0)
        self._sections_done = 0
        for i, s in enumerate(SECTIONS):
            item = self.section_list.item(i)
            item.setText(f"  {s}")
            item.setForeground(QColor(COLORS["text3"]))
            item.setBackground(QColor(COLORS["bg2"]))
        self.btn_run.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.btn_export.setEnabled(False)
        self.btn_ai_fix.setEnabled(False)
        self.lbl_status.setText("Running...")
        self.worker = AuditWorker(AUDIT_SECTIONS)
        self.worker.section_done.connect(self._on_section_done)
        self.worker.all_done.connect(self._on_all_done)
        self.worker.start()

    def _run_virus_scan(self):
        scan_path = self.scan_path_input.text().strip() or os.path.expanduser("~")
        self._scan_log = []
        self.output_view.clear()
        self.lbl_section_status.setText("Scanning…")
        self.lbl_section_status.setStyleSheet(f"color:{COLORS['cyan']};font-size:10px;")
        self.btn_run_scan.setEnabled(False)
        self.btn_stop_scan.setEnabled(True)
        self.scan_worker = AuditWorker([VIRUS_SECTION], scan_path=scan_path)
        self.scan_worker.section_done.connect(self._on_virus_scan_done)
        self.scan_worker.scan_progress.connect(self._on_scan_progress)
        self.scan_worker.start()

    def _stop_virus_scan(self):
        if hasattr(self, "scan_worker"):
            self.scan_worker.stop()
        self.btn_run_scan.setEnabled(True)
        self.btn_stop_scan.setEnabled(False)
        self.lbl_section_status.setText("Stopped")

    def _on_virus_scan_done(self, section, status, output):
        self.results[section] = (status, output)
        self.btn_run_scan.setEnabled(True)
        self.btn_stop_scan.setEnabled(False)
        self._show_output(status, output)
        self.btn_ai_fix.setEnabled(status in ("warn", "critical", "error"))

    def _stop_audit(self):
        if self.worker:
            self.worker.stop()
        self.btn_stop.setEnabled(False)
        self.lbl_status.setText("Stopped")

    def _on_section_done(self, section, status, output):
        self.results[section] = (status, output)
        self._sections_done += 1
        self.progress_bar.setValue(self._sections_done)
        idx = SECTIONS.index(section)
        item = self.section_list.item(idx)

        fg_map = {
            "ok":       COLORS["green"],
            "warn":     COLORS["orange"],
            "critical": COLORS["red"],
            "error":    COLORS["red"],
        }
        bg_map = {
            "ok":       "#0a1a0a",
            "warn":     "#1f1200",
            "critical": "#1f0000",
            "error":    "#1f0000",
        }
        prefix_map = {
            "ok":       "✓ ",
            "warn":     "⚠ ",
            "critical": "✖ ",
            "error":    "✖ ",
        }
        prefix = prefix_map.get(status, "  ")
        item.setText(f"{prefix}{section}")
        item.setForeground(QColor(fg_map.get(status, COLORS["text"])))
        item.setBackground(QColor(bg_map.get(status, COLORS["bg2"])))

        if self.section_list.currentRow() == idx:
            self.lbl_section.setText(section)
            self._show_output(status, output)
        self.lbl_status.setText(f"{self._sections_done}/{len(AUDIT_SECTIONS)} done")

    def _on_scan_progress(self, label, count):
        self.lbl_status.setText(label)
        self._scan_log.append(label)
        idx = SECTIONS.index(VIRUS_SECTION)
        if self.section_list.currentRow() == idx:
            # Trim to last 300 lines smoothly
            if len(self._scan_log) > 300:
                self._scan_log = self._scan_log[-300:]
                self.output_view.setPlainText("\n".join(self._scan_log))
            else:
                self.output_view.append(label)
            sb = self.output_view.verticalScrollBar()
            sb.setValue(sb.maximum())

    def _on_all_done(self):
        self.btn_run.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.btn_export.setEnabled(True)
        warnings = [(s, st, out) for s, (st, out) in self.results.items()
                    if st in ("warn", "critical", "error")]
        if warnings:
            self.lbl_status.setText(f"Done — {len(warnings)} warning(s)")
            self.lbl_status.setStyleSheet(f"color:{COLORS['orange']};font-size:10px;")
            self.btn_ai_fix.setEnabled(True)
            self._show_summary(warnings)
        else:
            self.lbl_status.setText("Audit complete — no issues found")
            self.lbl_status.setStyleSheet(f"color:{COLORS['green']};font-size:10px;")
            self._show_summary([])

    def _show_summary(self, warnings):
        self.lbl_section.setText("Audit Summary")
        self.lbl_section_status.setText("")
        self.scan_toolbar.setVisible(False)

        # ── Audit score ──────────────────────────────────────────────
        total = len(AUDIT_SECTIONS)
        warn_count     = sum(1 for _, st, _ in warnings if st == "warn")
        critical_count = sum(1 for _, st, _ in warnings if st in ("critical", "error"))
        score = max(0, 100 - warn_count * 5 - critical_count * 15)
        bar_filled = round(score / 5)   # 20-block bar, each block = 5 pts
        bar = "█" * bar_filled + "░" * (20 - bar_filled)
        if score >= 80:
            score_color = COLORS["green"]
            grade = "GOOD"
        elif score >= 50:
            score_color = COLORS["orange"]
            grade = "FAIR"
        else:
            score_color = COLORS["red"]
            grade = "POOR"

        score_html = (
            f'<div style="margin-bottom:16px;padding:12px 14px;'
            f'background:{COLORS["bg3"]};border-radius:6px;'
            f'border:1px solid {score_color}33">'
            f'<div style="color:{COLORS["text2"]};font-size:11px;margin-bottom:6px">'
            f'AUDIT SCORE</div>'
            f'<div style="display:flex;align-items:baseline;gap:12px">'
            f'<span style="color:{score_color};font-size:28px;font-weight:bold">{score}</span>'
            f'<span style="color:{score_color};font-size:12px;font-weight:bold">{grade}</span>'
            f'<span style="color:{COLORS["text2"]};font-size:11px">'
            f'/ 100 &nbsp;·&nbsp; {total - len(warnings)}/{total} sections clean</span>'
            f'</div>'
            f'<div style="color:{score_color};font-size:13px;letter-spacing:1px;margin-top:6px">'
            f'{bar}</div>'
            f'</div>'
        )

        if not warnings:
            self.output_view.setHtml(
                f'<div style="font-family:\'JetBrains Mono\',\'Fira Mono\',monospace;'
                f'background:{COLORS["bg2"]};color:{COLORS["text"]};padding:4px">'
                + score_html
                + f'<div style="color:{COLORS["green"]};font-size:13px;font-weight:bold">'
                  f'✓ All sections clean</div></div>'
            )
            return

        icon = {"warn": "⚠", "critical": "✖", "error": "✖"}
        color = {"warn": COLORS["orange"], "critical": COLORS["red"], "error": COLORS["red"]}

        lines = [
            score_html,
            (f'<div style="color:{COLORS["orange"]};font-size:12px;font-weight:bold;'
             f'margin-bottom:12px">{len(warnings)} issue(s) found — click a section for details</div>'),
        ]

        for section, status, output in warnings:
            c = color.get(status, COLORS["orange"])
            ic = icon.get(status, "⚠")
            preview_lines = [line for line in output.splitlines() if line.strip()][:6]
            preview = "<br>".join(
                f'<span style="color:{COLORS["text"]}">{line}</span>'
                for line in preview_lines
            )
            lines.append(
                f'<div style="margin-bottom:14px;padding:10px 12px;'
                f'background:{COLORS["bg3"]};border-left:3px solid {c};border-radius:6px">'
                f'<div style="color:{c};font-weight:bold;font-size:13px;margin-bottom:6px">'
                f'{ic} {section}</div>'
                f'<div style="font-size:12px;line-height:1.6">{preview}</div>'
                f'</div>'
            )

        self.output_view.setHtml(
            f'<div style="font-family:\'JetBrains Mono\',\'Fira Mono\',monospace;'
            f'background:{COLORS["bg2"]};color:{COLORS["text"]};padding:4px">'
            + "".join(lines) + "</div>"
        )

    def _ai_fix_current(self):
        from PyQt6.QtWidgets import QMessageBox
        row = self.section_list.currentRow()
        if row < 0:
            QMessageBox.information(self, "AI Fix", "Select a warning section first.")
            return
        section = SECTIONS[row]
        if section not in self.results:
            QMessageBox.information(self, "AI Fix", f"No results yet for: {section}")
            return
        status, output = self.results[section]
        if status not in ("warn", "critical", "error"):
            QMessageBox.information(self, "AI Fix",
                f"'{section}' has no issues to fix (status: {status}).\n"
                "Click on a ⚠ or ✖ section in the list first.")
            return
        try:
            provider = PROVIDER_IDS[self.provider_combo.currentIndex()]
            if provider == "claude":
                _save_config({
                    "claude_api_key": self.claude_api_key.text().strip(),
                    "claude_model":   self.claude_model.text().strip(),
                })
            elif provider == "deepseek":
                _save_config({
                    "deepseek_api_key": self.deepseek_api_key.text().strip(),
                    "deepseek_model":   self.deepseek_model.text().strip(),
                })
            dlg = RemediationDialog(
                self, section, output,
                provider=provider,
                ollama_url=self.ollama_url.text().strip(),
                ollama_model=self.ollama_model.text().strip(),
                claude_api_key=self.claude_api_key.text().strip(),
                claude_model=self.claude_model.text().strip(),
                deepseek_api_key=self.deepseek_api_key.text().strip(),
                deepseek_model=self.deepseek_model.text().strip() or DEEPSEEK_MODEL,
            )
            dlg.exec()
            if dlg.applied_output:
                self.results[section] = (status, output + "\n\n── Applied fix ──\n" + dlg.applied_output)
                self._show_output(status, self.results[section][1])
        except Exception as e:  # noqa: BLE001
            QMessageBox.critical(self, "AI Fix Error", str(e))

    def _export(self):
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Audit Report",
            f"aegis_audit_{datetime.date.today()}.json",  # noqa: DTZ011
            "JSON Files (*.json)",
        )
        if not path:
            return

        SENSITIVE = {"Sudo / Privileges", "SSH Config", "Users & Groups"}
        results_export = {}
        for s, (st, out) in self.results.items():
            if s in SENSITIVE:
                results_export[s] = {
                    "status": st,
                    "output": "[REDACTED — sensitive data omitted from export]",
                }
            else:
                results_export[s] = {"status": st, "output": out}

        export_data = {
            "tool":      APP_NAME,
            "version":   VERSION,
            "platform":  _OS,
            "timestamp": datetime.datetime.now().isoformat(),  # noqa: DTZ005
            "hostname":  socket.gethostname(),
            "note":      "Sensitive sections (Sudo/Privileges, SSH Config, Users & Groups) are redacted.",
            "results":   results_export,
        }
        try:
            with open(path, "w") as f:
                json.dump(export_data, f, indent=2)
            # Restrict file permissions (Unix only — no-op on Windows)
            if not IS_WIN:
                os.chmod(path, 0o600)
                self.lbl_status.setText(f"Exported → {os.path.basename(path)}  (chmod 600)")
            else:
                self.lbl_status.setText(f"Exported → {os.path.basename(path)}")
        except Exception as e:  # noqa: BLE001
            self.lbl_status.setText(f"Export failed: {e}")


# ============================================================
# ENTRY POINT
# ============================================================
def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)

    # Any argument means CLI; no argument keeps the original GUI behaviour.
    if argv and "--gui" not in argv:
        try:
            return _cli_main(argv)
        except KeyboardInterrupt:
            print("\ninterrupted", file=sys.stderr)
            return EXIT_USAGE
        except Exception as e:  # noqa: BLE001 — never a bare traceback
            print(f"rex: {type(e).__name__}: {e}", file=sys.stderr)
            return EXIT_USAGE

    if psutil is None:
        print("rex: warning - " + PSUTIL_MISSING, file=sys.stderr)

    if not HAS_QT:
        print(QT_MISSING_MSG, file=sys.stderr)
        return EXIT_USAGE

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(VERSION)
    win = SecurityAuditWindow()
    win.show()
    return app.exec()



if __name__ == "__main__":
    sys.exit(main())
