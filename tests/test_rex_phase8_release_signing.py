"""PLAN.md Phase 8 — rex.py distribution integrity (release signing).

The actual signing mechanism (ed25519 keypair, ssh-keygen -Y sign/verify,
the allowed-signers file) is deliberately manual and out-of-band — see
RELEASING.md — and lives on the serving side (aegis1's /rex page), not in
rex.py itself. rex.py's own piece is capabilities()["self_sha256"]: a purely
informational self-hash, useful for diffing a local copy against what a
download page advertises, but NOT itself a security mechanism (a tampered
copy could patch the function out too).

Run with:  .venv/bin/python -m pytest tests/test_rex_phase8_release_signing.py -v
"""
import hashlib
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
REX = ROOT / "rex.py"
sys.path.insert(0, str(ROOT))
import rex as rexmod  # noqa: E402


def test_self_sha256_matches_the_file_on_disk():
    expected = hashlib.sha256(REX.read_bytes()).hexdigest()
    assert rexmod.capabilities()["self_sha256"] == expected


def test_self_sha256_is_a_well_formed_hex_digest():
    digest = rexmod.capabilities()["self_sha256"]
    assert isinstance(digest, str)
    assert re.fullmatch(r"[0-9a-f]{64}", digest)


def test_self_sha256_is_not_claimed_as_a_security_mechanism():
    """The function's own docstring must keep disclaiming this — the field
    is informational, not a substitute for ssh-keygen -Y verify."""
    source = REX.read_text()
    match = re.search(r'def _self_sha256\(\):\n(?:    """.*?""")', source, re.S)
    assert match, "_self_sha256() lost its docstring"
    assert "cannot meaningfully attest" in match.group(0)
