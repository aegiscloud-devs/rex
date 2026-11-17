#!/usr/bin/env bash
# PLAN.md Phase 11 — one scripted promotion step, not a remembered copy.
#
# /home/neo/rex is the single source of truth for rex.py (see README.md).
# This script is the only sanctioned way bytes move from here to the two
# places rex is served from: the aegis1 website's download button and the
# npm package. Hand-copying is what produced the three-way version drift
# Phase 11 exists to fix (PLAN.md rev 3, finding 2).
#
# Reuses attic/misc/rex-npm/scripts/sync-artifact.js for the actual byte
# copy + mirror refresh — that script already existed, already defaults its
# source to this repo's rex.py, and already lists the aegis1 static file as
# a durable mirror it keeps in sync. This script wraps it with the two
# pieces Phase 11 still needed: a dirty-tree refusal, and the website test
# suite's VERSION expectation.
#
# Usage: rex/scripts/promote_to_site.sh
set -euo pipefail

REX_REPO="/home/neo/rex"
NPM_PKG="/home/neo/attic/misc/rex-npm"
AEGIS1_SITE="/home/neo/aegis1/static/source-backup/rex.py"
AEGIS1_TEST="/home/neo/aegis1/tests/test_rex_page.py"

version_of() {
  grep -m1 -oP '^VERSION\s*=\s*"\K[^"]+' "$1"
}

# (a) refuse on a dirty source tree — a promotion ships exactly what's in
# git, never an uncommitted edit that the next real commit could diverge from.
dirty="$(git -C "$REX_REPO" status --porcelain)"
if [ -n "$dirty" ]; then
  echo "promote_to_site: $REX_REPO has uncommitted changes — commit or stash first" >&2
  echo "$dirty" >&2
  exit 1
fi

SRC_VERSION="$(version_of "$REX_REPO/rex.py")"
if [ -z "$SRC_VERSION" ]; then
  echo "promote_to_site: no VERSION constant in $REX_REPO/rex.py" >&2
  exit 1
fi

# Phase 8 (release signing) is not built yet. It hooks in here, between the
# npm vendor copy and the website mirror copy that sync-artifact.js performs
# below — there is nothing to call until that phase exists.

# sync-artifact.js refuses to run on a source/package.json version mismatch
# by design (that refusal is what catches a forgotten bump), so package.json
# has to be updated before it's invoked.
node -e '
  const fs = require("fs");
  const p = process.argv[1];
  const pkg = JSON.parse(fs.readFileSync(p, "utf8"));
  pkg.version = process.argv[2];
  fs.writeFileSync(p, JSON.stringify(pkg, null, 2) + "\n");
' "$NPM_PKG/package.json" "$SRC_VERSION"

# (b)+(c) copy rex.py -> vendor/rex.py, and refresh every durable mirror
# (today: aegis1's served copy) whose bytes have drifted. Not --strict: a
# freshly-stale mirror getting refreshed is this script's normal job, not a
# failure, and a ruff complaint about rex.py's own style is a separate
# concern from whether the promotion moved the right bytes — step (e) below
# is this script's actual "fail loudly on disagreement" gate.
( cd "$NPM_PKG" && node scripts/sync-artifact.js )

# (d) bump the VERSION expectation the page-vs-artifact test suite asserts.
sed -i -E 's/^VERSION = "[^"]+"/VERSION = "'"$SRC_VERSION"'"/' "$AEGIS1_TEST"

# (e) fail loudly if the three copies disagree after all of the above.
V_SITE="$(version_of "$AEGIS1_SITE")"
V_NPM="$(version_of "$NPM_PKG/vendor/rex.py")"
if [ "$SRC_VERSION" != "$V_SITE" ] || [ "$SRC_VERSION" != "$V_NPM" ]; then
  echo "promote_to_site: version mismatch after promotion — src=$SRC_VERSION site=$V_SITE npm=$V_NPM" >&2
  exit 1
fi

echo "promote_to_site: $SRC_VERSION promoted to site + npm; test_rex_page.py updated"
