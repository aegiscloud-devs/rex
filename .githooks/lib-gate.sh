#!/bin/sh
#
# lib-gate.sh — the agent-key gate, shared by .githooks/pre-commit and
# .githooks/pre-push. SOURCED, never executed directly.
#
# Policy lives in tools/agent-gate.mjs (one decision function, one manifest
# format, one place "allowed" is computed). This file only does the shell
# things: find the tree, pass the changed paths, and turn "cannot verify" into
# a refusal.
#
# ## Fail-closed, on purpose
#
# A MISSING gate, a MISSING node, or an UNPARSEABLE manifest BLOCKS the
# operation. The reflex is to treat those as "no policy configured, carry on",
# and that reflex is exactly backwards: it means deleting this file — the first
# move anyone bypassing a gate makes — silently disables the gate. A control
# that fails open when its own machinery is removed is a comment, not a
# control.
#
# The one escape hatch is AEGIS_GATE_SKIP=1. It is deliberately an environment
# variable rather than a flag: it has to be set on the process that runs the
# commit, it is greppable, and it prints a warning every time, so "we bypassed
# the gate" ends up in a transcript instead of being reconstructed later.
#
# ## What this cannot do
#
# `git commit --no-verify` skips both hooks, and a fresh clone has NO hooks at
# all until someone runs `git config core.hooksPath .githooks`. Neither is
# fixable from inside this repository. See `agent-gate.mjs lock-status` for the
# server-side half — a GitHub ruleset on main — which is the actual lock.

# The single path-list caveat: the gate takes paths as whitespace-separated
# tokens, so a filename containing a space cannot be represented exactly. Rather
# than risk a split that checks two non-matching halves and passes, the
# space case is escalated to "gate the whole tree" (below). Fail-closed.
agent_gate_has_space() {
    printf '%s' "$1" | grep -q ' '
}

agent_gate_run() {
    _root=$(git rev-parse --show-toplevel 2>/dev/null || pwd)

    if [ "${AEGIS_GATE_SKIP:-}" = "1" ]; then
        echo "⚠ agent-gate SKIPPED (AEGIS_GATE_SKIP=1) — this edit is unverified" >&2
        return 0
    fi

    _gate=$(agent_gate_find_cli) || {
        echo "✗ agent-gate: no gate CLI found — refusing." >&2
        echo "  Tried: \$AEGIS_GATE_CLI, $_root/tools/agent-gate.mjs," >&2
        echo "         \${AEGIS_PLUGIN_HOME:-\$HOME/aegiscode-plugin}/tools/agent-gate.mjs" >&2
        echo "  A removed gate is not an open gate. Restore it with:" >&2
        echo "    git checkout -- tools/agent-gate.mjs .aegis/guard.json .githooks/" >&2
        echo "  …or point AEGIS_GATE_CLI at a checkout that has it." >&2
        return 1
    }

    if ! command -v node >/dev/null 2>&1; then
        echo "✗ agent-gate: node is not on PATH, so the key cannot be verified — refusing." >&2
        return 1
    fi

    if [ "$#" -gt 0 ]; then
        node "$_gate" check --cwd "$_root" --paths "$@"
    else
        node "$_gate" check --cwd "$_root"
    fi
    _rc=$?

    case "$_rc" in
        0)
            return 0 ;;
        3)
            cat >&2 <<'EOF'
  This tree is agent-gated: changes to protected paths require the agent key.
    • key at      $AEGIS_HOME/keys/agent.key   (mode 600), or AEGIS_AGENT_KEY
    • first time on this machine:  node tools/agent-gate.mjs bind-machine
    • see who can currently do this:  node tools/agent-gate.mjs status
EOF
            return 1 ;;
        *)
            echo "✗ agent-gate: configuration error (exit $_rc) — refusing rather than guessing." >&2
            return 1 ;;
    esac
}

# The gate CLI is ONE file, canonical in aegiscode-plugin. A repo that does not
# vendor it — aegiscodex-dev and aegis1 carry .aegis/guard.json and this library
# but keep their own tree clean — resolves it from the environment or from the
# canonical checkout, rather than keeping a second copy of the decision function
# and the manifest format that then drifts from the first. The order is explicit
# and printed on failure, so "which gate ran?" is answerable from the transcript
# instead of by reading this file.
agent_gate_find_cli() {
    for _cand in "${AEGIS_GATE_CLI:-}" \
                 "$_root/tools/agent-gate.mjs" \
                 "${AEGIS_PLUGIN_HOME:-$HOME/aegiscode-plugin}/tools/agent-gate.mjs" \
                 "$HOME/aegiscode-plugin/tools/agent-gate.mjs"; do
        if [ -n "$_cand" ] && [ -f "$_cand" ]; then
            printf '%s' "$_cand"
            return 0
        fi
    done
    return 1
}

# Paths staged for this commit. No paths and no files ⇒ gate the whole tree.
agent_gate_check_staged() {
    _files=$(git diff --cached --name-only -z | tr '\0' '\n')
    if [ -z "$_files" ] || agent_gate_has_space "$_files"; then
        agent_gate_run
        return $?
    fi
    # shellcheck disable=SC2086  # word splitting is the interface here
    agent_gate_run $_files
}

# Paths in the commits this push would send. Reads pre-push's stdin format:
#   <local ref> <local sha> <remote ref> <remote sha>
# A new branch (zero remote sha) is diffed against the merge base with
# origin/main, falling back to the root commit, so a first push of a long-lived
# branch does not silently check nothing.
agent_gate_check_push_paths() {
    _zeros=0000000000000000000000000000000000000000
    _all=""
    _lref=""; _lsha=""; _rref=""; _rsha=""
    while read -r _lref _lsha _rref _rsha; do
        [ -n "${_lsha:-}" ] || continue
        [ "$_lsha" = "$_zeros" ] && continue
        if [ -z "${_rsha:-}" ] || [ "$_rsha" = "$_zeros" ]; then
            _base=$(git merge-base "$_lsha" origin/main 2>/dev/null || true)
            if [ -z "$_base" ]; then
                _base=$(git rev-list --max-parents=0 "$_lsha" 2>/dev/null | tail -1)
            fi
            _range="$_base..$_lsha"
        else
            _range="$_rsha..$_lsha"
        fi
        _files=$(git diff --name-only -z "$_range" 2>/dev/null | tr '\0' '\n')
        _all="$_all
$_files"
    done
    if [ -z "$(printf '%s' "$_all" | tr -d '[:space:]')" ] || agent_gate_has_space "$_all"; then
        agent_gate_run
        return $?
    fi
    # shellcheck disable=SC2086
    agent_gate_run $_all
}
