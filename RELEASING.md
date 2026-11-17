# Releasing rex (PLAN.md Phase 8)

This repo (`/home/neo/rex`) is the source of truth for `rex.py`; see
[README.md](README.md#source-of-truth) and `scripts/promote_to_site.sh`.
This document is the one step that script does **not** do, and never will:
signing a release so a user can verify the file they downloaded was not
tampered with even if `aegiscloud.org` itself were compromised.

## Why this can't be automated or run on the server

A checksum published by the same server that serves the file only proves
the file wasn't altered *in transit or by a third party* — it proves
nothing if the server itself is compromised, because an attacker who can
rewrite `rex.py` can just as easily rewrite the checksum next to it.
Defending against that requires a private key the server (and this
machine, and Railway) never holds. That means:

- The signing key is generated and kept **offline**, on whatever machine
  AEGIS actually signs releases from — never committed to this repo,
  never uploaded to Railway, never pasted into a chat or a shell history
  that leaves that machine.
- Verification happens with a tool the **downloader** runs
  (`ssh-keygen -Y verify`), not with code inside `rex.py` — a tampered copy
  of rex.py could patch out any self-check it tried to run.

## One-time setup (do this once, offline)

```bash
ssh-keygen -t ed25519 -f rex-release-key -C rex-release -N ""
```

This produces `rex-release-key` (private — keep it offline, never commit
it) and `rex-release-key.pub` (public — safe to commit). Commit the public
half as an OpenSSH "allowed signers" file at
`aegis1/static/source-backup/rex-allowed-signers`:

```
rex-release namespaces="file" ssh-ed25519 AAAA...   # paste rex-release-key.pub's key material here
```

(`rex-release` is the identity string used below; `namespaces="file"`
matches the `-n file` namespace used when signing/verifying.)

## Every release

1. Promote the new `rex.py` to the site as usual:
   `rex/scripts/promote_to_site.sh`.
2. Sign the file that now sits at
   `aegis1/static/source-backup/rex.py`, from the offline machine holding
   `rex-release-key`:

   ```bash
   ssh-keygen -Y sign -f rex-release-key -n file static/source-backup/rex.py
   ```

   This produces `static/source-backup/rex.py.sig`.
3. Commit `rex.py.sig` alongside the `rex.py` it signs, in the same commit
   as the promotion — a `.sig` committed separately from the bytes it
   covers is a drift hazard, the same class of bug Phase 11 exists to fix
   for `VERSION`.
4. Push. The `/rex` page reads the artifact's SHA-256 and whether both
   `rex.py.sig` and `rex-allowed-signers` are present at render time
   (`app.py`'s `_rex_artifact_info()`) — it shows the verify instructions
   automatically once both files exist, and omits them (rather than
   showing a dead link) until they do.

## What a downloader runs to verify

```bash
ssh-keygen -Y verify -f rex-allowed-signers -I rex-release -n file -s rex.py.sig < rex.py
```

Success prints `Good "file" signature for rex-release with ED25519 key ...`.
A corrupted file or a signature from any other key fails loudly instead.

## Status

As of this writing, **no release has been signed yet** — `rex-release-key`
has not been generated. `aegis1/static/source-backup/rex-allowed-signers`
and `rex.py.sig` do not exist, and the `/rex` page correctly shows no
verify instructions until the one-time setup above is actually run. This
file is the runbook for doing that; nothing in this repo or aegis1 can do
it for you.
