# rex

**ÆGIS Security Audit** — a local, offline security auditing tool with an AI-powered fix assistant.

Single Python file. No server. No telemetry. Runs entirely on your machine.

---

## Features

- **16 audit sections** — system info, open ports, firewall, SSH config, SUID/SGID files, world-writable files, sudo privileges, startup services, scheduled tasks, environment secrets, and more
- **Virus scan** — ClamAV integration (optional)
- **AI Fix (Ollama · Pollinations · Claude · DeepSeek)** — select any finding, ask an LLM for a remediation, review the suggested commands, and apply them with one click. Ollama is local; Pollinations needs no key and no account
- **Export** — save the full audit report as a `.json` file
- **Headless / agent-drivable** — `--audit` and `--fix` from a script or an LLM agent; no GUI, display, or third-party packages required
- Cross-platform: Linux · macOS · Windows

---

## Requirements

- Python 3.10+
- [Ollama](https://ollama.com) (optional — only needed for the local AI Fix provider)
- A Claude or DeepSeek API key (optional — only needed for those two hosted AI Fix providers; Pollinations and Ollama need no key, and the audit itself needs no network at all)

---

## Install

```bash
git clone https://github.com/aegisinfo/rex
cd rex
pip install -r requirements.txt
python rex.py
```

Or without cloning:

```bash
pip install PyQt6 psutil
curl -O https://raw.githubusercontent.com/aegisinfo/rex/main/rex.py
python rex.py
```

---

## Headless / agent use

Every task rex performs is reachable from the command line, with no GUI, no
display, and no third-party packages. A bare `python3` is enough:

```bash
python3 rex.py --capabilities   # machine-readable contract: commands, schemas, exit codes
python3 rex.py --list-checks    # every audit section and its stable id
python3 rex.py --audit --json
python3 rex.py --fix ssh-config --provider deepseek --json
```

Start with `--capabilities`. It declares every flag, JSON schema, exit code and
provider in one document, so a caller never has to scrape `--help` prose.

PyQt6 is **not** needed for any `--` command — the GUI import is deferred, so a
bare interpreter can import the audit core. `psutil` is optional as well: without
it, four of the sixteen sections (`cpu-memory`, `disk`, `network`,
`running-processes`) report status `error` and are listed in `summary.unassessed`,
because a check that could not run is absent evidence, not a pass. The score
drops accordingly; that is a missing module, not a broken host.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | success — the audit ran |
| 1 | findings met an explicit `--fail-on` threshold |
| 2 | bad arguments or unreadable input |
| 3 | provider unreachable, unauthorized, or out of budget |
| 4 | `--apply` ran and at least one command failed |

`--fail-on` defaults to `none`, so an audit never fails a build unless you ask it
to. Use `--fail-on warn` (or `critical`) in CI.

### Applying fixes

Nothing is ever executed without `--apply`; add `--yes` to skip confirmation.
`--print-prompt` emits the exact prompt without contacting the provider.

`Sudo / Privileges`, `SSH Config` and `Users & Groups` are **redacted** in saved
reports, so `--fix --report FILE` on one of those exits 2 rather than sending
placeholder text to the model. Audit the section live (omit `--report`) instead,
or pass `--yes` to acknowledge that the model will see the redaction.

---

## AI Fix

rex can suggest remediations via four providers, chosen from the sidebar dropdown.

Nothing in rex requires an account. The audit path makes **no outbound connection
at all**, and two of the four AI Fix providers need no credential of any kind —
so rex can be installed and used end to end without ever identifying anyone.

### Ollama (local, private, no API key)

1. Install Ollama: https://ollama.com/download
2. Pull a model: `ollama pull llama3.2`
3. Start the server: `ollama serve`
4. In rex: check the URL (`http://localhost:11434`) and model, then select a finding → **AI Fix**

### DeepSeek

Uses the OpenAI-compatible `https://api.deepseek.com/v1` endpoint with streaming.
Models: `deepseek-flash` (default) or `deepseek-v4-pro`.

Open the sidebar dropdown → **DeepSeek** → paste your API key. If `DEEPSEEK_API_KEY`
is already exported in your shell, rex prefills it on launch. The key is stored in
`~/.aegis_config.json` with `chmod 600`.

> The DeepSeek reasoning models bill hidden chain-of-thought against `max_tokens`.
> rex requests 8192 tokens for this reason — a small budget can be spent entirely on
> reasoning and return an empty answer.

### Claude

Open the sidebar dropdown → **Claude** → paste your `sk-ant-…` API key.

### Pollinations (hosted, anonymous, no API key, no account)

The only hosted provider that needs no signup: select **Pollinations** in the
dropdown and click **AI Fix**. There is no key field because there is no key —
the request carries no `Authorization` header at all, so rex never forwards a
credential to it (a test asserts this, including that keys exported in your
environment are not sent).

```console
$ python3 rex.py --fix ssh-config --provider pollinations --json
$ python3 rex.py --fix ssh-config --provider pollinations --apply --yes
```

> **Anonymous is not private.** This lane is the one hosted provider that asks
> nobody who they are — and the trade is that the finding text leaves your
> machine and is answered by a shared, rate-limited tier (a `429` means busy,
> not misconfigured; retry, or pick another provider). Only Ollama keeps the
> finding on this machine. If anonymity is the requirement rather than privacy,
> this is the lane; if privacy is the requirement, use Ollama.

> **Security note:** rex previews all suggested commands before running them. Commands targeting sensitive system paths (`/etc/sudoers`, `/etc/shadow`, `/etc/passwd`, `/etc/ssh/sshd_config`) are never auto-executed — they are shown for manual review only. All other system-path commands are run with `sudo`.

---

## Audit sections

| Section | What it checks |
|---|---|
| System Info | OS, kernel, hostname, uptime |
| CPU & Memory | load average, RAM/swap usage |
| Disk | partition usage, mount flags |
| Network | interfaces, IPs, MAC addresses |
| Open Ports | listening TCP/UDP ports and owning processes |
| Running Processes | top processes by CPU/memory |
| Startup Services | enabled systemd / launchd / startup items |
| Firewall | ufw / iptables / pf / Windows Firewall status |
| Users & Groups | local accounts, sudoers membership |
| Sudo / Privileges | `sudo -n -l` rule set; each `NOPASSWD` grant is classified as a fixed root-owned task or a door to arbitrary root |
| SSH Config | PermitRootLogin, PasswordAuthentication, key settings |
| Scheduled Tasks | crontab entries, systemd timers, Task Scheduler |
| SUID/SGID Files | setuid/setgid binaries outside standard paths |
| World-Writable Files | files/dirs writable by any user |
| Environment Secrets | credentials in the environment, split by whether an owner-only file defines them |
| Sensitive File Permissions | ssh keys, .env files and config files with loose permissions |
| Virus Scan | ClamAV scan of your home directory (path editable in the GUI) |

### What rex will not call a finding

Three of these sections used to charge score (and hand the model a "fix this"
prompt) for states that are not defects. They now report `info`, which is
neutral in the score, and say so explicitly:

- **A password-gated sudo.** The probe is `sudo -n -l` — never a bare `sudo -l`,
  which blocks on a prompt an audit tool cannot answer. A refusal is reported as
  *unverified* (`info`), naming the reason: `NOPASSWD` entries are then unknown,
  not absent.
- **`NOPASSWD` grants that are fixed, root-owned, non-writable targets** — a
  stock Linux Mint host has four, all `/usr/lib` helpers. `ALL`, `/usr/bin/*`,
  a shell or editor (`bash`, `python`, `vim`, `systemctl`…), a target that is
  not root-owned, or one that is group/world-writable, still scores `warn`.
- **Credentials inherited from an owner-only file.** A key is a finding only
  when nothing owner-only defines it — an `export` in a world-readable rc, or
  nothing on disk at all. When every credential is defined in a `0600` file
  (e.g. `~/.aegiscode/.env`), the section reports `info` and names the file and
  its mode.

`rex.py --fix <section>` follows the same rule: if the section's live verdict
is not fixable, rex refuses and contacts no provider, because a model handed a
prompt for a non-finding can only invent commands for it. `--force` overrides
that refusal when you want an opinion regardless.

---

## Screenshot

_Coming soon_

---

## License

MIT — see [LICENSE](LICENSE)

---

Built by [Niklas Borneklint](https://aegiscloud.org) · part of the [ÆGIS](https://github.com/aegisinfo) ecosystem
