# LinuStart

A self-hosted web panel for administering **Debian and Ubuntu** servers:
networking, unattended updates, hostname, timezone and APT package management -
from one clean dashboard.

Built for the "day 0 → day N" case: it installs onto a freshly created server
*and* onto a server that has been running for years. On startup it **reads and
imports the existing configuration** (network backend, hostname, timezone,
update policy) and never overwrites anything you don't explicitly change.

## Supported systems

| Distro | Status |
| --- | --- |
| Debian 11+ | ✅ tested logic (`ifupdown` by default, `netplan` supported) |
| Ubuntu 20.04+ | ✅ tested logic (`netplan` by default) |
| Derivatives (Linux Mint, Pop!_OS, Raspbian/Raspberry Pi OS, …) | ✅ accepted via `ID_LIKE` in `/etc/os-release` |

Anything in the Debian family works; the installer refuses to continue on
distros outside it. The panel detects the active network backend
(`netplan` / `NetworkManager` / `ifupdown`) rather than assuming one, which is
what makes the same binary behave correctly on both Debian and Ubuntu.

## Features

| Area | What you get |
| --- | --- |
| **Overview** | OS + distro family, kernel, uptime, CPU/memory/disk, live addresses, default route |
| **Networking** | Detects `netplan`, `NetworkManager` or `ifupdown`; DHCP ↔ static editing, gateway, DNS; **90-second auto-revert** so a bad change can't lock you out of SSH |
| **Hostname** | `hostnamectl` + `/etc/hosts` kept in sync (`127.0.1.1` line) |
| **Timezone / NTP** | `timedatectl` timezone picker (all tzdata names) and NTP toggle |
| **Reboot / Shutdown** | Reboot or power off the server from the **Hostname & Time** view, with a selectable countdown (5s / 30s / 1m / 5m) and a **cancel** button that stays available until the timer fires. The action is handed to `systemd-run` as a one-shot transient unit (`linustart-power-reboot.timer` / `linustart-power-shutdown.timer`) rather than run directly, so the panel survives long enough to answer the request, the countdown is cancellable, and scheduled actions are cancelled automatically if the panel is uninstalled. Requires a double confirmation and every action is written to the audit log |
| **Unattended updates** | Full control of `20auto-upgrades` + `50unattended-upgrades`: enable/disable, package-list refresh frequency, download-in-advance, autoclean interval, auto-reboot (+time, +reboot-with-users), unused-kernel cleanup, new/unused dependency removal, auto-fix interrupted dpkg; editable **upgrade origins** (`Unattended-Upgrade::Origins-Pattern` *or* legacy `Allowed-Origins`, one per line) and **package blacklist**, so Debian-only origin patterns are one paste away; activity log and dry-run button. Detects a missing `unattended-upgrades` package (common on minimal Debian) and offers to install it. **Email reports** (always / on-change / **only-on-error**) delivered through your SMTP relay to any address *or local mailbox* (e.g. `root`) - the configuration file is created when missing and the sender is set to your relay account so hosted mail servers accept the reports |
| **Email** | Sets up **Postfix** (local queue) **or msmtp** (lightweight, no daemon) as an authenticated SMTP relay (smarthost) through **your own mail server** (the mail account hosted there), sending from an address hosted on that server, with the envelope sender (MAIL FROM) pinned to the relay account so servers that reject senders the login does not own don't bounce it; STARTTLS or SSL on any port; wires unattended-upgrades reports to a mailbox (falling back to the from address when left blank); one-click **test send** through the full mail pipeline. Detects **conflicting mail transfer agents** (`msmtp-mta`, `ssmtp`, `nullmailer`, `exim4`, `sendmail-bin`, `dma`) that would swallow reports and offers one-click removal (client-only tools like plain `msmtp`, `bsd-mailx`, `mailutils` are left untouched). **Existing `msmtp` setups are adopted, not bulldozed**: an `/etc/msmtprc` is detected and the relay form is pre-filled from it, and the password is picked up from the msmtp password file when left blank, so switching delivery to Postfix is one click |
| **Software** | Search, install, remove APT packages; list upgradable packages; one-click upgrade; **maintenance**: `update`, `upgrade`, `autoremove`, `autoclean`, `clean` - all as background jobs with live logs, plus cache size and autoremove-candidate previews |
| **Users** | Create/maintain accounts: passwords (via `chpasswd`), full name, login shell, sudo membership, lock/unlock, delete (optionally with home); full **SSH key management** (add, edit and remove, editing a key in place without disturbing the rest of `authorized_keys`) with key validation and locked-down `~/.ssh` permissions; **password aging** (`chage`), **login history** (`last`) and per-user **sudo rules** in `sudoers.d` (validated with `visudo -cf`) |
| **Firewall** | UFW, nftables or firewalld (auto-detected; a running firewalld takes precedence); for firewalld the default zone's ports, services and rich rules are listed and edited, and its target is the incoming policy (zones do not filter outgoing traffic); allow/deny rules with ports and CIDRs, default policies, enable/disable; the SSH port is kept reachable automatically when switching to a deny-incoming policy; changes use the same **90-second auto-revert** as networking |
| **SSH hardening** | `sshd_config` management: port, `PermitRootLogin`, password/key auth, `MaxAuthTries`, client-alive settings; every change is validated with `sshd -t` and applied with **90-second auto-revert** so a bad setting can't lock you out |
| **Services** | Systemd service list with active/enabled state, one-click start/stop/restart/enable/disable as background jobs, and per-service journal output |
| **Storage** | Filesystem usage (`df`) and a **directory-size explorer**: `du` scans run as background jobs with the results parsed into a sortable table |
| **Logs & Processes** | `journalctl` viewer (unit + priority filters) and safe tails of `/var/log` files; process list sorted by CPU/memory with validated `kill` (TERM/KILL/HUP/INT) |
| **Cron** | Every scheduled job on the box - `/etc/crontab`, `/etc/cron.d/*` and the user crontabs in `/var/spool/cron/crontabs/` - listed per file with schedule, run-as user and command. Jobs can be added, edited, disabled (commented out) and deleted, individually or by file; comments, `PATH=`/`MAILTO=` lines and job order are preserved, `@daily`-style shorthands and commented-out jobs are understood, and every write is validated, backed up and audited |
| **Sysctl** | Kernel parameters from `/etc/sysctl.conf` and the `/etc/sysctl.d/*.conf` drop-ins, listed per file with the value each file configures **and the value the kernel is actually using**, read from `/proc/sys` so a pending or overridden change is visible at a glance. Settings can be added, edited and removed individually or by file, and every change is applied with `sysctl --system` - if the kernel rejects a parameter, the files are restored and the previous values re-applied, so a typo cannot leave the kernel half-configured |
| **Terminal** | A web terminal over WebSocket: real PTY-backed shells (optionally as another user via `runuser`), every session recorded to `/var/lib/linustart/terminal/` and noted in the audit log |
| **Self-update** | Check for and install new LinuStart releases from GitHub in the GUI: downloads the release tarball, backs up the current application to `/var/lib/linustart/backups`, re-installs and restarts the service - with one-click **rollback** to the last backup |
| **Safety** | Diff-friendly edits (comments/formatting preserved), automatic backups of every file it rewrites (`/var/lib/linustart/backups`), append-only audit log |

## Quick install (Debian / Ubuntu)

```bash
sudo ./install.sh
```

The installer:

1. verifies the system is in the Debian family (`/etc/os-release`),
2. checks for other mail transfer agents (`msmtp-mta`, `ssmtp`, `exim4`, …) and reports them - they are left working; the Email page switches delivery to Postfix and removes them afterwards,
3. installs `python3` + venv, `iproute2` and `unattended-upgrades`,
4. fetches the **newest published release** from GitHub and installs it into `/opt/linustart` - an install is a released version, so the panel's own "check for updates" always has a real release to compare against. If GitHub is unreachable it installs the checkout it was run from instead and says so; `./install.sh --source` skips the release lookup deliberately (developers), and `LINUSTART_REPO=owner/name` points it at a fork,
5. creates `/etc/linustart/config.json` with a generated access token and the
   listen address (every interface, so the panel is reachable on the LAN),
6. offers to open the port in `ufw` (or prints the `firewalld` equivalent),
7. installs and enables the `linustart` systemd service, then prints both the
   loopback and LAN URLs.

Open `http://<server-ip>:8765` from any machine on the LAN and paste the token
the installer printed. To reach it from outside the LAN, forward the port over
SSH instead of exposing it:

```bash
ssh -L 8765:127.0.0.1:8765 user@your-server
# browser: http://127.0.0.1:8765   (paste the token printed by the installer)
```

Install flags: `--source` installs the checkout instead of the newest release,
`--loopback` binds `127.0.0.1` only, `--host ADDR` and
`--port N` set the listen address, and `./install.sh --uninstall` removes the
service again.

### Updating LinuStart

The **Software → LinuStart Updates** panel checks GitHub releases and installs
them in place (the service restarts a few seconds later). Publishing a new
version is just tagging a release:

```bash
git tag v0.2.0 && git push --tags
# then create a GitHub release from the tag
```

**What version am I running?** The panel never guesses. An installed copy
reports the release it came from; a **git checkout** reports what git says,
e.g. `1.0.0-3-g0cdaeb8`, with the commit and how many commits past the tag it
is - visible in the Updates panel, in `/api/health` and in `linustart --version`.
Cloning `main` therefore never hides the fact that you are running unreleased
code. For the same reason **bump `__version__` in `linustart/__init__.py` only
together with the tag**: a version ahead of the newest release would leave
nothing for the updater to offer, and the suite fails if that ever happens.
Source checkouts are also never self-updated from the GUI - the panel refuses
to overwrite a working tree, and tells you to use `git pull` instead.

Each update first archives the running application to
`/var/lib/linustart/backups/`; if the new version fails to verify, the old one
is restored automatically. Roll back manually at any time from the GUI or:

```bash
/opt/linustart/venv/bin/python -m linustart.updater rollback
```

**Verified downloads.** The `Release assets` workflow attaches
`linustart-<tag>.tar.gz` and a `SHA256SUMS` file to every published release.
The panel and `install.sh` download that archive and refuse it if the checksum
does not match. Releases without `SHA256SUMS` (older ones) still install, with a
warning; set `"update_require_checksum": true` in `config.json` to refuse them.
A checksum protects against corrupted or tampered downloads, not against
someone who controls the GitHub repository itself.

Updates and rollbacks also install the release's `systemd/linustart.service`
when it differs from `/etc/systemd/system/linustart.service`, followed by
`systemctl daemon-reload`, so changes to the service sandbox reach updated
machines.

Air-gapped servers can update from a downloaded archive:
`python -m linustart.updater apply --tarball release.tar.gz --tag v0.2.0`.

### Bind addresses

A fresh install listens on `0.0.0.0`, so the panel is reachable from the LAN
straight away, protected only by the generated access token. The installer prints
both URLs and offers to open the port in `ufw`.

Change the listen address at install time or afterwards:

```bash
./install.sh --loopback                        # back to 127.0.0.1, tunnel only
./install.sh --host 192.168.1.10 --port 8765   # one interface only
```

or by editing `/etc/linustart/config.json` and running
`systemctl restart linustart`:

```json
{
  "host": "0.0.0.0",
  "port": 8765,
  "auth_token": "your-long-random-token"
}
```

The service **refuses to bind to a non-loopback address without a token**, and
the installer generates one when an existing config lacks it. Because this is a
root-level admin panel served over plain HTTP, prefer an SSH tunnel or a TLS
reverse proxy (Caddy/nginx) over exposing it beyond a trusted network.

## Running without installing (development)

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
python -m linustart --no-auth          # localhost, no token
```

Every filesystem path is rooted at `$LINUSTART_ROOT` (default `/`), so you
can point a dev instance at a scratch directory and play safely.

## CLI

```
linustart [--host HOST] [--port PORT] [--config PATH] [--token TOKEN] [--no-auth]
```

| Flag | Meaning |
| --- | --- |
| `--config` | Path to `config.json` (default `/etc/linustart/config.json`) |
| `--token` | Override the token from the config file |
| `--no-auth` | Disable authentication (loopback binds only, unless forced) |

OpenAPI docs are served at `/api/docs` when the service runs.

## How the safety net works

**Network changes.** Clicking *Apply* writes the backend's native config file
(and snapshots it first), applies it, and starts a 90-second countdown. If you
don't click **Keep changes**, the panel restores the previous config and
re-applies it automatically - even if your SSH connection dropped during the
change. This is the same trick used by `nmtui` and cloud-init.

**Firewall and SSH changes.** Firewall rule/policy changes and sshd
settings get the same confirm-or-revert treatment as networking: apply,
validate, then a 90-second countdown to keep the change - otherwise the
previous files are restored and re-applied automatically. Enabling a
deny-incoming firewall policy automatically allows the current SSH port
first, so the panel can't cut off its own access.

**File writes.** Every rewritten file is first copied to
`/var/lib/linustart/backups/` with a timestamp, and writes are atomic
(tempfile + rename), so a crash can't leave a half-written config. The
newest 20 backups of each file are kept, and the file's mode and owner are
preserved.

**Audit log.** Every action is appended to `/var/lib/linustart/audit.log`
and shown in the UI. It rotates at 5 MiB, keeping five older files
(`audit.log.1` … `audit.log.5`).

**Retention.** The newest 5 application backups (self-update rollback points)
and the newest 200 terminal recordings are kept; a single terminal session
stops recording after 50 MiB of output and notes that in its log.

## Architecture

```
linustart/
├── app.py            FastAPI application factory
├── routes.py         REST API (system, network, updates, packages, jobs, audit)
├── jobs.py           Background job runner with live logs + cancellation
├── settings.py       config.json + CLI settings
├── modules/
│   ├── sysinfo.py    /proc-based overview + distro family detection
│   ├── hostname.py   hostnamectl + /etc/hosts
│   ├── timezone.py   timedatectl + tzdata picker
│   ├── network.py    netplan / NetworkManager / ifupdown
│   ├── mail.py       Postfix SMTP relay (smarthost) + SASL + TLS
│   ├── unattended.py /etc/apt/apt.conf.d auto-upgrades
│   ├── users.py      useradd/usermod/userdel, chpasswd, authorized_keys, chage, last
│   ├── sudoers.py    per-user sudoers.d drop-ins, validated with visudo
│   ├── sshd.py       sshd_config hardening with sshd -t validation
│   ├── firewall.py   UFW / nftables rules with managed-block editing
│   ├── services.py   systemctl list/show + unit actions
│   ├── power.py      reboot/shutdown via cancellable systemd-run timers
│   ├── disk.py       df parsing + du directory scans
│   ├── logs.py       journalctl queries + safe /var/log tails
│   ├── procs.py      ps parsing + validated kill
│   └── packages.py   apt-get / apt-cache / dpkg-query
terminal.py           WebSocket web terminal (PTY + session logs)
updater.py            Self-update from GitHub releases (apply/rollback CLI)
└── static/           Plain HTML/CSS/JS UI (no build step, no Node needed)
tests/                Python tests (config logic and the HTTP API); tests/js: frontend helpers
```

The UI intentionally has **no build step and no Node runtime dependency** -
the whole thing is one `.deb`-friendly Python package with a static frontend
(xterm.js is vendored under `static/vendor`). Node is only used in development
to lint and unit-test the JavaScript.

## Tests

```bash
pip install -e '.[dev]'
pytest                                    # Python: config logic + HTTP API
ruff check linustart tests conftest.py    # Python lint (rules in pyproject.toml)
node --test tests/js/*.test.js            # frontend helper unit tests
npx eslint@9 linustart/static tests/js    # frontend lint (eslint.config.js)
```

The Python tests cover the config-manipulation logic (ifupdown/netplan
editing, hosts-file updates, apt.conf editing, firewall rulesets, input
validation) and the HTTP API - including a check that every endpoint refuses
requests without the token - without needing root or a Debian-family system.
CI runs all four.

## Email setup in detail

LinuStart turns the server into a **satellite/smarthost**: locally generated
mail (cron, unattended-upgrades, `sendmail`) is handed to your mail server
with SMTP authentication and appears to come from an address you host there.

It manages:

| Piece | Purpose |
| --- | --- |
| `/etc/postfix/main.cf` | `relayhost`, `myorigin` (your sender domain), SASL + TLS settings, `inet_interfaces = loopback-only` so the server can't be used as an open relay |
| `/etc/postfix/sasl_passwd` | Credentials (`chmod 600`, `postmap`-hashed) - the password is **never** returned by the API or stored in the panel's own state |
| `/etc/postfix/sender_canonical` | `@yourdomain  relay-account@yourdomain` with `sender_canonical_classes = envelope_sender`, so the SMTP envelope sender (MAIL FROM) is always the authenticated mailbox while the `From:` header keeps the address you chose |
| `/etc/linustart/mail.json` | Panel state: relay host/port/security, username, from address, report settings |
| `50unattended-upgrades` | `Unattended-Upgrade::Mail` + `MailReport` so update reports arrive in your inbox |

Why the envelope sender is pinned: hosted mail servers only let an authenticated
mailbox send as itself. Sending as an address the login does not own is refused at
`RCPT TO` and bounces everything with
`553 5.7.1 <x@y>: Sender address rejected: not owned by user <login>`. Pinning
`MAIL FROM` to the relay account also keeps SPF and DMARC aligned with the relay,
while the visible `From:` still shows the address from the Email page.

Saving runs `postmap` and reloads Postfix. If Postfix isn't installed yet, the
Email page offers a one-click install (pre-seeded via debconf so it stays
non-interactive). The **Send test email** button queues a real message through
the local Postfix queue and out via the relay - watch its live log in the Jobs
view to see exactly what happened.

## Requirements

- Debian 11+, Ubuntu 20.04+, or a derivative (systemd-based)
- `systemctl`, `timedatectl`, `hostnamectl`, `ip -j` (all standard on both distros)
- Python 3.9+
- root (the systemd service runs as root to manage the system)
- for the web terminal: `runuser` (only when opening sessions as non-root users)

## Security notes

- Token auth protects the API; the token lives root-readable in
  `/etc/linustart/config.json`.
- All privileged actions map to fixed, validated operations; package names are
  validated against a strict allowlist regex and passed as argv (no shell).
- User management: the panel refuses to delete `root`, usernames must match a
  strict pattern, passwords have a minimum length and are fed to `chpasswd`
  over stdin (never argv), and SSH public keys must decode as real key
  material before they are accepted.
- Prefer SSH port forwarding over exposing the port publicly.
- Security policy, validation boundaries, backups and the audit log are documented in [SECURITY.md](SECURITY.md).
