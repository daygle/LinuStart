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
| **Unattended updates** | Full control of `20auto-upgrades` + `50unattended-upgrades`: enable/disable, package-list refresh frequency, download-in-advance, autoclean interval, auto-reboot (+time, +reboot-with-users), unused-kernel cleanup, new/unused dependency removal, auto-fix interrupted dpkg; editable **upgrade origins** (`Unattended-Upgrade::Origins-Pattern` *or* legacy `Allowed-Origins`, one per line) and **package blacklist**, so Debian-only origin patterns are one paste away; activity log and dry-run button. Detects a missing `unattended-upgrades` package (common on minimal Debian) and offers to install it. **Email reports** (always / on-change / **only-on-error**) delivered through your SMTP relay to any address *or local mailbox* (e.g. `root`) - the configuration file is created when missing and the sender is set to your relay account so hosted mail servers accept the reports |
| **Email** | Sets up Postfix as an authenticated SMTP relay (smarthost) through **your own mail server** (the mail account hosted there), sending from an address hosted on that server; STARTTLS or SSL on any port; wires unattended-upgrades reports to a mailbox (falling back to the from address when left blank); one-click **test send** through the full mail pipeline. Detects **conflicting mail transfer agents** (`msmtp-mta`, `ssmtp`, `nullmailer`, `exim4`, `sendmail-bin`, `dma`) that would swallow reports and offers one-click removal (client-only tools like plain `msmtp`, `bsd-mailx`, `mailutils` are left untouched). **Existing `msmtp` setups are adopted, not bulldozed**: an `/etc/msmtprc` is detected and the relay form is pre-filled from it, and the password is picked up from the msmtp password file when left blank, so switching delivery to Postfix is one click |
| **Software** | Search, install, remove APT packages; list upgradable packages; one-click upgrade; **maintenance**: `update`, `upgrade`, `autoremove`, `autoclean`, `clean` - all as background jobs with live logs, plus cache size and autoremove-candidate previews |
| **Users** | Create/maintain accounts: passwords (via `chpasswd`), full name, login shell, sudo membership, lock/unlock, delete (optionally with home); full **SSH key management** with key validation and locked-down `~/.ssh` permissions; **password aging** (`chage`), **login history** (`last`) and per-user **sudo rules** in `sudoers.d` (validated with `visudo -cf`) |
| **Firewall** | UFW or nftables (auto-detected); allow/deny rules with ports and CIDRs, default policies, enable/disable; the SSH port is kept reachable automatically when switching to a deny-incoming policy; changes use the same **90-second auto-revert** as networking |
| **SSH hardening** | `sshd_config` management: port, `PermitRootLogin`, password/key auth, `MaxAuthTries`, client-alive settings; every change is validated with `sshd -t` and applied with **90-second auto-revert** so a bad setting can't lock you out |
| **Services** | Systemd service list with active/enabled state, one-click start/stop/restart/enable/disable as background jobs, and per-service journal output |
| **Storage** | Filesystem usage (`df`) and a **directory-size explorer**: `du` scans run as background jobs with the results parsed into a sortable table |
| **Logs & Processes** | `journalctl` viewer (unit + priority filters) and safe tails of `/var/log` files; process list sorted by CPU/memory with validated `kill` (TERM/KILL/HUP/INT) |
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
4. installs the app into `/opt/linustart`,
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

Install flags: `--loopback` binds `127.0.0.1` only, `--host ADDR` and
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

Each update first archives the running application to
`/var/lib/linustart/backups/`; if the new version fails to verify, the old one
is restored automatically. Roll back manually at any time from the GUI or:

```bash
/opt/linustart/venv/bin/python -m linustart.updater rollback
```

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
(tempfile + rename), so a crash can't leave a half-written config.

**Audit log.** Every action is appended to `/var/lib/linustart/audit.log`
and shown in the UI.

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
│   ├── disk.py       df parsing + du directory scans
│   ├── logs.py       journalctl queries + safe /var/log tails
│   ├── procs.py      ps parsing + validated kill
│   └── packages.py   apt-get / apt-cache / dpkg-query
terminal.py           WebSocket web terminal (PTY + session logs)
updater.py            Self-update from GitHub releases (apply/rollback CLI)
└── static/           Plain HTML/CSS/JS UI (no build step, no Node needed)
tests/                Unit tests for all config-editing logic (131 tests)
```

The UI intentionally has **no build step and no Node dependency** - the whole
thing is one `.deb`-friendly Python package with a static frontend.

## Tests

```bash
pip install -e '.[dev]'
pytest            # or run any file directly: python tests/test_ifupdown.py
```

The tests cover the config-manipulation logic (ifupdown/netplan editing,
hosts-file updates, apt.conf editing, apt output parsing, input validation)
without needing root or a Debian-family system.

## Email setup in detail

LinuStart turns the server into a **satellite/smarthost**: locally generated
mail (cron, unattended-upgrades, `sendmail`) is handed to your mail server
with SMTP authentication and appears to come from an address you host there.

It manages:

| Piece | Purpose |
| --- | --- |
| `/etc/postfix/main.cf` | `relayhost`, `myorigin` (your sender domain), SASL + TLS settings, `inet_interfaces = loopback-only` so the server can't be used as an open relay |
| `/etc/postfix/sasl_passwd` | Credentials (`chmod 600`, `postmap`-hashed) - the password is **never** returned by the API or stored in the panel's own state |
| `/etc/linustart/mail.json` | Panel state: relay host/port/security, username, from address, report settings |
| `50unattended-upgrades` | `Unattended-Upgrade::Mail` + `MailReport` so update reports arrive in your inbox |

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
