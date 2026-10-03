# LinuStart

A self-hosted web panel for administering **Debian and Ubuntu** servers:
networking, unattended updates, hostname, timezone and APT package management —
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
| **Unattended updates** | Enable/disable, refresh frequency, auto-reboot (+time), unused-kernel cleanup; shows `Allowed-Origins` and the activity log; dry-run button. Detects a missing `unattended-upgrades` package (common on minimal Debian) and offers to install it |
| **Email** | Sets up Postfix as an authenticated SMTP relay (smarthost) through **your own mail server**, sending from an address hosted there; STARTTLS or SSL on any port; wires unattended-upgrades reports to a mailbox; one-click **test send** through the full mail pipeline |
| **Software** | Search, install, remove APT packages; list upgradable packages; one-click upgrade; **maintenance**: `update`, `upgrade`, `autoremove`, `autoclean`, `clean` — all as background jobs with live logs, plus cache size and autoremove-candidate previews |
| **Users** | Create/maintain accounts: passwords (via `chpasswd`), full name, login shell, sudo membership, lock/unlock, delete (optionally with home); full **SSH key management** with key validation and locked-down `~/.ssh` permissions |
| **Safety** | Diff-friendly edits (comments/formatting preserved), automatic backups of every file it rewrites (`/var/lib/linustart/backups`), append-only audit log |

## Quick install (Debian / Ubuntu)

```bash
sudo ./install.sh
```

The installer:

1. verifies the system is in the Debian family (`/etc/os-release`),
2. installs `python3` + venv, `iproute2` and `unattended-upgrades`,
3. installs the app into `/opt/linustart`,
4. creates `/etc/linustart/config.json` with a generated access token,
5. installs and enables the `linustart` systemd service.

Then forward the port over SSH (recommended) and open the UI:

```bash
ssh -L 8765:127.0.0.1:8765 user@your-server
# browser: http://127.0.0.1:8765   (paste the token printed by the installer)
```

Remove it again with `sudo ./install.sh --uninstall`.

### Exposing it on the network

By default it binds to `127.0.0.1:8765`. To serve it directly, edit
`/etc/linustart/config.json`:

```json
{
  "host": "0.0.0.0",
  "port": 8765,
  "auth_token": "your-long-random-token"
}
```

and `sudo systemctl restart linustart`. The service **refuses to bind to a
non-loopback address without a token**. Ideally, put it behind a reverse proxy
with TLS (Caddy/nginx) rather than exposing plain HTTP.

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
re-applies it automatically — even if your SSH connection dropped during the
change. This is the same trick used by `nmtui` and cloud-init.

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
│   ├── users.py      useradd/usermod/userdel, chpasswd, authorized_keys
│   └── packages.py   apt-get / apt-cache / dpkg-query
└── static/           Plain HTML/CSS/JS UI (no build step, no Node needed)
tests/                Unit tests for all config-editing logic (74 tests)
```

The UI intentionally has **no build step and no Node dependency** — the whole
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
| `/etc/postfix/sasl_passwd` | Credentials (`chmod 600`, `postmap`-hashed) — the password is **never** returned by the API or stored in the panel's own state |
| `/etc/linustart/mail.json` | Panel state: relay host/port/security, username, from address, report settings |
| `50unattended-upgrades` | `Unattended-Upgrade::Mail` + `MailReport` so update reports arrive in your inbox |

Saving runs `postmap` and reloads Postfix. If Postfix isn't installed yet, the
Email page offers a one-click install (pre-seeded via debconf so it stays
non-interactive). The **Send test email** button queues a real message through
the local Postfix queue and out via the relay — watch its live log in the Jobs
view to see exactly what happened.

## Requirements

- Debian 11+, Ubuntu 20.04+, or a derivative (systemd-based)
- `systemctl`, `timedatectl`, `hostnamectl`, `ip -j` (all standard on both distros)
- Python 3.9+
- root (the systemd service runs as root to manage the system)

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
