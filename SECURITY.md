# Security

This document describes how this panel protects operators who run it, and what
to do when you find something. It covers the defensive posture of the
application itself, not of the operating systems or network behind it.

## What the panel does and does not trust

The panel is a root-level administration interface. Everything it edits is
executed by the system: SSH, firewall, package lists, cron, sysctl and mail.
That trust boundary is enforced in three ways:

* **Input is validated before it is written.** Every file the panel rewrites -
  sshd, sudoers, firewall rules, cron jobs, sysctl parameters - has its fields
  validated in code (`valid_username`, `valid_schedule`, `valid_command`,
  `valid_key`/`valid_value`, ...) and is never executed or sourced until it has
  been through that check.
* **Writes are recorded.** Each successful change is written to the audit log
  with the changed path, the effective user and a summary of what changed. The
  audit log is append-only and lives in `/var/lib/linustart`.
* **Reads and writes are atomic.** A file is never modified in place: every
  write is backed up first (in `/var/lib/linustart/backups`) and replaces the
  old file with an `os.replace`, so a failed edit cannot leave a half-written
  configuration behind.

## What the panel will not do

Some operations that look like administration are deliberately refused so a
mistake cannot become an outage:

* You cannot ask the panel to remove `/etc/crontab` or `/etc/sysctl.conf` - the
  only thing it deletes is a single cron job line or a single parameter entry.
  Entire shared-files are only replaced by the installer, which refuses to run
  outside a clean checkout.
* The web terminal runs through a PTY with a maximum of 8 concurrent sessions
  and is capped at a per-session timeout, so one session cannot hold a port
  open for everyone.
* SSH hardening that removes host key verification or disables
  `PasswordAuthentication` is validated with `sshd -t` before it is applied, and
  the panel refuses a run that would break `sshd`.

## How the panel keeps its own code safe

* The Python dependencies are pinned in `pyproject.toml` and kept current by
  Dependabot. The panel runs from its own virtualenv; the system Python on
  Debian/Ubuntu images is frequently broken, so the venv is the interpreter of
  record and CI checks this.
* The panel's own files are checked on every push and pull request: the full
  unit suite, the JavaScript syntax check, and the shell script syntax check.
* Releases and update tooling are covered by the self-update flow, which backs
  up the application, verifies the new tree, installs it, and rolls back on
  failure.

## Reporting a vulnerability

This project is open source but not a hosted service, so there are no
third-party vendors or production data to worry about. If you find something
in the panel itself, please open an issue describing the request, the steps to
reproduce it, and the expected versus actual outcome. The maintainer will
review it within a reasonable time and credit you in the fix unless you ask to
stay anonymous.

Do not open an issue describing how to escape a container, exploit a service,
or access data you do not own, and do not attempt those things against any
host that is not yours.

## Running with this panel

The installer offers a reverse proxy or a dedicated hostname for the panel.
Ideally the panel sits behind TLS with a reverse proxy rather than being
exposed directly, and remote access goes through an SSH tunnel so the panel's
credentials and the system it controls never cross the network in the clear.
