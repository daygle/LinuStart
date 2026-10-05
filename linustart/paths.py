"""Filesystem locations used by LinuStart.

Every path is rooted at ``LINUSTART_ROOT`` (default ``/``) so tests and
development sandboxes can redirect all file writes into a temporary
directory without touching the real system.
"""

from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(os.environ.get("LINUSTART_ROOT", "/")).resolve()


def rooted(*parts: str) -> Path:
    """Return a path under the configured root."""
    return ROOT.joinpath(*parts)


# System configuration files we read and manage.
HOSTNAME_FILE = rooted("etc", "hostname")
HOSTS_FILE = rooted("etc", "hosts")
INTERFACES_FILE = rooted("etc", "network", "interfaces")
NETPLAN_DIR = rooted("etc", "netplan")
APT_CONF_D_DIR = rooted("etc", "apt", "apt.conf.d")
AUTO_UPGRADES_FILE = APT_CONF_D_DIR / "20auto-upgrades"
UNATTENDED_FILE = APT_CONF_D_DIR / "50unattended-upgrades"
UNATTENDED_LOG = rooted("var", "log", "unattended-upgrades", "unattended-upgrades.log")
APT_CACHE_DIR = rooted("var", "cache", "apt", "archives")
PASSWD_FILE = rooted("etc", "passwd")
SHADOW_FILE = rooted("etc", "shadow")
GROUP_FILE = rooted("etc", "group")
SHELLS_FILE = rooted("etc", "shells")
MSMTPRC = rooted("etc", "msmtprc")
POSTFIX_DIR = rooted("etc", "postfix")
POSTFIX_MAIN_CF = POSTFIX_DIR / "main.cf"
POSTFIX_SASL_PASSWD = POSTFIX_DIR / "sasl_passwd"
POSTFIX_SENDER_CANONICAL = POSTFIX_DIR / "sender_canonical"
ZONEINFO_DIR = rooted("usr", "share", "zoneinfo")
OS_RELEASE_FILE = rooted("etc", "os-release")
SSHD_CONFIG = rooted("etc", "ssh", "sshd_config")
NFTABLES_CONF = rooted("etc", "nftables.conf")
UFW_DIR = rooted("etc", "ufw")
FIREWALLD_DIR = rooted("etc", "firewalld")
SUDOERS_D = rooted("etc", "sudoers.d")
CRONTAB = rooted("etc", "crontab")
SYSCTL_CONF = rooted("etc", "sysctl.conf")
SYSCTL_D = rooted("etc", "sysctl.d")
PROC_SYS = rooted("proc", "sys")
CRON_D = rooted("etc", "cron.d")
CRON_SPOOL = rooted("var", "spool", "cron", "crontabs")
VAR_LOG_DIR = rooted("var", "log")

# LinuStart state.
CONFIG_DIR = rooted("etc", "linustart")
CONFIG_FILE = CONFIG_DIR / "config.json"
MAIL_STATE_FILE = CONFIG_DIR / "mail.json"
STATE_DIR = rooted("var", "lib", "linustart")
BACKUP_DIR = STATE_DIR / "backups"
AUDIT_LOG = STATE_DIR / "audit.log"
TERMINAL_LOG_DIR = STATE_DIR / "terminal"
PENDING_REVERTS_FILE = STATE_DIR / "pending-reverts.json"
