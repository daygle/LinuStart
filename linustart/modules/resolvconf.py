"""Install resolvconf so the panel's DNS setting reaches /etc/resolv.conf.

On ifupdown systems ``dns-nameservers`` is only a request: something has to
turn it into /etc/resolv.conf. Debian's minimal installs often have nothing
that does - or a resolv.conf left behind by the installer's dhcpcd lease,
which nothing will ever rewrite again. resolvconf is the piece ifupdown
expects: its if-up hook registers each interface's ``dns-nameservers``, and
dhcpcd hands its servers to it instead of writing the file itself.

Run as a panel job (``python -m linustart.modules.resolvconf setup``) so apt's
output streams into the job log. Installing resolvconf swaps /etc/resolv.conf
for a generated file that starts out empty, so the configured servers are
registered straight away instead of waiting for the next ``ifup``, and the
previous file is put back if the machine would be left with no nameserver.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import subprocess
import sys
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from ..paths import RESOLV_CONF_FILE
from . import network, packages

PACKAGE = "resolvconf"
# Interfaces with no dns-nameservers of their own (all DHCP, say) still need
# a resolver until dhcpcd renews: the servers in use today are registered
# under this record. It lives in /run, so it goes away at the next boot,
# when ifup and dhcpcd register the real ones.
FALLBACK_RECORD = "linustart"


def setup_offered(backend: str, summary: Mapping[str, object]) -> bool:
    """Should the Networking page offer to install resolvconf?"""
    return (
        backend == "ifupdown"
        and not summary.get("dns_setting_applies")
        and not summary.get("has_resolvconf")
    )


def records_for(
    interfaces: Sequence[Mapping[str, object]], current: Sequence[str]
) -> List[Tuple[str, List[str]]]:
    """``(record name, nameservers)`` to register with ``resolvconf -a``.

    Records are named ``<iface>.inet`` like ifupdown's own hook names them,
    so the next ``ifup`` replaces them instead of adding duplicates. Invalid
    entries are dropped rather than written into resolv.conf.
    """
    records: List[Tuple[str, List[str]]] = []
    for iface in interfaces:
        try:
            name = network.validate_interface_name(str(iface.get("name") or ""))
        except ValueError:
            continue
        servers = [s for s in (network._is_ip(str(d)) for d in iface.get("dns") or []) if s]
        if servers:
            records.append((f"{name}.inet", list(dict.fromkeys(servers))))
    if not records:
        servers = [s for s in (network._is_ip(str(d)) for d in current) if s]
        if servers:
            records.append((FALLBACK_RECORD, list(dict.fromkeys(servers))))
    return records


def record_text(servers: Sequence[str]) -> str:
    return "".join(f"nameserver {server}\n" for server in servers)


def install_command() -> List[str]:
    return packages.install_command([PACKAGE])


def command() -> List[str]:
    """The job the panel runs."""
    return [sys.executable, "-m", "linustart.modules.resolvconf", "setup"]


def log(message: str) -> None:
    print(message, flush=True)


def _run(argv: Sequence[str], stdin_text: Optional[str] = None) -> int:
    """Run a command with its output going straight to the job log."""
    sys.stdout.flush()
    try:
        return subprocess.run(
            list(argv), input=stdin_text, text=True, check=False,
            env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
        ).returncode
    except OSError as exc:
        log(f"could not run {argv[0]}: {exc}")
        return 127


def _restore(previous: str, was_link: Optional[str]) -> None:
    """Put the pre-install /etc/resolv.conf back (file or symlink)."""
    try:
        if RESOLV_CONF_FILE.is_symlink() or RESOLV_CONF_FILE.exists():
            RESOLV_CONF_FILE.unlink()
        if was_link is not None:
            os.symlink(was_link, RESOLV_CONF_FILE)
        else:
            RESOLV_CONF_FILE.write_text(previous, encoding="utf-8")
        log(f"restored the previous {RESOLV_CONF_FILE}")
    except OSError as exc:
        log(f"could not restore {RESOLV_CONF_FILE}: {exc}")


def cmd_setup() -> int:
    backend = asyncio.run(network.detect_backend())
    if backend != "ifupdown":
        log(f"nothing to do: the network backend is {backend}, which applies DNS itself")
        return 1

    previous = ""
    was_link: Optional[str] = None
    try:
        if RESOLV_CONF_FILE.is_symlink():
            was_link = os.readlink(RESOLV_CONF_FILE)
        previous = RESOLV_CONF_FILE.read_text(encoding="utf-8")
    except OSError:
        pass
    current = [str(s) for s in network.parse_resolv_conf(previous)["nameservers"]]
    log(f"current nameservers: {', '.join(current) or 'none'}")

    config: Dict[str, object] = asyncio.run(network.get_config(backend))
    records = records_for(config.get("interfaces") or [], current)  # type: ignore[arg-type]

    log(f"installing {PACKAGE}")
    if _run(install_command()) != 0:
        log(f"apt-get could not install {PACKAGE}")
        return 1
    # Debian's resolvconf ships updates enabled; openresolv has no such flag.
    _run(["resolvconf", "--enable-updates"])

    if not records:
        log("no interface has DNS servers configured and none were in use")
    for name, servers in records:
        log(f"registering {name}: {', '.join(servers)}")
        if _run(["resolvconf", "-a", name], stdin_text=record_text(servers)) != 0:
            log(f"resolvconf refused the {name} record")
    _run(["resolvconf", "-u"])

    try:
        now = network.parse_resolv_conf(RESOLV_CONF_FILE.read_text(encoding="utf-8"))
    except OSError:
        now = {"nameservers": []}
    servers = [str(s) for s in now["nameservers"]]
    if not servers:
        log(f"{RESOLV_CONF_FILE} has no nameserver after the install; putting the old file back")
        _restore(previous, was_link)
        return 1
    log(f"{RESOLV_CONF_FILE} -> {', '.join(servers)}")
    log("the DNS servers saved on the Networking page now apply (on save and at boot)")
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="linustart-resolvconf", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("setup", help="install resolvconf and register the configured DNS servers")
    parser.parse_args(argv)
    return cmd_setup()


if __name__ == "__main__":
    raise SystemExit(main())
