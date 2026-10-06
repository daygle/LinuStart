"""Tests for install.sh.

CI cannot run the installer, but it can read it. These guard the few orderings
that matter: every path that touches systemd or /etc must come after the root
check, otherwise an unprivileged run fails with a raw systemctl error instead
of the friendly message.
"""

import pathlib
import re

INSTALLER = pathlib.Path(__file__).resolve().parents[1] / "install.sh"

ROOT_CHECK = 'if [[ $EUID -ne 0 ]]'
UNINSTALL_BLOCK = 'if [[ "$UNINSTALL" -eq 1 ]]'


def read_installer():
    # Universal newlines, so a CRLF checkout on Windows reads the same.
    return INSTALLER.read_text(encoding="utf-8")


def test_installer_exists():
    assert INSTALLER.is_file(), f"missing {INSTALLER}"


def test_root_check_comes_before_uninstall():
    """Uninstalling stops a systemd unit, so it needs the root check first."""
    source = read_installer()
    assert source.count(ROOT_CHECK) == 1, "expected exactly one root check"
    assert source.count(UNINSTALL_BLOCK) == 1, "expected exactly one uninstall block"
    root_at = source.index(ROOT_CHECK)
    uninstall_at = source.index(UNINSTALL_BLOCK)
    assert root_at < uninstall_at, (
        "the root check must run before --uninstall is handled, otherwise an "
        "unprivileged uninstall dies on a systemctl permission error"
    )


def test_root_check_explains_how_to_fix_it():
    assert "This installer must run as root (try: sudo ./install.sh)" in read_installer()


def test_help_and_validation_run_before_the_root_check():
    """--help and bad arguments must still work for an unprivileged user."""
    source = read_installer()
    assert source.index("-h|--help)") < source.index(ROOT_CHECK)
    assert source.index('case "$1" in') < source.index(ROOT_CHECK)


def test_uninstall_keeps_configuration_and_state():
    """Uninstall removes the app, not the user's config or recorded state."""
    source = read_installer()
    block_start = source.index(UNINSTALL_BLOCK)
    block_end = source.index("\nfi\n", block_start)
    block = source[block_start:block_end]
    assert 'rm -rf "$APP_DIR"' in block
    assert 'rm -f "$SERVICE_FILE"' in block
    assert "exit 0" in block
    # config and state go only with --purge
    purge_at = block.index('if [[ "$PURGE" -eq 1 ]]')
    assert 'rm -rf "$CONFIG_DIR" "$STATE_DIR"' in block[purge_at:]
    assert '"$CONFIG_DIR"' not in block[:purge_at].replace('echo "LinuStart', "")


def test_purge_implies_uninstall_and_never_touches_system_settings():
    source = read_installer()
    assert "--purge)     UNINSTALL=1; PURGE=1 ;;" in source
    report = source[source.index("report_system_changes() {"):source.index(UNINSTALL_BLOCK)]
    # The report only reads: once the quoted messages (which name the undo
    # commands) are taken out, nothing in it removes or changes anything.
    commands = re.sub(r'"[^"]*"' + "|'[^']*'", '""', report)
    commands = "\n".join(line for line in commands.splitlines() if not line.lstrip().startswith("#"))
    for forbidden in ("rm ", "nft ", "systemctl ", "sed -i", ">"):
        assert forbidden not in commands, forbidden


if __name__ == "__main__":
    for name, func in sorted(list(globals().items())):
        if name.startswith("test_") and callable(func):
            func()
            print(f"ok: {name}")
    print("all installer tests passed")
