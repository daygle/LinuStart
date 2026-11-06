"""Tests for install.sh.

CI cannot run the installer, but it can read it. These guard the few orderings
that matter: every path that touches systemd or /etc must come after the root
check, otherwise an unprivileged run fails with a raw systemctl error instead
of the friendly message.
"""

import json
import pathlib
import re
import subprocess
import sys

INSTALLER = pathlib.Path(__file__).resolve().parents[1] / "install.sh"
DETECTION_START = "# --- reverse proxy detection"
DETECTION_END = "# --- end reverse proxy detection"
MERGE_HEREDOC = "<<'MERGE'"

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


def detection_block():
    """The proxy-detection functions, which read only config files."""
    source = read_installer()
    start = source.index(DETECTION_START)
    end = source.index(DETECTION_END)
    return source[start:end]


def run_detection(tmp_path, port="8765", call='detect_reverse_proxies "$1"'):
    """Run the installer's real detection against a fake /etc tree.

    The block names /etc/nginx and friends directly, so the prefix is rewritten
    to the temporary root and the functions are executed with bash. That keeps
    the detector itself untested-free: no copy of the logic lives in the tests.
    """
    script = tmp_path / "detect.sh"
    script.write_text(
        detection_block().replace("/etc/", f"{tmp_path}/etc/") + "\n" + call + "\n",
        encoding="utf-8",
    )
    return subprocess.run(
        ["bash", str(script), port], capture_output=True, text=True, check=False
    )


def write_config_file(tmp_path, relative, content):
    path = tmp_path / "etc" / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def test_detection_finds_each_proxy_that_forwards_to_the_panel_port(tmp_path):
    write_config_file(tmp_path, "nginx/sites-enabled/panel.conf", "proxy_pass http://127.0.0.1:8765;\n")
    write_config_file(tmp_path, "caddy/Caddyfile", "panel.example.com {\n  reverse_proxy localhost:8765\n}\n")
    write_config_file(tmp_path, "haproxy/haproxy.cfg", "server panel 127.0.0.1:8765 check\n")
    result = run_detection(tmp_path)
    assert result.returncode == 0, result.stderr
    found = [line.split("|")[0] for line in result.stdout.splitlines()]
    assert sorted(found) == ["Caddy", "HAProxy", "nginx"]


def test_detection_ignores_proxies_for_other_ports_and_plain_mentions(tmp_path):
    """An nginx for some other app must not change the panel's config."""
    write_config_file(tmp_path, "nginx/sites-enabled/other.conf", "proxy_pass http://127.0.0.1:9999;\n")
    # the panel's port, but not as a forward target
    write_config_file(tmp_path, "nginx/conf.d/logs.conf", "access_log /var/log/nginx/8765.log;\n")
    result = run_detection(tmp_path)
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""


def test_detection_reports_the_address_each_proxy_connects_from(tmp_path):
    """A LAN upstream is that address; a hostname upstream is loopback."""
    write_config_file(tmp_path, "nginx/sites-enabled/panel.conf", "proxy_pass http://192.168.1.9:8765;\n")
    write_config_file(tmp_path, "caddy/Caddyfile", "reverse_proxy localhost:8765\n")
    result = run_detection(tmp_path, call='proxy_addresses "$1"')
    assert result.returncode == 0, result.stderr
    assert sorted(result.stdout.split()) == ["127.0.0.1/32", "192.168.1.9/32", "::1/128"]


def merge_script(tmp_path):
    """Extract the inline python that writes trusted_proxies."""
    source = read_installer()
    start = source.index(MERGE_HEREDOC) + len(MERGE_HEREDOC)
    start = source.index("\n", start) + 1
    end = source.index("\nMERGE\n", start)
    return tmp_path / "merge.py", source[start:end] + "\n"


def test_merging_trusted_proxies_keeps_the_rest_of_the_config(tmp_path):
    script, body = merge_script(tmp_path)
    script.write_text(body, encoding="utf-8")
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps({"host": "0.0.0.0", "port": 8765, "auth_token": "secret"}), encoding="utf-8"
    )
    for _ in range(2):  # running it twice must not duplicate the addresses
        running = subprocess.run(
            [sys.executable, str(script), str(config), "127.0.0.1/32", "::1/128"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert running.returncode == 0, running.stderr
    written = json.loads(config.read_text(encoding="utf-8"))
    assert written["trusted_proxies"] == ["127.0.0.1/32", "::1/128"]
    assert written["auth_token"] == "secret"
    assert written["host"] == "0.0.0.0"
    # the token stays private, and no temporary file is left behind
    assert (config.stat().st_mode & 0o777) == 0o600
    assert [p.name for p in tmp_path.glob(".linustart-*")] == []


def test_merging_keeps_the_proxies_already_listed(tmp_path):
    script, body = merge_script(tmp_path)
    script.write_text(body, encoding="utf-8")
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"trusted_proxies": ["10.0.0.5/32"]}), encoding="utf-8")
    subprocess.run(
        [sys.executable, str(script), str(config), "127.0.0.1/32"], check=True
    )
    assert json.loads(config.read_text(encoding="utf-8"))["trusted_proxies"] == [
        "10.0.0.5/32",
        "127.0.0.1/32",
    ]


def test_the_offer_is_opt_in_and_respects_an_existing_setting():
    source = read_installer()
    assert "[y/N]" in source, "the prompt must default to No"
    assert 'if [[ -t 0 ]]' in source
    # a configured value short-circuits before any prompt is shown
    assert source.index('elif [[ -n "$EXISTING_TRUSTED" ]]') < source.index("[y/N]")
    offer = source[source.index(DETECTION_END):]
    # the config is only written by the prompt's yes branch (and by the explicit
    # --trusted-proxy flag); nothing else calls the merge
    assert source.count("add_trusted_proxies ") == 2
    yes_branch = offer[offer.index("== y*"):]
    yes_branch = yes_branch[: yes_branch.index("Non-interactive install")]
    assert yes_branch.count("add_trusted_proxies") == 1
    # unattended installs are told what to add instead of being edited silently
    unattended = offer[offer.index("Non-interactive install"):]
    assert 'trusted_proxies\\": $TRUSTED_SHOWN' in unattended
    assert "add_trusted_proxies" not in unattended
    assert "MERGE" not in unattended


def test_trusted_proxy_flag_is_documented_in_the_usage_text():
    result = subprocess.run(
        ["bash", str(INSTALLER), "--help"], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
    assert "--trusted-proxy 10.0.0.0/8" in result.stdout


def test_trusted_proxy_flag_needs_a_value():
    result = subprocess.run(
        ["bash", str(INSTALLER), "--trusted-proxy"], capture_output=True, text=True, check=False
    )
    assert result.returncode == 1
    assert "--trusted-proxy needs an address" in result.stderr


def test_trusted_proxy_flag_rejects_a_bad_address_before_doing_anything():
    """A typo would leave an unattended panel unable to start, so it stops here."""
    result = subprocess.run(
        ["bash", str(INSTALLER), "--trusted-proxy", "nonsense"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "Invalid --trusted-proxy address: 'nonsense'" in result.stderr
    # rejected while parsing arguments, before the root check and any change
    assert "must run as root" not in result.stderr


def test_trusted_proxy_flag_accepts_addresses_and_networks():
    for value in ("10.0.0.0/8", "127.0.0.1", "::1", "2001:db8::/32"):
        result = subprocess.run(
            ["bash", str(INSTALLER), "--trusted-proxy", value],
            capture_output=True,
            text=True,
            check=False,
        )
        assert "Invalid --trusted-proxy" not in result.stderr, value
        # validation passed: only the root check stopped this unprivileged run
        assert "must run as root" in result.stderr, value


def test_the_flag_trusts_the_addresses_without_prompting_or_detecting():
    source = read_installer()
    start = source.index('if [[ "$TRUSTED_FLAG" -eq 1 ]]; then\n    echo "==> Trusting')
    end = source.index('elif [[ -n "$EXISTING_TRUSTED" ]]', start)
    branch = source[start:end]
    assert 'add_trusted_proxies "${TRUSTED_PROXIES[@]}"' in branch
    assert "read -r" not in branch, "the flag must not prompt"
    # detection is skipped: the operator already said which proxies are trusted
    detection = source[source.index('DETECTED_PROXIES=""'):start]
    assert '"$TRUSTED_FLAG" -eq 0' in detection


def trusted_helpers():
    """The trusted_shown/add_trusted_proxies functions, extracted verbatim."""
    source = read_installer()
    start = source.index("trusted_shown() {")
    end = source.index("\n}\n", source.index("add_trusted_proxies() {")) + 3
    return source[start:end]


def test_the_merge_helper_adds_without_a_prompt_and_keeps_existing_entries(tmp_path):
    script = tmp_path / "trusted.sh"
    script.write_text(
        "set -euo pipefail\n"
        'CONFIG_FILE="$1"; SERVICE_FILE="$2"; RESTART_NEEDED=0\n'
        + trusted_helpers()
        + "\nadd_trusted_proxies '10.0.0.5/32' '::1/128'\n"
        + 'echo "restart=$RESTART_NEEDED"\n',
        encoding="utf-8",
    )
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {"host": "0.0.0.0", "auth_token": "secret", "trusted_proxies": ["10.0.0.5/32"]}
        ),
        encoding="utf-8",
    )
    service = tmp_path / "linustart.service"
    service.write_text("", encoding="utf-8")
    first = subprocess.run(
        ["bash", str(script), str(config), str(service)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert first.returncode == 0, first.stderr
    written = json.loads(config.read_text(encoding="utf-8"))
    assert written["trusted_proxies"] == ["10.0.0.5/32", "::1/128"]
    assert written["auth_token"] == "secret"
    assert (config.stat().st_mode & 0o777) == 0o600
    assert 'Added ["10.0.0.5/32", "::1/128"] to trusted_proxies' in first.stdout
    # a running service has to pick the new list up
    assert "restart=1" in first.stdout

    second = subprocess.run(
        ["bash", str(script), str(config), str(service)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert second.returncode == 0, second.stderr
    # nothing new: not rewritten, and no restart asked for
    assert "Already in trusted_proxies" in second.stdout
    assert "restart=0" in second.stdout


if __name__ == "__main__":
    for name, func in sorted(list(globals().items())):
        if name.startswith("test_") and callable(func):
            func()
            print(f"ok: {name}")
    print("all installer tests passed")
