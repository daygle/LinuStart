#!/usr/bin/env bash
#
# LinuStart installer for Debian, Ubuntu and derivatives (anything in the
# Debian family, detected via /etc/os-release).
#
# Usage:
#   ./install.sh                     # install the latest release (or upgrade in place)
#   ./install.sh --source            # install this checkout instead of the latest release
#   ./install.sh --loopback          # bind 127.0.0.1 only (access over an SSH tunnel)
#   ./install.sh --host 0.0.0.0 --port 8765
#   ./install.sh --trusted-proxy 10.0.0.0/8  # trust that proxy's X-Forwarded-For
#   ./install.sh --uninstall         # remove the service and files, list what LinuStart changed
#   ./install.sh --purge             # --uninstall, and also delete its config and state
#
set -euo pipefail

APP_DIR=/opt/linustart
VENV_DIR="$APP_DIR/venv"
SRC_DIR="$APP_DIR/app"
CONFIG_DIR=/etc/linustart
CONFIG_FILE="$CONFIG_DIR/config.json"
SERVICE_FILE=/etc/systemd/system/linustart.service
STATE_DIR=/var/lib/linustart

# A fresh install binds every interface so the panel is reachable from the
# LAN; the generated token is what keeps it locked down. --loopback opts out.
DEFAULT_HOST="0.0.0.0"
DEFAULT_PORT=8765
HOST=""
PORT=""
HOST_SET=0
PORT_SET=0
UNINSTALL=0
PURGE=0
RESTART_NEEDED=0
# Proxies named with --trusted-proxy, trusted without asking; the list is what
# unattended installs use instead of answering the prompt.
TRUSTED_FLAG=0
TRUSTED_PROXIES=()
# An install is a released version: cloning main gives you a tree ahead of
# every tag, so the newest release is what gets installed unless --source
# says otherwise. The panel then reports a version that matches the release
# it came from and its own "check for updates" has something to compare.
FROM_SOURCE=0
REPO="${LINUSTART_REPO:-daygle/LinuStart}"
TAG_PATTERN='^v?[0-9]+(\.[0-9]+){0,3}([-.][0-9A-Za-z.]+)?$'

usage() {
    sed -n '3,13p' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --uninstall) UNINSTALL=1 ;;
        --purge)     UNINSTALL=1; PURGE=1 ;;
        --source)    FROM_SOURCE=1 ;;
        --loopback)  HOST="127.0.0.1"; HOST_SET=1 ;;
        --host)      HOST="${2:-}"; HOST_SET=1; shift ;;
        --port)      PORT="${2:-}"; PORT_SET=1; shift ;;
        --trusted-proxy)
            if [[ -z "${2:-}" ]]; then
                echo "--trusted-proxy needs an address, for example: --trusted-proxy 127.0.0.1/32" >&2
                exit 1
            fi
            TRUSTED_PROXIES+=("$2"); TRUSTED_FLAG=1; shift ;;
        -h|--help)   usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
    shift
done

if [[ "$PORT_SET" -eq 1 ]] && { [[ ! "$PORT" =~ ^[0-9]+$ ]] || [[ "$PORT" -lt 1 ]] || [[ "$PORT" -gt 65535 ]]; }; then
    echo "Invalid port: '${PORT}' (use 1-65535)" >&2
    exit 1
fi
if [[ "$HOST_SET" -eq 1 && -z "$HOST" ]]; then
    echo "--host needs an address, for example: --host 127.0.0.1" >&2
    exit 1
fi

# These addresses are written into the config without a prompt, and the panel
# refuses to start on a bad entry (deliberately: ignoring a typo would leave the
# throttle looking per-client while it is not), so a typo has to stop the
# install here rather than leave an unattended server unable to boot.
if [[ "$TRUSTED_FLAG" -eq 1 ]] && command -v python3 >/dev/null 2>&1; then
    BAD_TRUSTED="$(python3 - "${TRUSTED_PROXIES[@]}" <<'PY'
import ipaddress
import sys

for value in sys.argv[1:]:
    try:
        ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        print(value)
        break
PY
)" || BAD_TRUSTED="?"
    if [[ -n "$BAD_TRUSTED" ]]; then
        echo "Invalid --trusted-proxy address: '$BAD_TRUSTED'" >&2
        echo "  use an IP address or CIDR range, for example: --trusted-proxy 10.0.0.0/8" >&2
        exit 1
    fi
fi

is_loopback() {
    case "$1" in
        127.0.0.1|localhost|::1|127.*) return 0 ;;
        *) return 1 ;;
    esac
}

if [[ $EUID -ne 0 ]]; then
    echo "This installer must run as root (try: sudo ./install.sh)" >&2
    exit 1
fi

# What the panel changed on the system, found by the marks it leaves. These
# are settings the server now runs with (sudo rules, SSH and kernel settings,
# firewall rules, mail and network fixes), so uninstalling - even --purge -
# leaves them in place and says how to undo each one: taking them away
# automatically could open the firewall or lock someone out.
report_system_changes() {
    local found=0 file
    note() { found=1; echo "    - $1"; echo "        undo: $2"; }
    echo "==> Changes LinuStart made to the system (left in place):"
    for file in /etc/sudoers.d/linustart-*; do
        [[ -e "$file" ]] && note "sudo rule $file" "rm $file (that user loses sudo)"
    done
    [[ -e /etc/ssh/sshd_config.d/00-linustart.conf ]] && note "SSH settings /etc/ssh/sshd_config.d/00-linustart.conf" \
        "rm the file, then: systemctl reload ssh"
    [[ -e /etc/sysctl.d/99-linustart.conf ]] && note "kernel settings /etc/sysctl.d/99-linustart.conf" \
        "rm the file, then: sysctl --system"
    grep -qs '# >>> linustart firewall (managed) >>>' /etc/nftables.conf && note \
        "firewall rules (marked block in /etc/nftables.conf, table inet linustart)" \
        "delete the marked block, then: nft delete table inet linustart"
    grep -qs '# BEGIN LinuStart account' /etc/msmtprc && note "msmtp account 'linustart' in /etc/msmtprc" \
        "delete the marked block (re-enable your own 'account default' line)"
    grep -qs '# BEGIN LinuStart' /etc/dhcpcd.conf && note "dhcpcd denyinterfaces block in /etc/dhcpcd.conf" \
        "delete the marked block, then: systemctl restart dhcpcd"
    for file in /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg /etc/cloud/cloud.cfg.d/99-linustart-hostname.cfg; do
        grep -qs 'Written by LinuStart' "$file" && note "cloud-init setting $file" "rm $file"
    done
    grep -qs 'Generated by LinuStart' /etc/apt/apt.conf.d/20auto-upgrades && note \
        "automatic updates /etc/apt/apt.conf.d/20auto-upgrades" "edit or remove it (apt keeps working)"
    [[ "$found" -eq 0 ]] && echo "    (none found)"
    return 0
}

# Checked for root above: uninstalling stops and removes a systemd unit, so
# without this it failed later with a raw systemctl permission error.
if [[ "$UNINSTALL" -eq 1 ]]; then
    systemctl disable --now linustart.service 2>/dev/null || true
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload
    rm -rf "$APP_DIR"
    report_system_changes
    if [[ "$PURGE" -eq 1 ]]; then
        # Only the panel's own data: its config (token, settings) and state
        # (backups, metrics, audit log). Nothing the system runs with.
        rm -rf "$CONFIG_DIR" "$STATE_DIR"
        echo "LinuStart removed, with its configuration ($CONFIG_DIR) and state ($STATE_DIR)."
    else
        echo "LinuStart removed. Configuration in $CONFIG_DIR and state in $STATE_DIR were kept"
        echo "(use --purge to delete them as well)."
    fi
    exit 0
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required" >&2
    exit 1
fi

# --- distro check: Debian, Ubuntu, or a derivative (ID_LIKE) ---------------
if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
fi
DISTRO_FAMILY=""
for candidate in ${ID:-} ${ID_LIKE:-}; do
    case "$candidate" in
        ubuntu) DISTRO_FAMILY="ubuntu"; break ;;
        debian) DISTRO_FAMILY="debian" ;;
    esac
done
if [[ -z "$DISTRO_FAMILY" ]]; then
    echo "LinuStart supports Debian, Ubuntu and their derivatives." >&2
    echo "Found distribution ID '${ID:-unknown}' - aborting." >&2
    exit 1
fi
echo "==> Detected ${PRETTY_NAME:-$ID} ($DISTRO_FAMILY family)"

if ! command -v systemctl >/dev/null 2>&1; then
    echo "systemd is required (systemctl not found)" >&2
    exit 1
fi

echo "==> Checking for conflicting mail transfer agents"
# LinuStart delivers mail through Postfix; other MTAs that provide 'sendmail'
# (msmtp-mta, ssmtp, nullmailer, exim4, ...) would silently swallow reports.
# Client-only packages like plain 'msmtp' are harmless and left alone.
CONFLICTS=""
for pkg in msmtp-mta ssmtp nullmailer exim4 exim4-base exim4-daemon-heavy exim4-daemon-light sendmail-bin dma; do
    if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
        CONFLICTS="$CONFLICTS $pkg"
    fi
done
if [[ -n "$CONFLICTS" ]]; then
    echo "    Found:$CONFLICTS"
    echo "    These provide their own 'sendmail' and compete with LinuStart's recommended"
    echo "    Postfix setup. They are left in place for now so mail keeps working."
    echo "    The LinuStart Email page imports /etc/msmtprc, switches delivery to Postfix"
    echo "    in one step (password picked up from the msmtp password file), and offers"
    echo "    to remove these packages once Postfix is active."
fi

echo "==> Installing system dependencies"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip iproute2 unattended-upgrades >/dev/null

echo "==> Installing LinuStart into $APP_DIR"
mkdir -p "$APP_DIR" "$CONFIG_DIR" "$STATE_DIR"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Resolve, download and unpack the newest published release; echo
# "<tag>|<directory>|<workdir>". Return 1 means "fall back to the checkout",
# so an offline install never fails just because GitHub is down; return 3
# means the download failed its checksum, which must stop the install.
#
# The tag comes from the GitHub API but the download URL is built here from
# REPO and that tag, and the tag is checked against TAG_PATTERN first, so the
# only untrusted text that reaches the shell is a validated version string.
# When the release carries the workflow-built archive plus SHA256SUMS, that
# archive is downloaded and verified instead of GitHub's generated tarball.
fetch_release_info() {
    local tag archive top work meta has_assets name expected actual
    command -v curl >/dev/null 2>&1 || return 1
    work="$(mktemp -d)"
    meta="$work/release.json"
    curl -fsSL --max-time 20 \
        -H 'Accept: application/vnd.github+json' \
        -H 'User-Agent: LinuStart-Installer' \
        "https://api.github.com/repos/$REPO/releases/latest" -o "$meta" || { rm -rf "$work"; return 1; }
    tag="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1])).get("tag_name", ""))' "$meta" 2>/dev/null)" \
        || { rm -rf "$work"; return 1; }
    [[ "$tag" =~ $TAG_PATTERN ]] || { rm -rf "$work"; return 1; }
    name="linustart-${tag}.tar.gz"
    has_assets="$(python3 -c '
import json, sys
names = {a.get("name") for a in json.load(open(sys.argv[1])).get("assets") or []}
print("yes" if {sys.argv[2], "SHA256SUMS"} <= names else "no")' "$meta" "$name" 2>/dev/null || echo no)"
    if [[ "$has_assets" == "yes" ]]; then
        archive="$work/$name"
        curl -fsSL --max-time 180 -H 'User-Agent: LinuStart-Installer' \
            "https://github.com/$REPO/releases/download/$tag/$name" -o "$archive" || { rm -rf "$work"; return 1; }
        curl -fsSL --max-time 30 -H 'User-Agent: LinuStart-Installer' \
            "https://github.com/$REPO/releases/download/$tag/SHA256SUMS" -o "$work/SHA256SUMS" || { rm -rf "$work"; return 1; }
        expected="$(awk -v n="$name" '$2 == n || $2 == "*"n {print tolower($1)}' "$work/SHA256SUMS" | head -n1)"
        actual="$(sha256sum "$archive" | awk '{print $1}')"
        if [[ -z "$expected" || "$expected" != "$actual" ]]; then
            echo "    Checksum mismatch for $name (expected ${expected:-none}, got $actual)." >&2
            rm -rf "$work"
            return 3
        fi
        echo "    sha256 verified: $actual" >&2
    else
        echo "    Release $tag publishes no SHA256SUMS; the download cannot be verified." >&2
        archive="$work/release.tar.gz"
        curl -fsSL --max-time 180 -H 'User-Agent: LinuStart-Installer' \
            "https://api.github.com/repos/$REPO/tarball/$tag" -o "$archive" || { rm -rf "$work"; return 1; }
    fi
    mkdir "$work/src"
    # GNU tar refuses absolute paths and '..' members, so unpacking is safe.
    tar -xzf "$archive" -C "$work/src" || { rm -rf "$work"; return 1; }
    top="$(find "$work/src" -mindepth 1 -maxdepth 1 -type d | head -n1)"
    if [[ -z "$top" || ! -f "$top/linustart/__init__.py" || ! -f "$top/pyproject.toml" ]]; then
        rm -rf "$work"
        return 1
    fi
    printf '%s|%s|%s\n' "$tag" "$top" "$work"
}

SOURCE_TREE="$SCRIPT_DIR"
RELEASE_TAG=""
RELEASE_WORK=""
if [[ "$FROM_SOURCE" -eq 0 ]]; then
    echo "    Looking for the latest $REPO release..."
    FETCH_STATUS=0
    RELEASE_INFO="$(fetch_release_info)" || FETCH_STATUS=$?
    if [[ "$FETCH_STATUS" -eq 0 ]]; then
        RELEASE_TAG="${RELEASE_INFO%%|*}"
        RELEASE_REST="${RELEASE_INFO#*|}"
        SOURCE_TREE="${RELEASE_REST%%|*}"
        RELEASE_WORK="${RELEASE_REST#*|}"
        echo "    Installing release $RELEASE_TAG"
    elif [[ "$FETCH_STATUS" -eq 3 ]]; then
        echo "error: the release download failed verification; refusing to install it." >&2
        echo "       Re-run later, or use --source to install this checkout deliberately." >&2
        exit 1
    else
        echo "    Could not fetch a release, installing this checkout instead." >&2
    fi
else
    echo "    --source: installing this checkout as-is"
fi

# .git is never copied: an installed tree is a release, not a working tree,
# and the panel refuses to self-update a directory that still looks like one.
rsync -a --delete --exclude venv --exclude __pycache__ --exclude .git "$SOURCE_TREE"/ "$SRC_DIR"/ 2>/dev/null \
    || (rm -rf "$SRC_DIR" && mkdir -p "$SRC_DIR" && cp -r "$SOURCE_TREE"/. "$SRC_DIR"/)
rm -rf "$SRC_DIR/.git"
if [[ -n "$RELEASE_WORK" ]]; then
    rm -rf "$RELEASE_WORK"
fi

# The release tag is the version: stamp it into the tree, which matters when
# GitHub's source tarball (not the workflow-built archive) was installed.
# RELEASE_TAG passed TAG_PATTERN, so it holds only [0-9A-Za-z.-].
if [[ -n "$RELEASE_TAG" ]]; then
    sed -i "s/^__version__ = \".*\"/__version__ = \"${RELEASE_TAG#[vV]}\"/" "$SRC_DIR/linustart/__init__.py"
fi

INSTALLED_VERSION="$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$SRC_DIR/linustart/__init__.py" | head -n1)"
echo "    Installed version ${INSTALLED_VERSION:-unknown}${RELEASE_TAG:+ (release $RELEASE_TAG)}"

if [[ ! -d "$VENV_DIR" ]]; then
    python3 -m venv "$VENV_DIR"
fi
"$VENV_DIR/bin/pip" install --quiet --upgrade pip
"$VENV_DIR/bin/pip" install --quiet "$SRC_DIR"

BIND_HOST="$DEFAULT_HOST"
BIND_PORT="$DEFAULT_PORT"
if [[ ! -f "$CONFIG_FILE" ]]; then
    BIND_HOST="${HOST:-$DEFAULT_HOST}"
    BIND_PORT="${PORT:-$DEFAULT_PORT}"
    TOKEN=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')
    cat > "$CONFIG_FILE" <<EOF
{
  "host": "$BIND_HOST",
  "port": $BIND_PORT,
  "auth_token": "$TOKEN"
}
EOF
    chmod 600 "$CONFIG_FILE"
    echo ""
    echo "    Access token (also stored in $CONFIG_FILE):"
    echo "    $TOKEN"
    echo ""
else
    echo "==> Keeping existing $CONFIG_FILE"
    if [[ "$HOST_SET" -eq 1 || "$PORT_SET" -eq 1 ]]; then
        python3 - "$CONFIG_FILE" "$HOST" "$PORT" <<'PY'
import json
import sys

path, host, port = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, encoding="utf-8") as handle:
    config = json.load(handle)
if host:
    config["host"] = host
if port:
    config["port"] = int(port)
with open(path, "w", encoding="utf-8") as handle:
    json.dump(config, handle, indent=2)
    handle.write("\n")
PY
        echo "    Listen address updated"
        RESTART_NEEDED=1
    fi
fi

# A non-loopback bind must have a token; a config written by an older
# install may predate token generation, and the service refuses to start
# without one - so generate it here rather than fail at boot.
read -r BIND_HOST BIND_PORT TOKEN < <(python3 - "$CONFIG_FILE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    config = json.load(handle)
print(config.get("host", "127.0.0.1"), config.get("port", 8765), config.get("auth_token", ""))
PY
)

if ! is_loopback "$BIND_HOST" && [[ -z "$TOKEN" ]]; then
    TOKEN=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')
    python3 - "$CONFIG_FILE" "$TOKEN" <<'PY'
import json
import sys

path, token = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8") as handle:
    config = json.load(handle)
config["auth_token"] = token
with open(path, "w", encoding="utf-8") as handle:
    json.dump(config, handle, indent=2)
    handle.write("\n")
PY
    chmod 600 "$CONFIG_FILE"
    echo ""
    echo "    A new access token was generated (also stored in $CONFIG_FILE):"
    echo "    $TOKEN"
    echo ""
fi

# --- reverse proxy detection: trusted_proxies -------------------------------
# A proxy in front of the panel makes every request arrive from the proxy's own
# address, so unless the panel is told to believe that proxy's X-Forwarded-For
# every visitor shares one access-token lockout and one guesser locks out the
# rest. Only a proxy whose own configuration forwards to this port counts: an
# nginx fronting something else must not change the panel's settings.
proxy_config_files() {
    local file
    for file in /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/* \
        /etc/caddy/Caddyfile /etc/caddy/conf.d/*.caddyfile \
        /etc/apache2/apache2.conf /etc/apache2/conf-enabled/*.conf /etc/apache2/sites-enabled/* \
        /etc/haproxy/haproxy.cfg /etc/traefik/*.yml /etc/traefik/*.yaml /etc/traefik/*.toml; do
        if [[ -f "$file" ]]; then
            printf '%s\n' "$file"
        fi
    done
}

proxy_name() {
    case "$1" in
        */nginx/*) printf 'nginx' ;;
        */caddy/*) printf 'Caddy' ;;
        */apache2/*) printf 'Apache' ;;
        */haproxy/*) printf 'HAProxy' ;;
        */traefik/*) printf 'Traefik' ;;
        *) printf 'a reverse proxy' ;;
    esac
}

# Lines of <file> that forward to <port>: the proxy directive is what counts,
# not any mention of the number (a listen port or a log name is not a proxy).
proxy_forward_lines() {
    grep -iE '(proxy_pass|reverse_proxy|proxypass|server[[:space:]]|backend[[:space:]]|url:)[^#]*:'"$2"'([^0-9]|$)' \
        "$1" 2>/dev/null || true
}

# "<name>|<file>" for every proxy configured to forward to <port>.
detect_reverse_proxies() {
    local port="$1" file
    while IFS= read -r file; do
        if [[ -n "$(proxy_forward_lines "$file" "$port")" ]]; then
            printf '%s|%s\n' "$(proxy_name "$file")" "$file"
        fi
    done < <(proxy_config_files)
}

# Addresses such a proxy connects to the panel from: the literal IPv4 in its
# forward target, or loopback when that target is localhost or a hostname.
proxy_addresses() {
    local port="$1" file targets addresses address
    while IFS= read -r file; do
        targets="$(proxy_forward_lines "$file" "$port")"
        if [[ -z "$targets" ]]; then
            continue
        fi
        addresses="$(printf '%s\n' "$targets" \
            | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}:'"$port" \
            | cut -d: -f1 | sort -u || true)"
        if [[ -z "$addresses" ]]; then
            printf '127.0.0.1/32\n::1/128\n'
            continue
        fi
        while IFS= read -r address; do
            case "$address" in
                0.0.0.0|127.*) printf '127.0.0.1/32\n::1/128\n' ;;
                *) printf '%s/32\n' "$address" ;;
            esac
        done <<< "$addresses"
    done < <(proxy_config_files)
}
# --- end reverse proxy detection --------------------------------------------

# The panel itself is the authority on which proxies it believes; the installer
# only offers what it can see, and never edits an existing setting by itself -
# --trusted-proxy is the operator saying what to trust, so that is applied.
EXISTING_TRUSTED=""
if [[ -f "$CONFIG_FILE" ]]; then
    EXISTING_TRUSTED="$(python3 - "$CONFIG_FILE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    value = json.load(handle).get("trusted_proxies")
if isinstance(value, str):
    value = [value]
print(", ".join(str(item) for item in value) if isinstance(value, list) else "")
PY
)"
fi

# The ["a", "b"] form of a list, for the messages and the hand-add hint.
trusted_shown() {
    local shown
    shown="$(printf '"%s", ' "$@")"
    printf '[%s]' "${shown%, }"
}

# Add addresses to trusted_proxies, keeping every entry already there, and say
# what happened. Returns non-zero (having printed the line to add by hand) when
# the config could not be written.
add_trusted_proxies() {
    local shown added status=0
    shown="$(trusted_shown "$@")"
    # Prints how many addresses were new; ``added`` is captured, not shown.
    added="$(python3 - "$CONFIG_FILE" "$@" <<'MERGE'
import json
import os
import sys
import tempfile

path, *addresses = sys.argv[1:]
with open(path, encoding="utf-8") as handle:
    config = json.load(handle)
current = config.get("trusted_proxies")
if isinstance(current, str):
    current = [current]
if not isinstance(current, list):
    current = []
merged = [str(item) for item in current]
for address in addresses:
    if address not in merged:
        merged.append(address)
if len(merged) == len(current):
    print(0)
    sys.exit(0)
config["trusted_proxies"] = merged
# Written beside the file and renamed into place: an interrupted install must
# not leave a half-written config that the service cannot start from.
handle, temporary = tempfile.mkstemp(dir=os.path.dirname(path) or ".", prefix=".linustart-")
with os.fdopen(handle, "w", encoding="utf-8") as out:
    json.dump(config, out, indent=2)
    out.write("\n")
os.chmod(temporary, 0o600)
os.replace(temporary, path)
print(len(merged) - len(current))
MERGE
)" || status=$?
    if [[ "$status" -ne 0 ]]; then
        echo "    Could not update $CONFIG_FILE; add this line by hand:" >&2
        echo "      \"trusted_proxies\": $shown" >&2
        return 1
    fi
    if [[ "$added" == 0 ]]; then
        echo "    Already in trusted_proxies: $shown"
        return 0
    fi
    # An upgrade has a unit running with the old config already.
    if [[ -f "$SERVICE_FILE" ]]; then
        RESTART_NEEDED=1
    fi
    echo "    Added $shown to trusted_proxies"
}

# Addresses given on the command line are trusted without a prompt: that is what
# lets an unattended install opt in instead of being told to edit the config.
# Detection is skipped for the same reason - the operator has already said which
# proxies face the panel.
DETECTED_PROXIES=""
if [[ "$TRUSTED_FLAG" -eq 0 && -z "$EXISTING_TRUSTED" ]]; then
    DETECTED_PROXIES="$(detect_reverse_proxies "$BIND_PORT")"
fi
if [[ "$TRUSTED_FLAG" -eq 1 ]]; then
    echo "==> Trusting the reverse proxies named on the command line"
    add_trusted_proxies "${TRUSTED_PROXIES[@]}" || true
elif [[ -n "$EXISTING_TRUSTED" ]]; then
    echo "==> Reverse proxies already trusted ($EXISTING_TRUSTED); leaving $CONFIG_FILE alone"
elif [[ -n "$DETECTED_PROXIES" ]]; then
    echo "==> Reverse proxy in front of port $BIND_PORT"
    while IFS='|' read -r PROXY_NAME PROXY_FILE; do
        if [[ -n "$PROXY_NAME" ]]; then
            echo "    $PROXY_NAME forwards to the panel ($PROXY_FILE)"
        fi
    done <<< "$DETECTED_PROXIES"

    TRUSTED=()
    while IFS= read -r address; do
        if [[ -z "$address" ]]; then
            continue
        fi
        case " ${TRUSTED[*]-} " in
            *" $address "*) ;;
            *) TRUSTED+=("$address") ;;
        esac
    done < <(proxy_addresses "$BIND_PORT")
    if [[ ${#TRUSTED[@]} -eq 0 ]]; then
        TRUSTED=("127.0.0.1/32" "::1/128")
    fi
    TRUSTED_SHOWN="$(trusted_shown "${TRUSTED[@]}")"
    TRUSTS_LOOPBACK=0
    for address in "${TRUSTED[@]}"; do
        case "$address" in
            127.*|::1/*) TRUSTS_LOOPBACK=1 ;;
        esac
    done

    echo "    The panel sees the proxy's address instead of each visitor's, so"
    echo "    without this list all visitors share one lockout and one wrong-token"
    echo "    guesser locks out the rest."
    if [[ "$TRUSTS_LOOPBACK" -eq 1 ]]; then
        echo "    Loopback is also where SSH tunnels arrive, so this trusts them too."
    fi
    if [[ -t 0 ]]; then
        read -r -p "    Believe X-Forwarded-For from ${TRUSTED[*]}? [y/N] " reply
        if [[ "${reply,,}" == y* ]]; then
            add_trusted_proxies "${TRUSTED[@]}" || true
        else
            echo "    Left alone. Per-client throttling needs this list, so add it"
            echo "    later if a proxy really faces the panel (see the README)."
        fi
    else
        echo "    Non-interactive install; add this line to $CONFIG_FILE and"
        echo "    restart the service (systemctl restart linustart) if it applies:"
        echo "      \"trusted_proxies\": $TRUSTED_SHOWN"
    fi
fi

echo "==> Installing systemd service"
cp "$SRC_DIR/systemd/linustart.service" "$SERVICE_FILE"
systemctl daemon-reload
systemctl enable --now linustart.service
# `enable --now` leaves an already-running service alone, so a changed listen
# address would not take effect until someone restarts it by hand.
if [[ "$RESTART_NEEDED" -eq 1 ]]; then
    systemctl restart linustart.service
    echo "    Service restarted to apply the new listen address"
fi

lan_ip() {
    local address
    address=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == "src") {print $(i + 1); exit}}' || true)
    if [[ -z "$address" ]]; then
        address=$(hostname -I 2>/dev/null | awk '{print $1}' || true)
    fi
    printf '%s' "$address"
}

if ! is_loopback "$BIND_HOST"; then
    echo "==> Opening the firewall"
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        if ufw status 2>/dev/null | grep -qE "^${BIND_PORT}(/tcp)?[[:space:]]"; then
            echo "    ufw already allows port $BIND_PORT"
        elif [[ -t 0 ]]; then
            read -r -p "    Allow LAN access to port ${BIND_PORT}? [y/N] " reply
            if [[ "${reply,,}" == y* ]]; then
                ufw allow "${BIND_PORT}/tcp" comment "LinuStart panel" >/dev/null
                echo "    Opened ${BIND_PORT}/tcp in ufw"
            else
                echo "    Left closed. Open it later with: ufw allow ${BIND_PORT}/tcp"
            fi
        else
            echo "    Non-interactive install; open the port yourself for LAN access:"
            echo "      ufw allow ${BIND_PORT}/tcp"
        fi
    elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        echo "    firewalld is active; allow the port with:"
        echo "      firewall-cmd --permanent --add-port=${BIND_PORT}/tcp && firewall-cmd --reload"
    else
        echo "    No ufw or firewalld found; check that port ${BIND_PORT} is reachable."
    fi
fi

echo ""
echo "LinuStart is running."
if is_loopback "$BIND_HOST"; then
    echo "  Local URL:  http://127.0.0.1:${BIND_PORT}"
    echo "  From your workstation, forward the port instead of opening it publicly:"
    echo "    ssh -L ${BIND_PORT}:127.0.0.1:${BIND_PORT} user@this-server"
    echo "  Then open http://127.0.0.1:${BIND_PORT} in your browser."
else
    LAN_IP="$(lan_ip)"
    echo "  On this server:  http://127.0.0.1:${BIND_PORT}"
    if [[ -n "$LAN_IP" ]]; then
        echo "  On your LAN:     http://${LAN_IP}:${BIND_PORT}"
    fi
    echo "  From outside the LAN, tunnel rather than opening it publicly:"
    echo "    ssh -L ${BIND_PORT}:127.0.0.1:${BIND_PORT} user@this-server"
    echo ""
    echo "  Token authentication is required (see $CONFIG_FILE)."
    echo "  This is a root-level admin panel served over plain HTTP: keep it on a"
    echo "  trusted network, or put a TLS reverse proxy in front of it."
    echo "  To go back to loopback-only, re-run: ./install.sh --loopback"
fi
