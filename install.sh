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
#   ./install.sh --uninstall         # remove the service and files
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
RESTART_NEEDED=0
# An install is a released version: cloning main gives you a tree ahead of
# every tag, so the newest release is what gets installed unless --source
# says otherwise. The panel then reports a version that matches the release
# it came from and its own "check for updates" has something to compare.
FROM_SOURCE=0
REPO="${LINUSTART_REPO:-daygle/LinuStart}"
TAG_PATTERN='^v?[0-9]+(\.[0-9]+){0,3}([-.][0-9A-Za-z.]+)?$'

usage() {
    sed -n '3,11p' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --uninstall) UNINSTALL=1 ;;
        --source)    FROM_SOURCE=1 ;;
        --loopback)  HOST="127.0.0.1"; HOST_SET=1 ;;
        --host)      HOST="${2:-}"; HOST_SET=1; shift ;;
        --port)      PORT="${2:-}"; PORT_SET=1; shift ;;
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

is_loopback() {
    case "$1" in
        127.0.0.1|localhost|::1|127.*) return 0 ;;
        *) return 1 ;;
    esac
}

if [[ "$UNINSTALL" -eq 1 ]]; then
    systemctl disable --now linustart.service 2>/dev/null || true
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload
    rm -rf "$APP_DIR"
    echo "LinuStart removed. Configuration in $CONFIG_DIR and state in $STATE_DIR were kept."
    echo "Remove them manually if you want a clean slate."
    exit 0
fi

if [[ $EUID -ne 0 ]]; then
    echo "This installer must run as root (try: sudo ./install.sh)" >&2
    exit 1
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
