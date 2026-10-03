#!/usr/bin/env bash
#
# LinuStart installer for Debian, Ubuntu and derivatives (anything in the
# Debian family, detected via /etc/os-release).
#
# Usage:
#   sudo ./install.sh              # install (or upgrade in place)
#   sudo ./install.sh --uninstall  # remove the service and files
#
set -euo pipefail

APP_DIR=/opt/linustart
VENV_DIR="$APP_DIR/venv"
SRC_DIR="$APP_DIR/app"
CONFIG_DIR=/etc/linustart
CONFIG_FILE="$CONFIG_DIR/config.json"
SERVICE_FILE=/etc/systemd/system/linustart.service
STATE_DIR=/var/lib/linustart

if [[ "${1:-}" == "--uninstall" ]]; then
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
rsync -a --delete --exclude venv --exclude __pycache__ "$SCRIPT_DIR"/ "$SRC_DIR"/ 2>/dev/null \
    || (rm -rf "$SRC_DIR" && mkdir -p "$SRC_DIR" && cp -r "$SCRIPT_DIR"/. "$SRC_DIR"/)

if [[ ! -d "$VENV_DIR" ]]; then
    python3 -m venv "$VENV_DIR"
fi
"$VENV_DIR/bin/pip" install --quiet --upgrade pip
"$VENV_DIR/bin/pip" install --quiet "$SRC_DIR"

if [[ ! -f "$CONFIG_FILE" ]]; then
    TOKEN=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')
    cat > "$CONFIG_FILE" <<EOF
{
  "host": "127.0.0.1",
  "port": 8765,
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
fi

echo "==> Installing systemd service"
cp "$SRC_DIR/systemd/linustart.service" "$SERVICE_FILE"
systemctl daemon-reload
systemctl enable --now linustart.service

echo ""
echo "LinuStart is running."
echo "  Local URL:  http://127.0.0.1:8765"
echo "  From your workstation, forward the port instead of opening it publicly:"
echo "    ssh -L 8765:127.0.0.1:8765 user@this-server"
echo "  Then open http://127.0.0.1:8765 in your browser."
echo ""
echo "To expose it directly, edit the 'host' value in $CONFIG_FILE"
echo "(token authentication is required for non-loopback binds) and run:"
echo "    systemctl restart linustart"
