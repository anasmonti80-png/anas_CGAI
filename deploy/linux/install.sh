#!/bin/sh
# Install CyberGuard AI on Linux (Debian/Ubuntu, RHEL/Fedora, Kali and other systemd distributions).
# Usage: sudo sh deploy/linux/install.sh [--prefix /opt/cyberguard] [--no-service]
# Needs Node.js 24 (node -v). Data stays in /var/lib/cyberguard, owned by a dedicated system user, listening on
# 127.0.0.1:4310 by default (CG-054); remote access only through ZTNA or VPN settings in /etc/cyberguard/cyberguard.env (CG-053).
set -eu
PREFIX=/opt/cyberguard; SERVICE=1; ROOT=${CG_INSTALL_ROOT:-}
while [ $# -gt 0 ]; do case "$1" in --prefix) PREFIX=$2; shift 2;; --no-service) SERVICE=0; shift;; *) echo "unknown option $1" >&2; exit 2;; esac; done
SRC=$(cd "$(dirname "$0")/../.." && pwd)
command -v node >/dev/null 2>&1 || { echo "Node.js 24 is required (https://nodejs.org)" >&2; exit 1; }
MAJOR=$(node -p 'process.versions.node.split(".")[0]'); [ "$MAJOR" -ge 24 ] || { echo "Node.js 24 or newer is required, found $(node -v)" >&2; exit 1; }
mkdir -p "$ROOT$PREFIX" "$ROOT/var/lib/cyberguard" "$ROOT/etc/cyberguard"
for d in server.js package.json lib public scripts deploy docs artifacts; do cp -R "$SRC/$d" "$ROOT$PREFIX/"; done
[ -f "$ROOT/etc/cyberguard/cyberguard.env" ] || printf '%s\n' '# CyberGuard settings (see docs/OPERATIONS_AR.md)' 'CG_PORT=4310' '# CG_TLS=self-signed' '# CG_TENANT=default' '# CG_REMOTE_ACCESS=ztna|vpn' > "$ROOT/etc/cyberguard/cyberguard.env"
chmod 700 "$ROOT/var/lib/cyberguard"; chmod 600 "$ROOT/etc/cyberguard/cyberguard.env"
if [ "$SERVICE" = 1 ] && [ -z "$ROOT" ]; then
  id cyberguard >/dev/null 2>&1 || useradd --system --home-dir /var/lib/cyberguard --shell /usr/sbin/nologin cyberguard
  chown -R cyberguard:cyberguard /var/lib/cyberguard; chown root:cyberguard /etc/cyberguard/cyberguard.env; chmod 640 /etc/cyberguard/cyberguard.env
  sed -e "s#/opt/cyberguard#$PREFIX#g" -e "s#/usr/bin/env node#$(command -v node)#" "$SRC/deploy/linux/cyberguard.service" > /etc/systemd/system/cyberguard.service
  systemctl daemon-reload; systemctl enable --now cyberguard
  echo "CyberGuard is running: http://127.0.0.1:4310 (first-run token in /var/lib/cyberguard/setup-token)"
else echo "Installed to $ROOT$PREFIX (service not installed)"; fi
