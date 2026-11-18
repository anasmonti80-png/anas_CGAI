#!/bin/sh
# Add one isolated tenant instance (CG-059). Usage: sudo sh deploy/linux/add-tenant.sh <tenant-id> <port>
# The tenant runs as cyberguard@<tenant-id>.service with its own service user, /var/lib/cyberguard-tenants/<tenant-id>
# (database, secret-store key, audit chain, setup token) and settings in /etc/cyberguard/tenants/<tenant-id>.env.
# Requires deploy/linux/install.sh to have installed the application under /opt/cyberguard first.
set -eu
TENANT=${1:-}; PORT=${2:-}
echo "$TENANT" | grep -Eq '^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$' || { echo "tenant id: 3-40 lowercase letters, digits or dashes" >&2; exit 2; }
echo "$PORT" | grep -Eq '^[0-9]+$' && [ "$PORT" -ge 1024 ] && [ "$PORT" -le 65535 ] || { echo "port: 1024-65535" >&2; exit 2; }
[ -f /opt/cyberguard/server.js ] || { echo "install CyberGuard first: sudo sh deploy/linux/install.sh" >&2; exit 1; }
mkdir -p /etc/cyberguard/tenants
for f in /etc/cyberguard/tenants/*.env; do [ -f "$f" ] || continue; [ "$f" = "/etc/cyberguard/tenants/$TENANT.env" ] && continue; grep -qx "CG_PORT=$PORT" "$f" && { echo "port $PORT is already used by $(basename "$f" .env)" >&2; exit 1; }; done
grep -qx "CG_PORT=$PORT" /etc/cyberguard/cyberguard.env 2>/dev/null && { echo "port $PORT is used by the default instance" >&2; exit 1; }
[ -f "/etc/cyberguard/tenants/$TENANT.env" ] || printf '%s\n' "# Tenant $TENANT (see docs/OPERATIONS_AR.md)" "CG_PORT=$PORT" > "/etc/cyberguard/tenants/$TENANT.env"
chmod 600 "/etc/cyberguard/tenants/$TENANT.env"
sed -e "s#/usr/bin/env node#$(command -v node)#" "$(cd "$(dirname "$0")" && pwd)/cyberguard@.service" > /etc/systemd/system/cyberguard@.service
systemctl daemon-reload; systemctl enable --now "cyberguard@$TENANT"
echo "Tenant $TENANT: http://127.0.0.1:$PORT (first-run token in /var/lib/cyberguard-tenants/$TENANT/setup-token)"
