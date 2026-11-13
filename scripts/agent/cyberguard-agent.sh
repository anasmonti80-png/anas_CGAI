#!/usr/bin/env bash
# CG-010 optional read-only Linux agent. Explicitly invoked (or scheduled by an administrator) on a
# managed device. Collects: auditd, journald and syslog channel health, services (systemd), processes
# (names only, no command lines) and AV/EDR status (ClamAV / Falco / common EDR services).
# Changes nothing, opens no network connection and stores no credential.
# Output: a cg.telemetry/1 file with one agent.inventory_report event. No upload performed.
# Usage: cyberguard-agent.sh <output.json> <enrolled-by-ref> [report-interval-minutes]
set -u
out="${1:?output path required}"; enrolled="${2:?enrolled-by reference required}"; interval="${3:-60}"
[ -e "$out" ] && { echo 'Output already exists. Choose a new private file path.' >&2; exit 1; }
[ -d "$(dirname "$out")" ] || { echo 'Output directory must exist and be private.' >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }
esc() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr -d '\000-\037'; }
iso() { date -u +%Y-%m-%dT%H:%M:%S.000Z; }
now="$(iso)"

channel() { # name status events reason
  local events="null" reason="null"
  [ -n "$3" ] && events="$3"
  [ -n "$4" ] && reason="\"$(esc "$4")\""
  printf '{"channel":"%s","status":"%s","events_last_hour":%s,"last_event_at":null,"reason":%s}' "$1" "$2" "$events" "$reason"
}
# auditd
if have auditctl || [ -e /var/log/audit/audit.log ]; then
  if [ -r /var/log/audit/audit.log ]; then
    since=$(( $(date +%s) - 3600 )); n=$(awk -v s="$since" -F'[(:.]' '/^type=/{ if ($3+0 >= s) c++ } END{print c+0}' /var/log/audit/audit.log 2>/dev/null)
    ch_audit="$(channel linux-auditd collected "${n:-0}" "")"
  else ch_audit="$(channel linux-auditd access-denied "" "Reading /var/log/audit/audit.log requires root or the adm group.")"; fi
else ch_audit="$(channel linux-auditd not-installed "" "auditd is not installed on this device.")"; fi
# journald
if have journalctl; then
  n=$(journalctl --since "-1h" -q 2>/dev/null | wc -l | tr -d ' ')
  if journalctl -n 1 -q >/dev/null 2>&1; then ch_journal="$(channel linux-journald collected "${n:-0}" "")"
  else ch_journal="$(channel linux-journald access-denied "" "Reading the system journal requires the systemd-journal or adm group.")"; fi
else ch_journal="$(channel linux-journald not-installed "" "systemd-journald is not present on this device.")"; fi
# syslog
syslog=""; for f in /var/log/syslog /var/log/messages; do [ -e "$f" ] && { syslog="$f"; break; }; done
if [ -n "$syslog" ]; then
  if [ -r "$syslog" ]; then ch_syslog="$(channel linux-syslog collected "$(tail -n 5000 "$syslog" 2>/dev/null | wc -l | tr -d ' ')" "")"
  else ch_syslog="$(channel linux-syslog access-denied "" "Reading $syslog requires the adm group.")"; fi
else ch_syslog="$(channel linux-syslog not-installed "" "No /var/log/syslog or /var/log/messages on this device.")"; fi

# services (systemd) and processes (names only)
svc_items=""; svc_total=0; svc_running=0
if have systemctl; then
  while read -r unit load active sub _; do
    [ -z "${unit:-}" ] && continue; name="${unit%.service}"; svc_total=$((svc_total+1)); [ "$sub" = "running" ] && svc_running=$((svc_running+1))
    [ "$svc_total" -le 1000 ] && svc_items="${svc_items}${svc_items:+,}{\"name\":\"$(esc "$name")\",\"state\":\"$(esc "$sub")\",\"start_mode\":\"unknown\"}"
  done < <(systemctl list-units --type=service --all --no-legend --plain 2>/dev/null)
fi
proc_items=""; proc_total=0
while read -r pid comm; do
  [ -z "${pid:-}" ] && continue; case "$pid" in ''|*[!0-9]*) continue;; esac; proc_total=$((proc_total+1))
  [ "$proc_total" -le 2000 ] && proc_items="${proc_items}${proc_items:+,}{\"name\":\"$(esc "$comm")\",\"pid\":$pid}"
done < <(ps -eo pid=,comm= 2>/dev/null)

# protection products
prot=""
add_prot() { prot="${prot}${prot:+,}{\"name\":\"$(esc "$1")\",\"type\":\"$2\",\"state\":\"$3\",\"signatures_age_days\":$4,\"realtime\":null}"; }
svc_state() { if have systemctl && systemctl is-active --quiet "$1" 2>/dev/null; then echo on; elif have systemctl && systemctl list-unit-files "$1.service" --no-legend 2>/dev/null | grep -q .; then echo off; else echo absent; fi; }
for s in clamav-daemon:av:ClamAV falco:edr:Falco mdatp:edr:"Microsoft Defender for Endpoint" falcon-sensor:edr:"CrowdStrike Falcon" ufw:firewall:UFW firewalld:firewall:firewalld; do
  unit="${s%%:*}"; rest="${s#*:}"; type="${rest%%:*}"; label="${rest#*:}"; st="$(svc_state "$unit")"
  [ "$st" = "absent" ] && continue
  age=null; if [ "$unit" = "clamav-daemon" ] && [ -e /var/lib/clamav/daily.cvd ]; then age=$(( ( $(date +%s) - $(stat -c %Y /var/lib/clamav/daily.cvd) ) / 86400 )); fi
  add_prot "$label" "$type" "$st" "$age"
done

host="$(hostname 2>/dev/null || uname -n)"
key="$(printf '%s|linux' "$host" | sha256sum 2>/dev/null | cut -c1-24)"
addrs=""; if have hostname; then for a in $(hostname -I 2>/dev/null); do case "$a" in 10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*) addrs="${addrs}${addrs:+,}\"$a\"";; esac; done; fi
cat > "$out" <<JSON
{"schema_version":"cg.telemetry/1","events":[{"event_id":"agent-$(cat /proc/sys/kernel/random/uuid 2>/dev/null || date +%s%N)","kind":"agent.inventory_report","observed_at":"$now","asset":{"external_id":"managed-$key","hostname":"$(esc "$host")","os_family":"linux","device_type":"server","addresses":[$addrs]},"details":{"agent_id":"cg-agent-linux-$key","agent_version":"1.0.0","platform":"linux","enrollment":{"mode":"optional","enrolled_by_ref":"$(esc "$enrolled")","report_interval_minutes":$interval},"channels":[$ch_audit,$ch_journal,$ch_syslog],"services":{"total":$svc_total,"running":$svc_running,"items":[$svc_items]},"processes":{"total":$proc_total,"items":[$proc_items]},"protection":[$prot]}}]}
JSON
echo "Agent report written: $svc_total services, $proc_total processes. No upload performed."
