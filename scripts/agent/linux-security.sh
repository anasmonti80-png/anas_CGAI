#!/usr/bin/env bash
# CG-094 read-only Linux security posture collector. Run by an administrator on a managed Linux host (root gives the
# complete view; without root, unreadable items are reported as access-denied, never guessed).
# Collects: auditd state and rule count, journald access, eBPF support (kernel, BTF, unprivileged BPF setting), Falco
# state and driver, sudo configuration (sudoers fingerprints, NOPASSWD and ALL grants, sudo/wheel members, sudo use in
# the last 24 hours as counts per user and command name), and fingerprints of cron and systemd unit/timer files.
# Changes nothing, opens no network connection, stores no credential, and records file fingerprints, not contents.
# Usage: linux-security.sh <output.json> <enrolled-by-ref>
set -u
out="${1:?output path required}"; enrolled="${2:?enrolled-by reference required}"
[ -e "$out" ] && { echo 'Output already exists. Choose a new private file path.' >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }
esc() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr -d '\000-\037'; }
now="$(date -u +%Y-%m-%dT%H:%M:%S.000Z)"
root=false; [ "$(id -u)" = "0" ] && root=true

# auditd
audit_state=not-installed; audit_rules=null
if have auditctl || [ -e /etc/audit/auditd.conf ]; then
  if have systemctl && systemctl is-active --quiet auditd 2>/dev/null; then audit_state=running; else audit_state=stopped; fi
  if $root && have auditctl; then audit_rules=$(auditctl -l 2>/dev/null | grep -vc '^No rules' ); fi
fi
# journald
journal_state=not-installed
if have journalctl; then if journalctl -n 1 -q >/dev/null 2>&1; then journal_state=readable; else journal_state=access-denied; fi; fi
# eBPF support where the kernel allows it
kernel="$(uname -r)"; btf=false; [ -e /sys/kernel/btf/vmlinux ] && btf=true
unpriv="$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo unknown)"
kmaj="${kernel%%.*}"; krest="${kernel#*.}"; kmin="${krest%%.*}"; kmin="${kmin%%[!0-9]*}"
ebpf=not-supported; ebpf_reason="kernel $kernel"
if [ "${kmaj:-0}" -gt 5 ] || { [ "${kmaj:-0}" -eq 5 ] && [ "${kmin:-0}" -ge 8 ]; }; then
  if $btf; then ebpf=supported; ebpf_reason="kernel $kernel with BTF"; else ebpf=limited; ebpf_reason="kernel $kernel without BTF (/sys/kernel/btf/vmlinux missing)"; fi
else ebpf_reason="kernel $kernel is older than 5.8; modern eBPF probes are not available"; fi
# Falco
falco_state=not-installed; falco_driver=null
for u in falco falco-modern-bpf falco-bpf falco-kmod; do
  if have systemctl && systemctl list-unit-files "$u.service" --no-legend 2>/dev/null | grep -q .; then
    if systemctl is-active --quiet "$u" 2>/dev/null; then falco_state=running; falco_driver="\"$u\""; break; else falco_state=stopped; falco_driver="\"$u\""; fi
  fi
done
[ "$falco_state" = "not-installed" ] && have falco && falco_state=stopped

# fingerprints: path + sha256 (contents are never copied)
files_json() { local first=1 f h; for f in "$@"; do [ -f "$f" ] || continue
    if [ -r "$f" ]; then h="$(sha256sum "$f" 2>/dev/null | cut -c1-64)"; [ $first -eq 1 ] || printf ','; first=0; printf '{"path":"%s","sha256":"%s"}' "$(esc "$f")" "$h"
    else [ $first -eq 1 ] || printf ','; first=0; printf '{"path":"%s","sha256":null}' "$(esc "$f")"; fi; done; }
shopt -s nullglob
sudoers="$(files_json /etc/sudoers /etc/sudoers.d/*)"
cron="$(files_json /etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* /var/spool/cron/crontabs/* /var/spool/cron/*)"
units="$(files_json /etc/systemd/system/*.service /etc/systemd/system/*.timer /etc/systemd/system/*/*.service /lib/systemd/system/*.timer /usr/lib/systemd/system/*.timer)"
# sudo grants (only readable files): NOPASSWD lines and full ALL grants, as counts
nopasswd=null; allgrants=null
if [ -r /etc/sudoers ]; then
  nopasswd=$(cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -v '^\s*#' | grep -c 'NOPASSWD')
  allgrants=$(cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -v '^\s*#' | grep -Ec '^\s*[^#%[:space:]][^=]*\sALL\s*=\s*\(ALL(:ALL)?\)\s*(NOPASSWD:\s*)?ALL\s*$')
fi
members=""; for g in sudo wheel admin; do m="$(getent group "$g" 2>/dev/null | cut -d: -f4)"; [ -n "$m" ] && members="${members}${members:+,}{\"group\":\"$g\",\"members\":[$(printf '%s' "$m" | tr ',' '\n' | sed '/^$/d' | while read -r u; do printf '"%s",' "$(esc "$u")"; done | sed 's/,$//')]}"; done
# sudo use in the last 24 hours: counts per user and command name (no arguments)
sudo_use=""; sudo_state=not-readable
if [ "$journal_state" = "readable" ]; then sudo_state=journald
  sudo_use="$(journalctl _COMM=sudo --since '-24h' -o cat -q 2>/dev/null | sed -n 's/^ *\([A-Za-z0-9._-]*\) : .*USER=\([A-Za-z0-9._-]*\) ; COMMAND=\([^ ]*\).*/\1 \2 \3/p' | awk '{n=split($3,p,"/"); print $1" "$2" "p[n]}' | sort | uniq -c | head -200 | while read -r c u t cmd; do printf '{"user":"%s","as":"%s","command":"%s","count":%s},' "$(esc "$u")" "$(esc "$t")" "$(esc "$cmd")" "$c"; done | sed 's/,$//')"
fi

host="$(hostname 2>/dev/null || uname -n)"; key="$(printf '%s|linux' "$host" | sha256sum | cut -c1-24)"
cat > "$out" <<JSON
{"schema_version":"cg.telemetry/1","events":[{"event_id":"linuxsec-$(cat /proc/sys/kernel/random/uuid 2>/dev/null || date +%s%N)","kind":"linux.security_posture","observed_at":"$now","asset":{"external_id":"managed-$key","hostname":"$(esc "$host")","os_family":"linux","device_type":"server","addresses":[]},"details":{"enrolled_by":"$(esc "$enrolled")","collected_as_root":$root,"kernel":"$(esc "$kernel")","auditd":{"state":"$audit_state","rules":$audit_rules},"journald":"$journal_state","ebpf":{"state":"$ebpf","btf":$btf,"unprivileged_bpf_disabled":"$(esc "$unpriv")","reason":"$(esc "$ebpf_reason")"},"falco":{"state":"$falco_state","unit":$falco_driver},"sudo":{"sudoers":[$sudoers],"no_prompt_rules":$nopasswd,"full_all_grants":$allgrants,"groups":[$members],"use_source":"$sudo_state","use_24h":[$sudo_use]},"cron":[$cron],"systemd_units":[$units]}}]}
JSON
echo "Linux security posture written (root: $root, auditd: $audit_state, eBPF: $ebpf, Falco: $falco_state). No upload performed."
