<#
CG-021 read-only network configuration snapshot of this Windows host: OS build (patch level), DNS and
NTP servers, VPN profiles and management-plane services (RDP, WinRM, OpenSSH, SNMP) with whether a
firewall rule exposes them to any address. Stores no secret. Changes nothing. No upload performed.
#>
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$OutputPath)
$ErrorActionPreference = 'Stop'
$destination = [System.IO.Path]::GetFullPath($OutputPath)
if (Test-Path -LiteralPath $destination) { throw 'Output already exists. Choose a new private file path.' }
if (-not (Test-Path -LiteralPath (Split-Path -Parent $destination) -PathType Container)) { throw 'Output directory must exist and be private.' }
$os = Get-CimInstance Win32_OperatingSystem; $cs = Get-CimInstance Win32_ComputerSystem
$ubr = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).UBR
$firmware = if ($ubr) { "$($os.Version).$ubr" } else { [string]$os.Version }
$dns = [object[]]@(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ } | Select-Object -Unique)
$ntp = [object[]]@(((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' -ErrorAction SilentlyContinue).NtpServer -split '\s+') | Where-Object { $_ } | ForEach-Object { ($_ -split ',')[0] } | Select-Object -Unique)
$vpn = [object[]]@(@(Get-VpnConnection -ErrorAction SilentlyContinue) + @(Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue) | Where-Object { $_ } | ForEach-Object { [ordered]@{ name = [string]$_.Name; peer = [string]$_.ServerAddress; protocol = ([string]$_.TunnelType).ToLower() } })
function Test-OpenToAny([string]$group) {
    try { foreach ($r in @(Get-NetFirewallRule -DisplayGroup $group -Direction Inbound -Enabled True -Action Allow -ErrorAction Stop)) { $a = $r | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue; if ($a -and ([string]$a.RemoteAddress -eq 'Any')) { return 'any' } }; return 'internal' } catch { return 'unknown' }
}
$rdpEnabled = ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue).fDenyTSConnections -eq 0)
$svc = { param($name) $s = Get-Service -Name $name -ErrorAction SilentlyContinue; return ($s -and $s.Status -eq 'Running') }
$management = [object[]]@(
    [ordered]@{ protocol = 'rdp'; enabled = $rdpEnabled; exposed_to = $(if ($rdpEnabled) { Test-OpenToAny 'Remote Desktop' } else { 'unknown' }); restricted_sources = $false },
    [ordered]@{ protocol = 'winrm'; enabled = (& $svc 'WinRM'); exposed_to = $(if (& $svc 'WinRM') { Test-OpenToAny 'Windows Remote Management' } else { 'unknown' }); restricted_sources = $false },
    [ordered]@{ protocol = 'ssh'; enabled = (& $svc 'sshd'); exposed_to = $(if (& $svc 'sshd') { Test-OpenToAny 'OpenSSH Server' } else { 'unknown' }); restricted_sources = $false },
    [ordered]@{ protocol = 'snmpv2c'; enabled = (& $svc 'SNMP'); exposed_to = 'unknown'; restricted_sources = $false }
)
$hostName = [System.Net.Dns]::GetHostName()
$sha = [System.Security.Cryptography.SHA256]::Create()
$hostKey = (($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($hostName + '|windows')) | ForEach-Object { $_.ToString('x2') }) -join '').Substring(0, 24)
$details = [ordered]@{ snapshot_id = 'hostcfg-' + [guid]::NewGuid(); device_ref = 'windows-host:' + $hostName; device_type = 'windows-host'; vendor = ([string]$cs.Manufacturer).Trim(); model = ([string]$cs.Model).Trim(); firmware_version = $firmware; dns_servers = $dns; ntp_servers = $ntp; vpn_profiles = $vpn; management = $management; config_sha256 = $null }
$now = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
$event = [ordered]@{ event_id = 'hostcfg-' + [guid]::NewGuid(); kind = 'network.device_config'; observed_at = $now; asset = [ordered]@{ external_id = 'managed-' + $hostKey; hostname = $hostName; os_family = 'windows'; device_type = 'workstation'; addresses = @() }; details = $details }
[System.IO.File]::WriteAllText($destination, ([ordered]@{ schema_version = 'cg.telemetry/1'; events = @($event) } | ConvertTo-Json -Depth 8), (New-Object System.Text.UTF8Encoding($false)))
Write-Output ('Host network configuration written: build {0}, {1} DNS servers, {2} VPN profiles, RDP enabled={3}. No upload performed.' -f $firmware, $dns.Count, $vpn.Count, $rdpEnabled)
