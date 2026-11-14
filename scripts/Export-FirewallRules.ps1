<#
CG-020 read-only Windows Firewall ruleset export. Reads every rule with its port, address and
application filters (joined in bulk), converts Windows keywords to explicit ranges, and writes one
firewall.ruleset event. Windows Firewall evaluates block-overrides-allow, so evaluation is
deny-overrides. Changes nothing. No upload performed.
#>
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$OutputPath)
$ErrorActionPreference = 'Stop'
$destination = [System.IO.Path]::GetFullPath($OutputPath)
if (Test-Path -LiteralPath $destination) { throw 'Output already exists. Choose a new private file path.' }
if (-not (Test-Path -LiteralPath (Split-Path -Parent $destination) -PathType Container)) { throw 'Output directory must exist and be private.' }
function Get-SafeText([string]$text) { if ($null -eq $text) { return $null }; $t = ($text -replace '[\x00-\x1F\x7F]', '').Trim(); $t = $t -replace '(?i)(\\Users\\)[^\\]+', '$1[USER]'; if ($t.Length -gt 300) { $t = $t.Substring(0, 300) }; return $t }
$private = @('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7', 'fe80::/10')
function Convert-Address($values) {
    $out = @()
    foreach ($v in @($values)) {
        $s = [string]$v
        if (-not $s -or $s -eq 'Any' -or $s -eq '*' -or $s -eq 'Internet') { return @('any') }
        if ($s -in @('LocalSubnet', 'LocalSubnet4', 'LocalSubnet6', 'Intranet', 'IntranetRemoteAccess', 'DNS', 'DHCP', 'WINS', 'DefaultGateway', 'PlayToDevice', 'Captive Portal Addresses')) { $out += $private; continue }
        if ($s -match '^(\d+\.\d+\.\d+\.\d+)/(\d+\.\d+\.\d+\.\d+)$') { $mask = ([System.Net.IPAddress]::Parse($Matches[2])).GetAddressBytes(); $bits = 0; foreach ($b in $mask) { $bits += [Convert]::ToString($b, 2).Replace('0', '').Length }; $out += "$($Matches[1])/$bits"; continue }
        if ($s -match '^(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$') {
            $a = [BitConverter]::ToUInt32((([System.Net.IPAddress]::Parse($Matches[1])).GetAddressBytes())[3..0], 0); $b = [BitConverter]::ToUInt32((([System.Net.IPAddress]::Parse($Matches[2])).GetAddressBytes())[3..0], 0)
            $bits = 32; while ($bits -gt 0 -and ([math]::Floor($a / [math]::Pow(2, 32 - $bits)) -ne [math]::Floor($b / [math]::Pow(2, 32 - $bits)))) { $bits-- }
            $out += "$($Matches[1])/$bits"; continue
        }
        if ($s -match '^[0-9a-fA-F:.]+(/\d+)?$') { $out += $s; continue }
        if ($s -match '^([0-9a-fA-F:]+)-([0-9a-fA-F:]+)$') { $out += 'any'; continue }
        $out += 'any'
    }
    if ($out.Count -eq 0) { return @('any') }
    return @($out | Select-Object -Unique)
}
function Convert-Port($values) {
    $out = @()
    foreach ($v in @($values)) {
        $s = [string]$v
        if (-not $s -or $s -eq 'Any') { return @('any') }
        if ($s -match '^\d+(-\d+)?$') { $out += $s; continue }
        switch ($s) { 'RPC' { $out += '49152-65535' } 'RPCEPMap' { $out += '135' } 'IPHTTPS' { $out += '443' } 'IPHTTPSIn' { $out += '443' } 'IPHTTPSOut' { $out += '443' } 'mDNS' { $out += '5353' } default { $script:portKeyword = $s; return @('any') } }
    }
    if ($out.Count -eq 0) { return @('any') }
    return @($out | Select-Object -Unique)
}
$rules = @(Get-NetFirewallRule)
$ports = @{}; foreach ($p in @(Get-NetFirewallPortFilter -All -ErrorAction SilentlyContinue)) { $ports[$p.InstanceID] = $p }
$addrs = @{}; foreach ($a in @(Get-NetFirewallAddressFilter -All -ErrorAction SilentlyContinue)) { $addrs[$a.InstanceID] = $a }
$apps = @{}; foreach ($a in @(Get-NetFirewallApplicationFilter -All -ErrorAction SilentlyContinue)) { $apps[$a.InstanceID] = $a }
$svcs = @{}; foreach ($a in @(Get-NetFirewallServiceFilter -All -ErrorAction SilentlyContinue)) { $svcs[$a.InstanceID] = $a }
$secs = @{}; foreach ($a in @(Get-NetFirewallSecurityFilter -All -ErrorAction SilentlyContinue)) { $secs[$a.InstanceID] = $a }
$ifaces = @{}; foreach ($a in @(Get-NetFirewallInterfaceTypeFilter -All -ErrorAction SilentlyContinue)) { $ifaces[$a.InstanceID] = $a }
$i = 0
$out = @($rules | Select-Object -First 5000 | ForEach-Object {
    $r = $_; $i++
    $pf = $ports[$r.InstanceID]; $af = $addrs[$r.InstanceID]; $ap = $apps[$r.InstanceID]
    $proto = [string]$pf.Protocol; $protocol = switch -Regex ($proto) { '^(?i)any$' { 'any' } '^(?i)tcp$|^6$' { 'tcp' } '^(?i)udp$|^17$' { 'udp' } '^(?i)icmpv4$|^1$' { 'icmp' } '^(?i)icmpv6$|^58$' { 'icmpv6' } default { if ($proto) { $proto.ToLower() } else { 'any' } } }
    $inbound = [string]$r.Direction -eq 'Inbound'
    $local = Convert-Address $af.LocalAddress; $remote = Convert-Address $af.RemoteAddress
    $script:portKeyword = $null; $lport = if ($protocol -in @('tcp', 'udp')) { Convert-Port $pf.LocalPort } else { @('any') }; $rport = if ($protocol -in @('tcp', 'udp')) { Convert-Port $pf.RemotePort } else { @('any') }; $keyword = $script:portKeyword
    $program = [string]$ap.Program; if ($program -eq 'Any' -or -not $program) { $program = $null }
    $scope = @(); if ($keyword) { $scope += 'port-keyword:' + $keyword }; $icmp = @($pf.IcmpType | Where-Object { $_ -and [string]$_ -ne 'Any' }); if ($icmp.Count) { $scope += 'icmp-type:' + (($icmp | ForEach-Object { [string]$_ }) -join ',') }; if ($r.Owner) { $scope += 'owner:' + [string]$r.Owner }; if ($ap.Package) { $scope += 'package:' + [string]$ap.Package }; $svc = [string]$svcs[$r.InstanceID].Service; if ($svc -and $svc -ne 'Any') { $scope += 'service:' + $svc }; $sec = $secs[$r.InstanceID]; if ($sec -and [string]$sec.LocalUser -and [string]$sec.LocalUser -ne 'Any') { $scope += 'local-user:' + [string]$sec.LocalUser }; if ($sec -and [string]$sec.RemoteUser -and [string]$sec.RemoteUser -ne 'Any') { $scope += 'remote-user:' + [string]$sec.RemoteUser }; $if = [string]$ifaces[$r.InstanceID].InterfaceType; if ($if -and $if -ne 'Any') { $scope += 'interface:' + $if }
    $profile = [string]$r.Profile; $profile = if ($profile -eq 'Any') { 'any' } else { $profile.ToLower().Replace(', ', '+') }
    [ordered]@{
        rule_id = [string]$r.Name; name = (Get-SafeText ([string]$r.DisplayName)); position = $i; enabled = ([string]$r.Enabled -eq 'True')
        direction = $(if ($inbound) { 'in' } else { 'out' }); action = $(if ([string]$r.Action -eq 'Block') { 'deny' } else { 'allow' }); protocol = $protocol
        src = [object[]]@(if ($inbound) { $remote } else { $local }); dst = [object[]]@(if ($inbound) { $local } else { $remote })
        src_ports = [object[]]@(if ($inbound) { $rport } else { $lport }); dst_ports = [object[]]@(if ($inbound) { $lport } else { $rport })
        application = (Get-SafeText $program); profile = $profile; filters_readable = ($null -ne $pf -and $null -ne $af); scope_constraints = [object[]]@($scope | ForEach-Object { Get-SafeText $_ } | Select-Object -First 20); last_hit_at = $null; hit_count = $null; expires_at = $null; owner = $null; created_at = $null
    }
})
$hostName = [System.Net.Dns]::GetHostName()
$sha = [System.Security.Cryptography.SHA256]::Create()
$hostKey = (($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($hostName + '|windows')) | ForEach-Object { $_.ToString('x2') }) -join '').Substring(0, 24)
$now = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
$event = [ordered]@{ event_id = 'fwrules-' + [guid]::NewGuid(); kind = 'firewall.ruleset'; observed_at = $now; asset = [ordered]@{ external_id = 'managed-' + $hostKey; hostname = $hostName; os_family = 'windows'; device_type = 'workstation'; addresses = @() }; details = [ordered]@{ ruleset_id = 'winfw-' + $hostKey + '-' + (Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss'); device_ref = 'windows-firewall:' + $hostName; vendor = 'windows-firewall'; evaluation = 'deny-overrides'; rules = $out } }
[System.IO.File]::WriteAllText($destination, ([ordered]@{ schema_version = 'cg.telemetry/1'; events = @($event) } | ConvertTo-Json -Depth 8 -Compress), (New-Object System.Text.UTF8Encoding($false)))
Write-Output ('Exported {0} firewall rules ({1} enabled, {2} with filters unreadable without elevation). No upload performed.' -f $out.Count, @($out | Where-Object { $_.enabled }).Count, @($out | Where-Object { -not $_.filters_readable }).Count)
