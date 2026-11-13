<#
CG-006 read-only local discovery exporter. Explicitly invoked; reads only what this Windows host
already knows: its ARP neighbour cache, its DNS client cache and its DHCP/gateway configuration.
It sends no packets of its own, opens no connection, changes no setting and stores no credential.
Active Directory is read only with -IncludeActiveDirectory on a domain-joined host.
LLDP/CDP, SNMPv3 and controller APIs need an authorized collector and are reported as not available.
Output: a cg.telemetry/1 file with one discovery.sequence event. No upload performed.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [Parameter(Mandatory = $true)][ValidateLength(3, 300)][string]$AuthorizationRef,
    [switch]$IncludeActiveDirectory
)
$ErrorActionPreference = 'Stop'
$destination = [System.IO.Path]::GetFullPath($OutputPath)
if (Test-Path -LiteralPath $destination) { throw 'Output already exists. Choose a new private file path.' }
if (-not (Test-Path -LiteralPath (Split-Path -Parent $destination) -PathType Container)) { throw 'Output directory must exist and be private.' }

function ConvertTo-UInt32([string]$ip) { $b = ([System.Net.IPAddress]::Parse($ip)).GetAddressBytes(); return ([uint32]$b[0] -shl 24) + ([uint32]$b[1] -shl 16) + ([uint32]$b[2] -shl 8) + [uint32]$b[3] }
function ConvertFrom-UInt32([uint32]$n) { return '{0}.{1}.{2}.{3}' -f (($n -shr 24) -band 255), (($n -shr 16) -band 255), (($n -shr 8) -band 255), ($n -band 255) }
function Test-Private([string]$ip) { return $ip -match '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)' }
function Get-Now { (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ') }

# Scope = this host's own private IPv4 networks (never wider than /16).
$addresses = @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne '127.0.0.1' -and (Test-Private $_.IPAddress) })
if ($addresses.Count -eq 0) { throw 'This host has no private IPv4 address. Nothing in scope.' }
$scopes = @($addresses | ForEach-Object {
    $prefix = [Math]::Max([int]$_.PrefixLength, 16)
    $mask = [uint32]([math]::Pow(2, 32) - [math]::Pow(2, 32 - $prefix))
    [pscustomobject]@{ Network = (ConvertTo-UInt32 $_.IPAddress) -band $mask; Mask = $mask; Prefix = $prefix }
} | Sort-Object Network, Prefix -Unique)
function Test-InScope([string]$ip) {
    if (-not ($ip -match '^\d+\.\d+\.\d+\.\d+$') -or -not (Test-Private $ip)) { return $false }
    $n = ConvertTo-UInt32 $ip
    foreach ($s in $scopes) { if (($n -band $s.Mask) -eq $s.Network) { $last = $s.Network + (-bnot $s.Mask -band [uint32]::MaxValue); return ($n -ne $s.Network -and $n -ne $last) } }
    return $false
}
$scopeText = @($scopes | ForEach-Object { '{0}/{1}' -f (ConvertFrom-UInt32 $_.Network), $_.Prefix })

function New-Stage([string]$method, [string]$status, [string]$reason, $started, $ended, $credential, $findings) {
    [ordered]@{ method = $method; status = $status; reason = $reason; started_at = $started; ended_at = $ended; credential_ref = $credential; findings = @($findings | Select-Object -First 5000) }
}
function New-Finding($ip, $mac, $hostname, $evidence) {
    [ordered]@{ ip = $ip; mac = $mac; hostname = $hostname; vendor = $null; neighbor = $null; evidence_ref = $evidence }
}
$stages = @()

# 1. ARP: this host's neighbour cache only.
$start = Get-Now
$arp = @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {
    $_.State -in @('Reachable', 'Stale', 'Delay', 'Probe', 'Permanent') -and (Test-InScope $_.IPAddress) -and
    $_.LinkLayerAddress -and $_.LinkLayerAddress -notmatch '^(00-00-00-00-00-00|FF-FF-FF-FF-FF-FF|01-00-5E)'
} | ForEach-Object { New-Finding $_.IPAddress ($_.LinkLayerAddress.ToLower() -replace '-', ':') $null ('Get-NetNeighbor:' + $_.InterfaceAlias) })
$stages += New-Stage 'arp' 'completed' $null $start (Get-Now) $null $arp

# 2. DNS: names this host already resolved (client cache), private in-scope answers only.
$start = Get-Now
$dns = @(Get-DnsClientCache -Type A -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 0 -and (Test-InScope ([string]$_.Data)) } |
    Sort-Object Entry, Data -Unique | ForEach-Object { New-Finding ([string]$_.Data) $null ([string]$_.Entry) 'Get-DnsClientCache' })
$stages += New-Stage 'dns' 'completed' $null $start (Get-Now) $null $dns

# 3. DHCP: DHCP server and default gateway from this host's adapter configuration.
$start = Get-Now
$configs = @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE')
$dhcpFindings = @()
foreach ($c in $configs) {
    if ($c.DHCPEnabled -and $c.DHCPServer -and (Test-InScope $c.DHCPServer)) { $dhcpFindings += New-Finding $c.DHCPServer $null $null 'Win32_NetworkAdapterConfiguration:DHCPServer' }
    foreach ($g in @($c.DefaultIPGateway)) { if ($g -and (Test-InScope $g)) { $dhcpFindings += New-Finding $g $null $null 'Win32_NetworkAdapterConfiguration:DefaultIPGateway' } }
}
if (@($configs | Where-Object { $_.DHCPEnabled }).Count -gt 0) { $stages += New-Stage 'dhcp' 'completed' $null $start (Get-Now) $null $dhcpFindings }
else { $stages += New-Stage 'dhcp' 'not-available' 'No DHCP-configured adapter on this host.' $null $null $null @() }

# 4. Active Directory: only when explicitly requested on a domain-joined host.
$system = Get-CimInstance -ClassName Win32_ComputerSystem
if (-not $system.PartOfDomain) { $stages += New-Stage 'ad' 'not-available' 'This host is not joined to an Active Directory domain.' $null $null $null @() }
elseif (-not $IncludeActiveDirectory) { $stages += New-Stage 'ad' 'skipped' 'Not requested; rerun with -IncludeActiveDirectory under an authorized scope.' $null $null $null @() }
else {
    $start = Get-Now
    $searcher = [adsisearcher]'(objectCategory=computer)'; $searcher.PageSize = 500; $searcher.SizeLimit = 2000
    [void]$searcher.PropertiesToLoad.Add('dnshostname')
    $adFindings = @()
    foreach ($r in $searcher.FindAll()) {
        $name = [string]($r.Properties['dnshostname'] | Select-Object -First 1); if (-not $name) { continue }
        try { foreach ($ip in [System.Net.Dns]::GetHostAddresses($name)) { if (Test-InScope $ip.IPAddressToString) { $adFindings += New-Finding $ip.IPAddressToString $null $name 'ActiveDirectory:computer' } } } catch { }
    }
    $stages += New-Stage 'ad' 'completed' $null $start (Get-Now) ('machine-context:' + $system.Domain) $adFindings
}

# 5-7. Need authorized collectors that this exporter does not provide.
$stages += New-Stage 'lldp-cdp' 'not-available' 'Requires an authorized switch-side LLDP/CDP collector; this host exposes no neighbour table.' $null $null $null @()
$stages += New-Stage 'snmpv3' 'not-available' 'Requires an SNMPv3 credential reference and an authorized target list.' $null $null $null @()
$stages += New-Stage 'api' 'not-available' 'No controller API connector is configured.' $null $null $null @()

$hostName = [System.Net.Dns]::GetHostName()
$hostAddresses = @($addresses | ForEach-Object { $_.IPAddress } | Select-Object -Unique)
$sha = [System.Security.Cryptography.SHA256]::Create()
$hostKey = (($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($hostName + '|windows')) | ForEach-Object { $_.ToString('x2') }) -join '').Substring(0, 24)
$export = [ordered]@{
    schema_version = 'cg.telemetry/1'
    events = @([ordered]@{
        event_id = 'local-discovery-' + [guid]::NewGuid().ToString()
        kind = 'discovery.sequence'
        observed_at = Get-Now
        asset = [ordered]@{ external_id = 'control-plane-' + $hostKey; hostname = $hostName; os_family = 'windows'; device_type = 'unknown'; addresses = $hostAddresses }
        details = [ordered]@{ run_id = 'local-' + (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'); authorization_ref = $AuthorizationRef; collector_ref = 'Export-LocalDiscovery.ps1@' + $hostName; scope = $scopeText; stages = $stages }
    })
}
[System.IO.File]::WriteAllText($destination, ($export | ConvertTo-Json -Depth 10), (New-Object System.Text.UTF8Encoding($false)))
$count = ($stages | ForEach-Object { $_.findings.Count } | Measure-Object -Sum).Sum
Write-Output ('Exported one discovery run with {0} findings to the requested private file. No upload performed.' -f $count)
