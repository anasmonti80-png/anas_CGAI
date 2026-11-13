<#
CG-019 read-only connection evidence for Windows. Converts this host's current TCP connections
(Get-NetTCPConnection) into goflow2-style flow lines and its DNS client cache into Suricata-EVE-style
DNS lines, then wraps both as cg.telemetry/1 log.batch events. No packets are sent and nothing is
changed. No upload performed.
#>
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$OutputPath)
$ErrorActionPreference = 'Stop'
$destination = [System.IO.Path]::GetFullPath($OutputPath)
if (Test-Path -LiteralPath $destination) { throw 'Output already exists. Choose a new private file path.' }
if (-not (Test-Path -LiteralPath (Split-Path -Parent $destination) -PathType Container)) { throw 'Output directory must exist and be private.' }
$now = Get-Date; $epoch = [int][double]::Parse((Get-Date -Date $now.ToUniversalTime() -UFormat %s))
$flowLines = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -notin @('127.0.0.1', '::1', '0.0.0.0', '::') } | Select-Object -First 2000 | ForEach-Object {
    ([ordered]@{ TimeFlowStart = $epoch; SrcAddr = [string]$_.LocalAddress; DstAddr = [string]$_.RemoteAddress; SrcPort = [int]$_.LocalPort; DstPort = [int]$_.RemotePort; Proto = 6; Bytes = 0; Packets = 0 } | ConvertTo-Json -Compress)
})
$iso = $now.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
$dnsLines = @(Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object { $_.Entry } | Sort-Object Entry -Unique | Select-Object -First 2000 | ForEach-Object {
    $type = switch ([int]$_.Type) { 1 { 'A' } 5 { 'CNAME' } 16 { 'TXT' } 28 { 'AAAA' } default { [string]$_.Type } }
    ([ordered]@{ timestamp = $iso; event_type = 'dns'; src_ip = $null; dest_ip = $null; proto = 'UDP'; dns = [ordered]@{ type = 'query'; rrname = ([string]$_.Entry -replace '[\x00-\x1F\x7F]', ''); rrtype = $type } } | ConvertTo-Json -Compress)
})
$hostName = [System.Net.Dns]::GetHostName()
$asset = [ordered]@{ external_id = 'log-collector-' + $hostName.ToLower(); hostname = $hostName; os_family = 'windows'; device_type = 'workstation'; addresses = @() }
$events = @()
if ($flowLines.Count) { $events += [ordered]@{ event_id = 'conn-' + [guid]::NewGuid(); kind = 'log.batch'; observed_at = $iso; asset = $asset; details = [ordered]@{ batch_id = 'connections-' + [guid]::NewGuid(); source_name = "$hostName TCP connections"; format = 'goflow-json'; lines = $flowLines } } }
if ($dnsLines.Count) { $events += [ordered]@{ event_id = 'dns-' + [guid]::NewGuid(); kind = 'log.batch'; observed_at = $iso; asset = $asset; details = [ordered]@{ batch_id = 'dnscache-' + [guid]::NewGuid(); source_name = "$hostName DNS client cache"; format = 'suricata-eve'; lines = $dnsLines } } }
[System.IO.File]::WriteAllText($destination, ([ordered]@{ schema_version = 'cg.telemetry/1'; events = $events } | ConvertTo-Json -Depth 8), (New-Object System.Text.UTF8Encoding($false)))
Write-Output ('Wrote {0} connection lines and {1} DNS lines. No upload performed.' -f $flowLines.Count, $dnsLines.Count)
