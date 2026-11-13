<#
CG-010 optional read-only Windows agent. Explicitly invoked (or scheduled by an administrator) on a
managed device. Collects: Windows Event Log channel health, Sysmon presence, services, processes
(names only, no command lines) and AV/EDR/firewall status. Changes nothing, opens no network
connection and stores no credential. Output: a cg.telemetry/1 file with one agent.inventory_report
event. No upload performed.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [Parameter(Mandatory = $true)][ValidateLength(3, 200)][string]$EnrolledBy,
    [ValidateRange(1, 1440)][int]$ReportIntervalMinutes = 60
)
$ErrorActionPreference = 'Stop'
$destination = [System.IO.Path]::GetFullPath($OutputPath)
if (Test-Path -LiteralPath $destination) { throw 'Output already exists. Choose a new private file path.' }
if (-not (Test-Path -LiteralPath (Split-Path -Parent $destination) -PathType Container)) { throw 'Output directory must exist and be private.' }
function Get-SafeText([string]$text) { if ($null -eq $text) { return $null }; return ($text -replace '[\x00-\x1F\x7F]', '').Trim() }
function Get-Iso($date) { if ($null -eq $date) { return $null }; return ([datetime]$date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ') }
$now = Get-Date
$since = $now.AddHours(-1)

# Event-log channels: count events in the last hour; access problems are reported, never bypassed.
function Get-Channel([string]$channel, [string]$logName) {
    try {
        $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
        if (-not $log.IsEnabled) { return [ordered]@{ channel = $channel; status = 'disabled'; events_last_hour = $null; last_event_at = $null; reason = "$logName is disabled." } }
        $recent = @(Get-WinEvent -FilterHashtable @{ LogName = $logName; StartTime = $since } -MaxEvents 5000 -ErrorAction SilentlyContinue)
        $last = Get-WinEvent -LogName $logName -MaxEvents 1 -ErrorAction SilentlyContinue
        return [ordered]@{ channel = $channel; status = 'collected'; events_last_hour = $recent.Count; last_event_at = (Get-Iso $last.TimeCreated); reason = $null }
    } catch [System.UnauthorizedAccessException] {
        return [ordered]@{ channel = $channel; status = 'access-denied'; events_last_hour = $null; last_event_at = $null; reason = "Reading $logName requires administrator or Event Log Readers membership." }
    } catch {
        if ($_.Exception.Message -match 'access|denied|unauthorized') { return [ordered]@{ channel = $channel; status = 'access-denied'; events_last_hour = $null; last_event_at = $null; reason = "Reading $logName requires administrator or Event Log Readers membership." } }
        return [ordered]@{ channel = $channel; status = 'not-installed'; events_last_hour = $null; last_event_at = $null; reason = "$logName is not present on this device." }
    }
}
$channels = @(
    (Get-Channel 'windows-security' 'Security'),
    (Get-Channel 'windows-system' 'System'),
    (Get-Channel 'windows-application' 'Application'),
    (Get-Channel 'sysmon' 'Microsoft-Windows-Sysmon/Operational')
)
$sysmonService = Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $sysmonService -and $channels[3].status -ne 'collected') { $channels[3].status = 'not-installed'; $channels[3].reason = 'Sysmon is not installed on this device.' }

# Services and processes (names only).
$services = @(Get-CimInstance -ClassName Win32_Service | Sort-Object Name)
$serviceItems = @($services | Select-Object -First 1000 | ForEach-Object { [ordered]@{ name = (Get-SafeText ([string]$_.Name)); state = ([string]$_.State).ToLower(); start_mode = ([string]$_.StartMode).ToLower() } })
$processes = @(Get-Process | Sort-Object ProcessName, Id)
$processItems = @($processes | Select-Object -First 2000 | ForEach-Object { [ordered]@{ name = (Get-SafeText ([string]$_.ProcessName)); pid = [int]$_.Id } })

# Protection status from Windows Security Center and Defender.
$products = @()
try {
    foreach ($p in @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop)) {
        $hex = '{0:X6}' -f [int]$p.productState
        $state = switch ($hex.Substring(2, 2)) { '10' { 'on' } '11' { 'on' } '00' { 'off' } '01' { 'snoozed' } default { 'unknown' } }
        $products += [ordered]@{ name = (Get-SafeText ([string]$p.displayName)); type = 'av'; state = $state; signatures_age_days = $null; realtime = $null }
    }
} catch { }
try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    $defender = [ordered]@{ name = 'Microsoft Defender Antivirus'; type = 'av'; state = $(if ($mp.AMServiceEnabled -and $mp.AntivirusEnabled) { 'on' } else { 'off' }); signatures_age_days = [int]$mp.AntivirusSignatureAge; realtime = [bool]$mp.RealTimeProtectionEnabled }
    $products = @($products | Where-Object { $_.name -notmatch 'Defender' }) + $defender
} catch { }
try {
    foreach ($f in @(Get-NetFirewallProfile -ErrorAction Stop)) { $products += [ordered]@{ name = "Windows Firewall ($($f.Name))"; type = 'firewall'; state = $(if ($f.Enabled) { 'on' } else { 'off' }); signatures_age_days = $null; realtime = $null } }
} catch { }

$hostName = [System.Net.Dns]::GetHostName()
$addresses = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -match '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)' } | ForEach-Object { $_.IPAddress } | Select-Object -Unique)
$sha = [System.Security.Cryptography.SHA256]::Create()
$hostKey = (($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($hostName + '|windows')) | ForEach-Object { $_.ToString('x2') }) -join '').Substring(0, 24)
$export = [ordered]@{
    schema_version = 'cg.telemetry/1'
    events = @([ordered]@{
        event_id = 'agent-' + [guid]::NewGuid().ToString()
        kind = 'agent.inventory_report'
        observed_at = (Get-Iso $now)
        asset = [ordered]@{ external_id = 'managed-' + $hostKey; hostname = $hostName; os_family = 'windows'; device_type = 'workstation'; addresses = $addresses }
        details = [ordered]@{
            agent_id = 'cg-agent-windows-' + $hostKey; agent_version = '1.0.0'; platform = 'windows'
            enrollment = [ordered]@{ mode = 'optional'; enrolled_by_ref = $EnrolledBy; report_interval_minutes = $ReportIntervalMinutes }
            channels = $channels
            services = [ordered]@{ total = $services.Count; running = @($services | Where-Object { $_.State -eq 'Running' }).Count; items = $serviceItems }
            processes = [ordered]@{ total = $processes.Count; items = $processItems }
            protection = $products
        }
    })
}
[System.IO.File]::WriteAllText($destination, ($export | ConvertTo-Json -Depth 8), (New-Object System.Text.UTF8Encoding($false)))
Write-Output ('Agent report written: {0} services, {1} processes, {2} protection products. No upload performed.' -f $services.Count, $processes.Count, $products.Count)
