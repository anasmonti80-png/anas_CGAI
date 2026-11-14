<#
Read-only, explicitly invoked exporter. No network access, policy changes or credentials.
Security-log access must already be authorized. Does not elevate or enable auditing.
Writes only an allowlisted subset of Security events since the current boot.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [ValidateRange(1, 250)][int]$MaxEvents = 200,
    [ValidateRange(1, 24)][int]$Hours = 1
)
$ErrorActionPreference = 'Stop'
$destination = [System.IO.Path]::GetFullPath($OutputPath)
if (Test-Path -LiteralPath $destination) { throw 'Output already exists. Choose a new private file path.' }
$parentDirectory = Split-Path -Parent $destination
if (-not (Test-Path -LiteralPath $parentDirectory -PathType Container)) { throw 'Output directory must exist and be private.' }
$operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
$bootTime = $operatingSystem.LastBootUpTime.ToUniversalTime()
$startTime = (Get-Date).ToUniversalTime().AddHours(-$Hours)
if ($startTime -lt $bootTime) { $startTime = $bootTime }
# Without access, Windows answers a filtered Security query with "no events found", which would read as
# "no logons happened". Check access first so the two cases are never confused.
try { $null = Get-WinEvent -ListLog 'Security' -ErrorAction Stop } catch {
    throw 'The Security log is not readable by this account (run as administrator or add the account to Event Log Readers). No telemetry file was created; this is not evidence that no logons occurred.'
}
try {
    $records = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = @(4624, 4625, 4634); StartTime = $startTime } -MaxEvents $MaxEvents -ErrorAction Stop)
} catch {
    if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $records = @() } else { throw }
}
$allowedFields = @('LogonType', 'TargetLogonId', 'TargetUserName', 'TargetDomainName', 'IpAddress', 'WorkstationName')
$events = @($records | Sort-Object TimeCreated | ForEach-Object {
    $record = $_
    [xml]$xml = $record.ToXml()
    $fields = [ordered]@{}
    foreach ($datum in $xml.Event.EventData.Data) {
        if ($allowedFields -contains [string]$datum.Name) { $fields[[string]$datum.Name] = [string]$datum.'#text' }
    }
    [ordered]@{
        event_id = [int]$record.Id
        record_id = [long]$record.RecordId
        time_created = $record.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        provider = [string]$record.ProviderName
        channel = 'Security'
        data = $fields
    }
})
if ($events.Count -eq 0) { throw ('The Security log is readable but has no logon events (4624, 4625, 4634) since {0} UTC. No telemetry file was created.' -f $startTime.ToString('yyyy-MM-dd HH:mm')) }
$export = [ordered]@{
    schema_version = 'cg.windows-export/1'
    computer = [System.Net.Dns]::GetHostName()
    boot_time = $bootTime.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    events = $events
}
$serialized = $export | ConvertTo-Json -Depth 8 -Compress
[System.IO.File]::WriteAllText($destination, $serialized, (New-Object System.Text.UTF8Encoding($false)))
Write-Output ('Exported {0} records to the requested private file. No upload performed.' -f $events.Count)
