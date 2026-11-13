<#
CG-011 read-only sensitive-change monitor for Windows. Each run takes a snapshot of sensitive state and
compares it with the previous snapshot in -StatePath:
  registry  - Run/RunOnce autostart values (HKLM and HKCU)
  service   - start mode, binary path and account of every service
  software  - installed programs and versions (Uninstall keys)
  firewall  - every firewall rule's enabled state, action and direction
  account   - local users (enabled state) and local Administrators members
  policy    - Windows Defender, Windows Update and System policy registry values
  file      - hosts file, Startup folders and any extra -WatchPath folders (SHA-256)
The first run records a baseline. Later runs write one change.sensitive event per difference.
Changes nothing on the system, opens no network connection. No upload performed.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$StatePath,
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [string[]]$WatchPath = @()
)
$ErrorActionPreference = 'Stop'
$state = [System.IO.Path]::GetFullPath($StatePath)
$destination = [System.IO.Path]::GetFullPath($OutputPath)
if (Test-Path -LiteralPath $destination) { throw 'Output already exists. Choose a new private file path.' }
foreach ($p in @($state, $destination)) { if (-not (Test-Path -LiteralPath (Split-Path -Parent $p) -PathType Container)) { throw 'Output directories must exist and be private.' } }
$sha = [System.Security.Cryptography.SHA256]::Create()
function Get-Hash([string]$text) { return (($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($text)) | ForEach-Object { $_.ToString('x2') }) -join '') }
function Get-Iso($date) { return ([datetime]$date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ') }
$snapshot = @{}
function Add-Item([string]$category, [string]$key, [string]$summary) { $snapshot["$category|$key"] = [ordered]@{ category = $category; key = $key; summary = $summary; hash = (Get-Hash $summary) } }

foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce')) {
    $item = Get-ItemProperty -Path $root -ErrorAction SilentlyContinue
    if ($item) { foreach ($prop in $item.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' }) { Add-Item 'registry' "$root\$($prop.Name)" ([string]$prop.Value) } }
}
foreach ($s in @(Get-CimInstance -ClassName Win32_Service)) { Add-Item 'service' ([string]$s.Name) ('{0}|{1}|{2}' -f $s.StartMode, $s.PathName, $s.StartName) }
foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
    foreach ($app in @(Get-ItemProperty -Path $root -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName })) { Add-Item 'software' ([string]$app.DisplayName) ([string]$app.DisplayVersion) }
}
try { foreach ($r in @(Get-NetFirewallRule -ErrorAction Stop)) { Add-Item 'firewall' ([string]$r.Name) ('{0}|{1}|{2}|{3}' -f $r.Enabled, $r.Action, $r.Direction, $r.Profile) } } catch { }
try { foreach ($u in @(Get-LocalUser -ErrorAction Stop)) { Add-Item 'account' ('user:' + $u.Name) ('enabled=' + $u.Enabled) } } catch { }
try { foreach ($m in @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)) { Add-Item 'account' ('administrators:' + $m.Name) ([string]$m.ObjectClass) } } catch { }
foreach ($root in @('HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender', 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System')) {
    foreach ($key in @(Get-Item -Path $root -ErrorAction SilentlyContinue) + @(Get-ChildItem -Path $root -Recurse -ErrorAction SilentlyContinue)) {
        foreach ($name in @($key.GetValueNames())) { Add-Item 'policy' ($key.Name + '\' + $name) ([string]$key.GetValue($name)) }
    }
}
$files = @("$env:SystemRoot\System32\drivers\etc\hosts")
$files += @(Get-ChildItem -LiteralPath ([Environment]::GetFolderPath('Startup')), ([Environment]::GetFolderPath('CommonStartup')) -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
foreach ($w in $WatchPath) { $files += @(Get-ChildItem -LiteralPath $w -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 2000 | ForEach-Object { $_.FullName }) }
foreach ($f in $files | Select-Object -Unique) { if (Test-Path -LiteralPath $f -PathType Leaf) { Add-Item 'file' $f ((Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash.ToLower()) } }

$now = Get-Date
$current = [ordered]@{ taken_at = (Get-Iso $now); items = $snapshot }
if (-not (Test-Path -LiteralPath $state)) {
    [System.IO.File]::WriteAllText($state, ($current | ConvertTo-Json -Depth 6 -Compress), (New-Object System.Text.UTF8Encoding($false)))
    Write-Output ('Baseline recorded with {0} sensitive items. No change events yet. No upload performed.' -f $snapshot.Count)
    return
}
$previous = Get-Content -LiteralPath $state -Raw -Encoding UTF8 | ConvertFrom-Json
$old = @{}; foreach ($p in $previous.items.PSObject.Properties) { $old[$p.Name] = $p.Value }
$changes = @()
foreach ($k in $snapshot.Keys) {
    if (-not $old.ContainsKey($k)) { $changes += @{ item = $snapshot[$k]; action = 'added'; before = $null; after = $snapshot[$k] } }
    elseif ($old[$k].hash -ne $snapshot[$k].hash) { $changes += @{ item = $snapshot[$k]; action = 'modified'; before = $old[$k]; after = $snapshot[$k] } }
}
foreach ($k in $old.Keys) { if (-not $snapshot.ContainsKey($k)) { $changes += @{ item = $old[$k]; action = 'removed'; before = $old[$k]; after = $null } } }

$hostName = [System.Net.Dns]::GetHostName()
$hostKey = (Get-Hash ($hostName + '|windows')).Substring(0, 24)
$addresses = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -match '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)' } | ForEach-Object { $_.IPAddress } | Select-Object -Unique)
function Limit([string]$text) { if ($null -eq $text) { return $null }; $text = ($text -replace '[\x00-\x1F\x7F]', ' ').Trim(); if ($text.Length -eq 0) { return $null }; if ($text.Length -gt 500) { return $text.Substring(0, 500) }; return $text }
$events = @($changes | Select-Object -First 250 | ForEach-Object {
    $c = $_
    [ordered]@{
        event_id = 'change-' + [guid]::NewGuid().ToString(); kind = 'change.sensitive'; observed_at = (Get-Iso $now)
        asset = [ordered]@{ external_id = 'managed-' + $hostKey; hostname = $hostName; os_family = 'windows'; device_type = 'workstation'; addresses = $addresses }
        details = [ordered]@{
            change_id = 'snap-' + (Get-Hash ($c.item.category + '|' + $c.item.key + '|' + $c.action + '|' + $current.taken_at)).Substring(0, 32)
            category = $c.item.category; object_ref = (Limit $c.item.key); action = $c.action
            before_hash = $(if ($c.before) { $c.before.hash } else { $null }); after_hash = $(if ($c.after) { $c.after.hash } else { $null })
            before_summary = $(if ($c.before) { Limit $c.before.summary } else { $null }); after_summary = $(if ($c.after) { Limit $c.after.summary } else { $null })
            baseline_at = $previous.taken_at; detected_at = $current.taken_at; detector = 'snapshot-diff'; actor_ref = $null; authorization_ref = $null
            evidence_ref = 'Watch-SensitiveChanges.ps1@' + $hostName
        }
    }
})
[System.IO.File]::WriteAllText($state, ($current | ConvertTo-Json -Depth 6 -Compress), (New-Object System.Text.UTF8Encoding($false)))
if ($events.Count -eq 0) { Write-Output ('No sensitive changes since {0}. Snapshot updated. No upload performed.' -f $previous.taken_at); return }
[System.IO.File]::WriteAllText($destination, ([ordered]@{ schema_version = 'cg.telemetry/1'; events = $events } | ConvertTo-Json -Depth 8), (New-Object System.Text.UTF8Encoding($false)))
Write-Output ('{0} sensitive changes written ({1} shown at most 250 per file). No upload performed.' -f $changes.Count, $events.Count)
