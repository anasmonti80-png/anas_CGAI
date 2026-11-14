<#
CG-013 read-only software and update inventory for Windows. Reads installed programs (Uninstall
registry keys), installed updates (Win32_QuickFixEngineering) and the OS version. Changes nothing,
opens no network connection. Output: a cg.telemetry/1 file with one software.inventory event.
No upload performed.
#>
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$OutputPath)
$ErrorActionPreference = 'Stop'
$destination = [System.IO.Path]::GetFullPath($OutputPath)
if (Test-Path -LiteralPath $destination) { throw 'Output already exists. Choose a new private file path.' }
if (-not (Test-Path -LiteralPath (Split-Path -Parent $destination) -PathType Container)) { throw 'Output directory must exist and be private.' }
function Get-Iso($date) { if ($null -eq $date) { return $null }; try { return ([datetime]$date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ') } catch { return $null } }
function Limit([string]$text, [int]$max) { if ([string]::IsNullOrWhiteSpace($text)) { return $null }; $t = ($text -replace '[\x00-\x1F\x7F]', '').Trim(); if ($t.Length -eq 0) { return $null }; if ($t.Length -gt $max) { return $t.Substring(0, $max) }; return $t }

$seen = @{}
$software = @()
foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
    foreach ($app in @(Get-ItemProperty -Path $root -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and -not $_.SystemComponent -and -not $_.ParentKeyName })) {
        $name = Limit ([string]$app.DisplayName) 300; $version = Limit ([string]$app.DisplayVersion) 100
        $key = "$name|$version"; if ($seen.ContainsKey($key)) { continue }; $seen[$key] = $true
        $installed = $null
        $parsed = [datetime]::MinValue; if ($app.InstallDate -match '^\d{8}$' -and [datetime]::TryParseExact([string]$app.InstallDate, 'yyyyMMdd', [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$parsed) -and $parsed.Year -ge 2000 -and $parsed -le (Get-Date)) { $installed = $parsed.ToString('yyyy-MM-dd') + 'T00:00:00.000Z' }  # non-Gregorian or invalid dates stay unknown
        $software += [ordered]@{ name = $name; vendor = (Limit ([string]$app.Publisher) 200); version = $version; install_date = $installed; source = 'uninstall-registry' }
    }
}
$updates = @(Get-CimInstance -ClassName Win32_QuickFixEngineering -ErrorAction SilentlyContinue | Where-Object { $_.HotFixID -match '^KB\d+$' } | Sort-Object HotFixID -Unique | ForEach-Object {
    [ordered]@{ update_id = [string]$_.HotFixID; description = (Limit ([string]$_.Description) 200); installed_on = (Get-Iso $_.InstalledOn) }
})
$os = Get-CimInstance -ClassName Win32_OperatingSystem
$hostName = [System.Net.Dns]::GetHostName()
$sha = [System.Security.Cryptography.SHA256]::Create()
$hostKey = (($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($hostName + '|windows')) | ForEach-Object { $_.ToString('x2') }) -join '').Substring(0, 24)
$addresses = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -match '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)' } | ForEach-Object { $_.IPAddress } | Select-Object -Unique)
$now = Get-Date
$export = [ordered]@{
    schema_version = 'cg.telemetry/1'
    events = @([ordered]@{
        event_id = 'software-' + [guid]::NewGuid().ToString(); kind = 'software.inventory'; observed_at = (Get-Iso $now)
        asset = [ordered]@{ external_id = 'managed-' + $hostKey; hostname = $hostName; os_family = 'windows'; device_type = 'workstation'; addresses = $addresses }
        details = [ordered]@{
            inventory_id = 'software-' + $hostKey
            os = [ordered]@{ name = [string]$os.Caption; version = [string]$os.Version; build = [string]$os.BuildNumber }
            software = @($software | Sort-Object name | Select-Object -First 5000)
            updates = @($updates | Select-Object -First 2000)
            evidence_ref = 'Export-SoftwareInventory.ps1@' + $hostName
        }
    })
}
[System.IO.File]::WriteAllText($destination, ($export | ConvertTo-Json -Depth 8 -Compress), (New-Object System.Text.UTF8Encoding($false)))
Write-Output ('Inventory written: {0} programs, {1} updates. No upload performed.' -f $software.Count, $updates.Count)
