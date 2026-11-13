<#
CG-015 read-only account posture for Windows local accounts: enabled state, last sign-in, password
age and privileged membership. With access to the Security log (administrator or Event Log Readers)
it also exports recent sign-in successes (4624) and failures (4625) with source address. Changes
nothing, stores no password or hash. Output: cg.telemetry/1 with identity.account_posture and,
when readable, identity.signin_activity. No upload performed.
#>
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$OutputPath, [ValidateRange(1, 168)][int]$Hours = 24)
$ErrorActionPreference = 'Stop'
$destination = [System.IO.Path]::GetFullPath($OutputPath)
if (Test-Path -LiteralPath $destination) { throw 'Output already exists. Choose a new private file path.' }
if (-not (Test-Path -LiteralPath (Split-Path -Parent $destination) -PathType Container)) { throw 'Output directory must exist and be private.' }
function Get-Iso($date) { if ($null -eq $date) { return $null }; return ([datetime]$date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ') }
function Get-SafeText([string]$text) { if ($null -eq $text) { return $null }; return ($text -replace '[\x00-\x1F\x7F]', '').Trim() }
$now = Get-Date
$hostName = [System.Net.Dns]::GetHostName()
$sha = [System.Security.Cryptography.SHA256]::Create()
$hostKey = (($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($hostName + '|windows')) | ForEach-Object { $_.ToString('x2') }) -join '').Substring(0, 24)
$addresses = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -match '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)' } | ForEach-Object { $_.IPAddress } | Select-Object -Unique)
$asset = [ordered]@{ external_id = 'managed-' + $hostKey; hostname = $hostName; os_family = 'windows'; device_type = 'workstation'; addresses = $addresses }
$directory = 'local:' + $hostName
$admins = @(); try { $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { ($_.Name -split '\\')[-1] }) } catch { }
$accounts = @(Get-LocalUser | ForEach-Object { [ordered]@{ principal_ref = (Get-SafeText ('user:' + $_.Name)); enabled = [bool]$_.Enabled; mfa_registered = $null; last_signin_at = (Get-Iso $_.LastLogon); credential_changed_at = (Get-Iso $_.PasswordLastSet); privileged = ($admins -contains $_.Name) } })
$events = @([ordered]@{ event_id = 'posture-' + [guid]::NewGuid().ToString(); kind = 'identity.account_posture'; observed_at = (Get-Iso $now); asset = $asset; details = [ordered]@{ posture_id = 'local-' + $hostKey; directory_ref = $directory; source = 'windows-local'; accounts = $accounts } })
$signinNote = 'Security log not readable without administrator or Event Log Readers; sign-in activity not exported.'
try {
    $records = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = @(4624, 4625); StartTime = $now.AddHours(-$Hours) } -MaxEvents 5000 -ErrorAction Stop)
    $signins = @($records | ForEach-Object {
        [xml]$x = $_.ToXml(); $data = @{}; foreach ($d in $x.Event.EventData.Data) { $data[[string]$d.Name] = [string]$d.'#text' }
        $ip = $data['IpAddress']; if ($ip -notmatch '^\d+\.\d+\.\d+\.\d+$') { $ip = $null }
        [ordered]@{ signin_id = 'evt-' + $_.RecordId; principal_ref = (Get-SafeText ('user:' + $data['TargetUserName'])); at = (Get-Iso $_.TimeCreated); result = $(if ($_.Id -eq 4624) { 'success' } else { 'failure' }); failure_reason = $(if ($_.Id -eq 4625) { Get-SafeText $data['SubStatus'] } else { $null }); source_ip = $ip; country = $null; client_app = (Get-SafeText ('logon-type-' + $data['LogonType'])); mfa = 'unknown' }
    } | Where-Object { $_.principal_ref -and $_.principal_ref -ne 'user:-' })
    if ($signins.Count -gt 0) { $events += [ordered]@{ event_id = 'signin-' + [guid]::NewGuid().ToString(); kind = 'identity.signin_activity'; observed_at = (Get-Iso $now); asset = $asset; details = [ordered]@{ batch_id = 'local-' + $hostKey + '-' + $now.ToUniversalTime().ToString('yyyyMMddHHmmss'); directory_ref = $directory; window = [ordered]@{ starts_at = (Get-Iso $now.AddHours(-$Hours)); ends_at = (Get-Iso $now) }; signins = $signins } }; $signinNote = "$($signins.Count) sign-in events exported." }
} catch { }
[System.IO.File]::WriteAllText($destination, ([ordered]@{ schema_version = 'cg.telemetry/1'; events = $events } | ConvertTo-Json -Depth 8), (New-Object System.Text.UTF8Encoding($false)))
Write-Output ("Account posture written for {0} accounts. {1} No upload performed." -f $accounts.Count, $signinNote)
