<#
CG-026 low-impact authorized validation of the local host. Read-only: it reads registry policy values and
local configuration through documented cmdlets. No network traffic, no writes, no exploitation, no credentials.
Writes one validation.test_run event for an approved low-impact-validation plan. No upload.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PlanId,
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [string]$ExecutedBy = 'local-operator'
)
$ErrorActionPreference = 'Stop'
$destination = [System.IO.Path]::GetFullPath($OutputPath)
if (Test-Path -LiteralPath $destination) { throw 'Output already exists. Choose a new private file path.' }
if (-not (Test-Path -LiteralPath (Split-Path -Parent $destination) -PathType Container)) { throw 'Output directory must exist and be private.' }
function Get-Iso([datetime]$value) { $value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ') }
function Get-RegValue([string]$path, [string]$name) { try { (Get-ItemProperty -LiteralPath $path -Name $name -ErrorAction Stop).$name } catch { $null } }
$hostName = [System.Net.Dns]::GetHostName()
$sha = [System.Security.Cryptography.SHA256]::Create()
$hostKey = (($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($hostName + '|windows')) | ForEach-Object { $_.ToString('x2') }) -join '').Substring(0, 24)
$target = 'managed-' + $hostKey
$started = Get-Date
$results = New-Object System.Collections.Generic.List[object]
function Add-Result([string]$technique, [string]$check, [string]$outcome, [string]$observation) {
    $results.Add([ordered]@{ technique_id = $technique; target_ref = $target; outcome = $outcome; observation = ($check + ': ' + $observation); evidence_ref = 'Invoke-LowImpactValidation.ps1#' + $check })
}
# 1. SMBv1 server disabled (registry policy) or the SMBv1 driver absent.
$smb1 = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1'
$smb1Driver = Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10'
if ($smb1 -eq 0) { Add-Result 'registry-policy-check' 'smb1-server' 'pass' 'SMB1 server value is 0 (disabled)' }
elseif ($null -eq $smb1 -and -not $smb1Driver) { Add-Result 'registry-policy-check' 'smb1-server' 'pass' 'SMB1 driver mrxsmb10 is not installed' }
elseif ($null -eq $smb1) { Add-Result 'registry-policy-check' 'smb1-server' 'fail' 'SMB1 driver present and no SMB1=0 server policy' }
else { Add-Result 'registry-policy-check' 'smb1-server' 'fail' ('SMB1 server value is ' + $smb1) }
# 2. Remote Desktop requires Network Level Authentication when it is enabled.
$deny = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
$nla = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
if ($deny -eq 1) { Add-Result 'registry-policy-check' 'rdp-nla' 'pass' 'Remote Desktop is disabled' }
elseif ($nla -eq 1) { Add-Result 'registry-policy-check' 'rdp-nla' 'pass' 'Remote Desktop enabled with Network Level Authentication required' }
elseif ($null -eq $deny) { Add-Result 'registry-policy-check' 'rdp-nla' 'error' 'Remote Desktop setting not readable' }
else { Add-Result 'registry-policy-check' 'rdp-nla' 'fail' 'Remote Desktop enabled without Network Level Authentication' }
# 3. LLMNR disabled by policy (name-resolution poisoning surface).
$llmnr = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
if ($llmnr -eq 0) { Add-Result 'registry-policy-check' 'llmnr' 'pass' 'LLMNR disabled by policy' } else { Add-Result 'registry-policy-check' 'llmnr' 'fail' 'No policy disables LLMNR (enabled by default)' }
# 4. User Account Control enabled.
$lua = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
if ($lua -eq 1) { Add-Result 'registry-policy-check' 'uac' 'pass' 'User Account Control enabled' } elseif ($null -eq $lua) { Add-Result 'registry-policy-check' 'uac' 'error' 'EnableLUA not readable' } else { Add-Result 'registry-policy-check' 'uac' 'fail' 'User Account Control disabled' }
# 5. Every Windows Firewall profile enabled.
try {
    $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
    $off = @($profiles | Where-Object { -not $_.Enabled } | ForEach-Object { [string]$_.Name })
    if ($off.Count -eq 0) { Add-Result 'credentialed-config-check' 'firewall-profiles' 'pass' ('All ' + $profiles.Count + ' firewall profiles enabled') } else { Add-Result 'credentialed-config-check' 'firewall-profiles' 'fail' ('Disabled profiles: ' + ($off -join ', ')) }
} catch { Add-Result 'credentialed-config-check' 'firewall-profiles' 'error' 'Firewall profiles not readable' }
# 6. Antivirus signatures no older than 7 days.
try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    if (-not $mp.RealTimeProtectionEnabled) { Add-Result 'credentialed-config-check' 'av-signatures' 'fail' 'Real-time protection is off' }
    elseif ($mp.AntivirusSignatureAge -le 7) { Add-Result 'credentialed-config-check' 'av-signatures' 'pass' ('Signatures ' + $mp.AntivirusSignatureAge + ' days old') }
    else { Add-Result 'credentialed-config-check' 'av-signatures' 'fail' ('Signatures ' + $mp.AntivirusSignatureAge + ' days old (limit 7)') }
} catch { Add-Result 'credentialed-config-check' 'av-signatures' 'not-run' 'Microsoft Defender status not available on this host' }
$ended = Get-Date
$event = [ordered]@{
    event_id = 'validation-' + [guid]::NewGuid().ToString(); kind = 'validation.test_run'; observed_at = (Get-Iso $ended)
    asset = [ordered]@{ external_id = $target; hostname = $hostName; os_family = 'windows'; device_type = 'workstation'; addresses = @() }
    details = [ordered]@{ run_id = 'lowimpact-' + $hostKey + '-' + $started.ToUniversalTime().ToString('yyyyMMddHHmmss'); plan_id = $PlanId; started_at = (Get-Iso $started); ended_at = (Get-Iso $ended); executed_by = $ExecutedBy; results = [object[]]$results.ToArray() }
}
[System.IO.File]::WriteAllText($destination, ([ordered]@{ schema_version = 'cg.telemetry/1'; events = @($event) } | ConvertTo-Json -Depth 8 -Compress), (New-Object System.Text.UTF8Encoding($false)))
$summary = $results | ForEach-Object { $_['outcome'] } | Group-Object | ForEach-Object { $_.Name + '=' + $_.Count }
Write-Output ('Low-impact validation: ' + $results.Count + ' read-only checks (' + ($summary -join ', ') + '). No upload performed.')
