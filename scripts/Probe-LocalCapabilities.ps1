<#
CG-044 capability probe of the local Windows host. Read-only: it tests what this host and account can actually
do (read, logs, configuration, policy, isolation, port shutdown, undo) without changing anything, and writes one
device.capability_probe event. No upload.
#>
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$OutputPath)
$ErrorActionPreference = 'Stop'
$destination = [System.IO.Path]::GetFullPath($OutputPath)
if (Test-Path -LiteralPath $destination) { throw 'Output already exists. Choose a new private file path.' }
if (-not (Test-Path -LiteralPath (Split-Path -Parent $destination) -PathType Container)) { throw 'Output directory must exist and be private.' }
$hostName = [System.Net.Dns]::GetHostName()
$sha = [System.Security.Cryptography.SHA256]::Create()
$hostKey = (($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($hostName + '|windows')) | ForEach-Object { $_.ToString('x2') }) -join '').Substring(0, 24)
$ref = 'managed-' + $hostKey
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$caps = New-Object System.Collections.Generic.List[object]
function Add-Cap([string]$name, [string]$status, [string]$method, [string]$evidence) { $caps.Add([ordered]@{ capability = $name; status = $status; method = $method; evidence = $evidence; min_version = $null; license_feature = $null }) }
$os = $null
try { $os = Get-CimInstance -ClassName Win32_OperatingSystem; Add-Cap 'read' 'supported' 'CIM Win32_OperatingSystem' 'Operating system inventory readable' } catch { Add-Cap 'read' 'unsupported' 'CIM Win32_OperatingSystem' 'CIM query failed' }
try { $null = Get-WinEvent -ListLog 'Security' -ErrorAction Stop; Add-Cap 'logs' 'supported' 'Get-WinEvent Security' 'Security log readable by this account' } catch { Add-Cap 'logs' 'unsupported' 'Get-WinEvent Security' 'Security log not readable by this account (administrator or Event Log Readers required)' }
try { $null = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name CurrentBuild; Add-Cap 'config' 'supported' 'Registry HKLM read' 'Machine configuration readable' } catch { Add-Cap 'config' 'unsupported' 'Registry HKLM read' 'Machine configuration not readable' }
$fw = $true; try { $null = Get-NetFirewallProfile -ErrorAction Stop } catch { $fw = $false }
if ($fw -and $admin) { Add-Cap 'policy' 'supported' 'Windows Firewall (NetSecurity)' 'Firewall present and the account is an administrator'; Add-Cap 'isolation' 'supported' 'Windows Firewall block-all with management exception' 'Firewall present and the account is an administrator'; Add-Cap 'undo' 'supported' 'Remove CyberGuard-tagged firewall rules' 'Rules created by policy or isolation can be removed by an administrator' }
elseif ($fw) { Add-Cap 'policy' 'unsupported' 'Windows Firewall (NetSecurity)' 'Changing firewall rules needs administrator rights; this account is not an administrator'; Add-Cap 'isolation' 'unsupported' 'Windows Firewall block-all with management exception' 'Isolation needs administrator rights'; Add-Cap 'undo' 'unsupported' 'Remove CyberGuard-tagged firewall rules' 'Nothing can be applied, so nothing can be undone' }
else { Add-Cap 'policy' 'inconclusive' 'Windows Firewall (NetSecurity)' 'Firewall profiles not readable'; Add-Cap 'isolation' 'inconclusive' 'Windows Firewall' 'Firewall profiles not readable'; Add-Cap 'undo' 'inconclusive' 'Windows Firewall' 'Firewall profiles not readable' }
Add-Cap 'port-shutdown' 'unsupported' 'not applicable' 'A host has no switch ports; port shutdown belongs to a switch connector'
$now = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
$event = [ordered]@{
    event_id = 'capprobe-' + [guid]::NewGuid().ToString(); kind = 'device.capability_probe'; observed_at = $now
    asset = [ordered]@{ external_id = $ref; hostname = $hostName; os_family = 'windows'; device_type = 'workstation'; addresses = @() }
    details = [ordered]@{ probe_id = 'local-' + $hostKey; device_ref = $ref; vendor = 'microsoft-windows'; model = [string]$os.Caption; version = [string]$os.Version; license = [ordered]@{ edition = [string]$os.Caption; features = @() }; probed_at = $now; probe_method = 'local-script'; capabilities = [object[]]$caps.ToArray() }
}
[System.IO.File]::WriteAllText($destination, ([ordered]@{ schema_version = 'cg.telemetry/1'; events = @($event) } | ConvertTo-Json -Depth 8 -Compress), (New-Object System.Text.UTF8Encoding($false)))
$supported = ($caps | ForEach-Object { if ($_['status'] -eq 'supported') { $_['capability'] } }) -join ', '
Write-Output ('Capability probe (administrator=' + $admin + '): supported ' + $supported + '. Nothing was changed. No upload performed.')
