<#
CG-014 read-only identity snapshot. Default: this Windows host's local accounts, local groups and
their members, with privileged built-in groups flagged by well-known SID. With
-IncludeActiveDirectory on a domain-joined host it also reads AD users and the members of
privileged AD groups through LDAP (read only). Changes nothing; stores no password or hash.
Output: a cg.telemetry/1 file with identity.directory_snapshot event(s). No upload performed.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [switch]$IncludeActiveDirectory
)
$ErrorActionPreference = 'Stop'
$destination = [System.IO.Path]::GetFullPath($OutputPath)
if (Test-Path -LiteralPath $destination) { throw 'Output already exists. Choose a new private file path.' }
if (-not (Test-Path -LiteralPath (Split-Path -Parent $destination) -PathType Container)) { throw 'Output directory must exist and be private.' }
function Get-SafeText([string]$text) { if ($null -eq $text) { return $null }; $t = ($text -replace '[\x00-\x1F\x7F]', '').Trim(); if ($t.Length -gt 300) { $t = $t.Substring(0, 300) }; return $t }
function Get-Iso($date) { return ([datetime]$date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ') }
$now = Get-Date
$hostName = [System.Net.Dns]::GetHostName()
$sha = [System.Security.Cryptography.SHA256]::Create()
$hostKey = (($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($hostName + '|windows')) | ForEach-Object { $_.ToString('x2') }) -join '').Substring(0, 24)
$addresses = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -match '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)' } | ForEach-Object { $_.IPAddress } | Select-Object -Unique)
$asset = [ordered]@{ external_id = 'managed-' + $hostKey; hostname = $hostName; os_family = 'windows'; device_type = 'workstation'; addresses = $addresses }
# Built-in groups that grant administrative or remote control rights.
$privilegedSids = @('S-1-5-32-544', 'S-1-5-32-547', 'S-1-5-32-548', 'S-1-5-32-549', 'S-1-5-32-551', 'S-1-5-32-555', 'S-1-5-32-578', 'S-1-5-32-580')
$events = @()

# Windows local directory
$principals = @(); $memberships = @()
foreach ($u in @(Get-LocalUser)) { $principals += [ordered]@{ principal_ref = (Get-SafeText ('user:' + $u.Name)); type = 'user'; enabled = [bool]$u.Enabled; privileged = $false } }
foreach ($g in @(Get-LocalGroup)) {
    $isPrivileged = $privilegedSids -contains $g.SID.Value
    $principals += [ordered]@{ principal_ref = (Get-SafeText ('group:' + $g.Name)); type = 'group'; enabled = $null; privileged = $isPrivileged }
    try { foreach ($m in @(Get-LocalGroupMember -Group $g -ErrorAction Stop)) { $memberships += [ordered]@{ group_ref = (Get-SafeText ('group:' + $g.Name)); member_ref = (Get-SafeText ('member:' + $m.Name)); privileged_group = $isPrivileged } } } catch { }
}
$privilegedMembers = @($memberships | Where-Object { $_.privileged_group } | ForEach-Object { $_.member_ref -replace '^member:.*\\', 'user:' } | Select-Object -Unique)
foreach ($p in $principals) { if ($p.type -eq 'user' -and $privilegedMembers -contains $p.principal_ref) { $p.privileged = $true } }
$events += [ordered]@{
    event_id = 'identity-' + [guid]::NewGuid().ToString(); kind = 'identity.directory_snapshot'; observed_at = (Get-Iso $now); asset = $asset
    details = [ordered]@{ snapshot_id = 'local-' + $hostKey + '-' + $now.ToUniversalTime().ToString('yyyyMMddHHmmss'); directory = [ordered]@{ type = 'windows-local'; ref = 'local:' + $hostName }; connector = [ordered]@{ method = 'local-api'; read_only = $true; credential_ref = $null }; principals = @($principals | Select-Object -First 5000); memberships = @($memberships | Select-Object -First 20000); privileges = @() }
}

# Active Directory (explicit, domain-joined only)
$system = Get-CimInstance -ClassName Win32_ComputerSystem
if ($IncludeActiveDirectory) {
    if (-not $system.PartOfDomain) { throw 'This host is not joined to an Active Directory domain.' }
    $adPrincipals = @(); $adMemberships = @()
    $users = [adsisearcher]'(&(objectCategory=person)(objectClass=user))'; $users.PageSize = 500; $users.SizeLimit = 20000
    foreach ($p in @('samaccountname', 'useraccountcontrol')) { [void]$users.PropertiesToLoad.Add($p) }
    foreach ($r in $users.FindAll()) { $uac = [int]($r.Properties['useraccountcontrol'] | Select-Object -First 1); $adPrincipals += [ordered]@{ principal_ref = (Get-SafeText ('user:' + ($r.Properties['samaccountname'] | Select-Object -First 1))); type = 'user'; enabled = -not ($uac -band 2); privileged = $false } }
    $groups = [adsisearcher]'(&(objectCategory=group)(adminCount=1))'; $groups.PageSize = 500
    foreach ($p in @('samaccountname', 'member')) { [void]$groups.PropertiesToLoad.Add($p) }
    foreach ($r in $groups.FindAll()) {
        $gname = Get-SafeText ('group:' + ($r.Properties['samaccountname'] | Select-Object -First 1))
        $adPrincipals += [ordered]@{ principal_ref = $gname; type = 'group'; enabled = $null; privileged = $true }
        foreach ($dn in @($r.Properties['member'])) { $cn = ([string]$dn -split ',')[0] -replace '^CN=', ''; $adMemberships += [ordered]@{ group_ref = $gname; member_ref = (Get-SafeText ('member:' + $cn)); privileged_group = $true } }
    }
    $events += [ordered]@{
        event_id = 'identity-' + [guid]::NewGuid().ToString(); kind = 'identity.directory_snapshot'; observed_at = (Get-Iso $now); asset = $asset
        details = [ordered]@{ snapshot_id = 'ad-' + $system.Domain + '-' + $now.ToUniversalTime().ToString('yyyyMMddHHmmss'); directory = [ordered]@{ type = 'active-directory'; ref = 'ad:' + $system.Domain }; connector = [ordered]@{ method = 'ldap'; read_only = $true; credential_ref = 'machine-context:' + $system.Domain }; principals = @($adPrincipals | Select-Object -First 5000); memberships = @($adMemberships | Select-Object -First 20000); privileges = @() }
    }
}
[System.IO.File]::WriteAllText($destination, ([ordered]@{ schema_version = 'cg.telemetry/1'; events = $events } | ConvertTo-Json -Depth 8 -Compress), (New-Object System.Text.UTF8Encoding($false)))
Write-Output ('Identity snapshot written: {0} directory snapshot(s), {1} local principals, {2} local memberships. No upload performed.' -f $events.Count, $principals.Count, $memberships.Count)
