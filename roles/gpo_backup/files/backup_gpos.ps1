# backup_gpos.ps1 — export a domain's GPOs + topology manifest for git_cgallagher.gpo.
#
# Runs on a Windows management host with RSAT (GroupPolicy + ActiveDirectory modules).
# Invoked by roles/gpo_backup via ansible.windows.win_powershell, but also runnable
# standalone for debugging (prints its result as JSON).
#
# Output layout (zipped into <WorkDir>\gpo-export.zip):
#   export\gpos\<SafeName>\manifest.xml + {backup-guid}\...   one self-contained
#       Backup-GPO folder per GPO — only GPOs whose DomainSysvol content changed
#       since the last run are included (state file keeps the hashes)
#   export\gpo-manifest.json                                  always included
#
# Windows PowerShell 5.1-compatible. Keep '# region common' in sync with
# roles/gpo_import/files/import_gpos.ps1.

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)][string]$Domain,
    [string]$Server = '',
    [Parameter(Mandatory = $true)][string]$WorkDir,
    [string[]]$GpoNames = @(),
    [bool]$FullExport = $false,
    # The role runs this task with check_mode: false (the export must run to
    # compute its report), so Ansible's check mode arrives as a parameter.
    [bool]$CheckMode = $false
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$inAnsible = $null -ne (Get-Variable -Name Ansible -ErrorAction SilentlyContinue)
$checkMode = $CheckMode
if ($inAnsible -and $Ansible.CheckMode) { $checkMode = $true }

try {
    Import-Module GroupPolicy, ActiveDirectory
}
catch {
    throw "The GroupPolicy and ActiveDirectory PowerShell modules are required (install RSAT): $_"
}

# region common — keep in sync with import_gpos.ps1
function ConvertTo-SafeName {
    param([string]$Name)
    $safe = $Name -replace '[\\/:*?"<>|]', '_'
    $safe = $safe.TrimEnd('.', ' ')
    if (-not $safe) { $safe = '_' }
    $safe
}

function Get-DirContentHash {
    # Deterministic hash of a directory tree: relative paths (case-folded) +
    # per-file SHA256. Empty directories count, so a GPO gaining or losing an
    # empty User/ folder still registers.
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return '' }
    $base = (Get-Item -LiteralPath $Path).FullName
    $sb = New-Object System.Text.StringBuilder
    $items = Get-ChildItem -LiteralPath $base -Recurse -Force |
        Sort-Object { $_.FullName.Substring($base.Length).ToLowerInvariant() }
    foreach ($it in $items) {
        $rel = $it.FullName.Substring($base.Length).TrimStart('\').ToLowerInvariant()
        if ($it.PSIsContainer) {
            [void]$sb.AppendLine("dir|$rel")
        }
        else {
            $h = (Get-FileHash -LiteralPath $it.FullName -Algorithm SHA256).Hash
            [void]$sb.AppendLine("file|$rel|$h")
        }
    }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($sb.ToString())
        ([System.BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '')
    }
    finally { $sha.Dispose() }
}

function Get-StringHash {
    param([string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        ([System.BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '')
    }
    finally { $sha.Dispose() }
}

function Get-GpoSysvolPath {
    # Inside a Backup-GPO folder, the settings payload lives under
    # {backup-guid}\DomainSysvol. Hashing only that subtree keeps the hash
    # stable across re-backups (Backup.xml / bkupInfo.xml / gpreport.xml
    # carry timestamps and a fresh backup GUID every time). A GPO with no
    # settings has no DomainSysvol: return $null (hashes as '') rather than
    # fall back to those volatile files, or it would re-ship on every run.
    param([string]$BackupDir)
    $guidDir = Get-ChildItem -LiteralPath $BackupDir -Directory |
        Where-Object { $_.Name -match '^\{.+\}$' } | Select-Object -First 1
    if ($null -eq $guidDir) { return $null }
    $sysvol = Join-Path $guidDir.FullName 'DomainSysvol'
    if (Test-Path -LiteralPath $sysvol) { return $sysvol }
    return $null
}

function Write-Utf8File {
    param([string]$Path, [string]$Content)
    $enc = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($Path, $Content, $enc)
}
# endregion common

function New-ZipFromDirectory {
    # Entries are written one by one so that (a) names use forward slashes —
    # some .NET Framework / PowerShell 5.1 combinations write backslashes,
    # which Linux unzip warns about and Ansible's unarchive treats as failure —
    # and (b) empty directories get explicit entries (GPO backups contain
    # them; Compress-Archive drops them).
    param([string]$Source, [string]$Destination)
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    $base = (Get-Item -LiteralPath $Source).FullName.TrimEnd('\') + '\'
    $zip = [System.IO.Compression.ZipFile]::Open($Destination, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($item in Get-ChildItem -LiteralPath $base -Recurse -Force) {
            $rel = $item.FullName.Substring($base.Length).Replace('\', '/')
            if ($item.PSIsContainer) {
                if (-not (Get-ChildItem -LiteralPath $item.FullName -Force | Select-Object -First 1)) {
                    [void]$zip.CreateEntry($rel + '/')
                }
            }
            else {
                [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $item.FullName, $rel)
            }
        }
    }
    finally { $zip.Dispose() }
}

function ConvertFrom-WmiFilterParm2 {
    # msWMI-Parm2 single-query form: "1;3;<nsLen>;<qLen>;WQL;<namespace>;<query>;"
    param([string]$Parm2)
    try {
        $i = $Parm2.IndexOf(';')
        $count = [int]$Parm2.Substring(0, $i)
        if ($count -ne 1) { return $null }   # multi-query: keep raw only
        $parts = $Parm2.Substring($i + 1).Split(';', 4)
        $nsLen = [int]$parts[1]
        $qLen = [int]$parts[2]
        $tail = $parts[3]
        $tail = $tail.Substring($tail.IndexOf(';') + 1)   # skip the language token (WQL)
        @{
            namespace = $tail.Substring(0, $nsLen)
            query = $tail.Substring($nsLen + 1, $qLen)
        }
    }
    catch { $null }
}

function ConvertTo-RelativeDn {
    # Link targets are stored relative to the domain root ('' = the root
    # itself), so the manifest imports into a domain with another name.
    param([string]$Dn, [string]$RootDn)
    if ($Dn -ieq $RootDn) { return '' }
    $suffix = ',' + $RootDn
    if ($Dn.EndsWith($suffix, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $Dn.Substring(0, $Dn.Length - $suffix.Length)
    }
    throw "'$Dn' is not inside '$RootDn'"
}

function Test-Denied {
    # A Deny entry (typically "Deny Apply group policy" to exclude admins) must
    # never be mistaken for an Apply grant.
    param($Permission)
    [bool]($Permission.PSObject.Properties['Denied'] -and $Permission.Denied)
}

function Get-TrusteeEntry {
    # Store trustees domain-relative so the manifest imports into any domain
    # following the same naming convention (relative-name mapping).
    param($Permission, [string]$NetBiosName)
    $name = [string]$Permission.Trustee.Name
    if ($name -and $name.Contains('\')) {
        $parts = $name.Split('\', 2)
        if ($parts[0] -eq $NetBiosName) { $name = $parts[1] }
    }
    $type = 'Group'
    $sidType = [string]$Permission.Trustee.SidType
    if ($sidType -eq 'User') { $type = 'User' }
    elseif ($sidType -eq 'Computer') { $type = 'Computer' }
    [ordered]@{ name = $name; type = $type }
}

# --- resolve domain context -------------------------------------------------
$adDomain = Get-ADDomain -Identity $Domain
$pdc = $Server
if (-not $pdc) { $pdc = $adDomain.PDCEmulator }
$rootDn = $adDomain.DistinguishedName
$netbios = $adDomain.NetBIOSName

# --- state ------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $WorkDir)) {
    New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
}
$stateFile = Join-Path $WorkDir ("backup-state-{0}.json" -f $Domain.ToLowerInvariant())
$state = @{ gpos = @{}; manifest_hash = '' }
if (Test-Path -LiteralPath $stateFile) {
    $rawState = Get-Content -LiteralPath $stateFile -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($rawState.PSObject.Properties['gpos']) {
        foreach ($p in $rawState.gpos.PSObject.Properties) {
            $state.gpos[$p.Name] = @{ hash = [string]$p.Value.hash; dir = [string]$p.Value.dir }
        }
    }
    if ($rawState.PSObject.Properties['manifest_hash']) {
        $state.manifest_hash = [string]$rawState.manifest_hash
    }
}

# --- staging ----------------------------------------------------------------
$stage = Join-Path $WorkDir 'stage'
if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
$rawRoot = Join-Path $stage 'raw'
$exportRoot = Join-Path $stage 'export'
$exportGpos = Join-Path $exportRoot 'gpos'
New-Item -ItemType Directory -Path $rawRoot, $exportGpos -Force | Out-Null

# --- back up every (selected) GPO -------------------------------------------
$live = Get-GPO -All -Domain $Domain -Server $pdc | Sort-Object DisplayName
if ($GpoNames.Count -gt 0) {
    $live = $live | Where-Object { $GpoNames -contains $_.DisplayName }
}

$safeSeen = @{}
$shipped = New-Object System.Collections.ArrayList
$backupErrors = New-Object System.Collections.ArrayList
$newState = @{ gpos = @{}; manifest_hash = '' }

foreach ($gpo in $live) {
    $safe = ConvertTo-SafeName -Name $gpo.DisplayName
    if ($safeSeen.ContainsKey($safe.ToLowerInvariant())) {
        throw ("GPO display names '{0}' and '{1}' map to the same folder name '{2}'; rename one." -f
            $safeSeen[$safe.ToLowerInvariant()], $gpo.DisplayName, $safe)
    }
    $safeSeen[$safe.ToLowerInvariant()] = $gpo.DisplayName

    # One broken GPO (missing SYSVOL folder, unreadable ACL) must not hide the
    # others: collect every failure, then fail the run without saving state.
    try {
        $rawDir = Join-Path $rawRoot $safe
        New-Item -ItemType Directory -Path $rawDir -Force | Out-Null
        Backup-GPO -Guid $gpo.Id -Domain $Domain -Server $pdc -Path $rawDir `
            -Comment 'git_cgallagher.gpo export' | Out-Null
        $hash = Get-DirContentHash -Path (Get-GpoSysvolPath -BackupDir $rawDir)
    }
    catch {
        [void]$backupErrors.Add("GPO '$($gpo.DisplayName)': $($_.Exception.Message)")
        $newState.gpos[$gpo.DisplayName] = @{ hash = ''; dir = $safe }
        continue
    }
    $newState.gpos[$gpo.DisplayName] = @{ hash = $hash; dir = $safe }

    $prev = $null
    if ($state.gpos.ContainsKey($gpo.DisplayName)) { $prev = $state.gpos[$gpo.DisplayName].hash }
    if ($FullExport -or ($hash -ne $prev)) {
        Move-Item -LiteralPath $rawDir -Destination (Join-Path $exportGpos $safe)
        [void]$shipped.Add(@{ name = $gpo.DisplayName; backup_dir = $safe })
    }
}

# GPOs recorded in state but gone from the domain (skip when filtering: an
# unselected GPO is not a deleted one).
$deleted = New-Object System.Collections.ArrayList
if ($GpoNames.Count -eq 0) {
    foreach ($name in $state.gpos.Keys) {
        if (-not $newState.gpos.ContainsKey($name)) {
            [void]$deleted.Add(@{ name = $name; backup_dir = $state.gpos[$name].dir })
        }
    }
}

# --- build the topology manifest ---------------------------------------------
$manifest = [ordered]@{
    domain = $Domain
    netbios = $netbios
    root_dn = $rootDn
    domain_sid = $adDomain.DomainSID.Value
    gpos = [ordered]@{}
    wmi_filters = [ordered]@{}
    soms = @()
}

foreach ($gpo in $live) {
    $wmiName = $null
    if ($gpo.WmiFilter) { $wmiName = $gpo.WmiFilter.Name }
    $perms = @(Get-GPPermission -Guid $gpo.Id -All -Domain $Domain -Server $pdc)
    $applyTo = @(
        $perms | Where-Object { [string]$_.Permission -eq 'GpoApply' -and -not (Test-Denied $_) } |
            ForEach-Object { Get-TrusteeEntry -Permission $_ -NetBiosName $netbios } |
            Sort-Object { $_['name'] }
    )
    # Recorded so they're visible in Git and checked on import; this
    # collection can't create Deny entries (Set-GPPermission has no deny).
    $denied = @(
        $perms | Where-Object { Test-Denied $_ } | ForEach-Object {
            $trustee = Get-TrusteeEntry -Permission $_ -NetBiosName $netbios
            $trustee['permission'] = [string]$_.Permission
            $trustee
        } | Sort-Object { $_['name'] }
    )
    $manifest.gpos[$gpo.DisplayName] = [ordered]@{
        backup_dir = $newState.gpos[$gpo.DisplayName].dir
        status = $gpo.GpoStatus.ToString()
        wmi_filter = $wmiName
        apply_to = $applyTo
        denied = $denied
    }
}

$somContainer = "CN=SOM,CN=WMIPolicy,CN=System,$rootDn"
$filters = @(
    Get-ADObject -SearchBase $somContainer -SearchScope OneLevel -Server $pdc `
        -LDAPFilter '(objectClass=msWMI-Som)' `
        -Properties msWMI-Name, msWMI-Parm1, msWMI-Parm2 -ErrorAction SilentlyContinue
) | Sort-Object { [string]$_.'msWMI-Name' }
foreach ($f in $filters) {
    $parsed = ConvertFrom-WmiFilterParm2 -Parm2 ([string]$f.'msWMI-Parm2')
    $entry = [ordered]@{
        description = [string]$f.'msWMI-Parm1'
        namespace = $null
        query = $null
        raw_parm2 = [string]$f.'msWMI-Parm2'
    }
    if ($parsed) {
        $entry.namespace = $parsed.namespace
        $entry.query = $parsed.query
    }
    $manifest.wmi_filters[[string]$f.'msWMI-Name'] = $entry
}

# Scopes of management: the domain root plus every OU, shallowest first.
$somDns = @($rootDn) + @(
    Get-ADOrganizationalUnit -Filter * -SearchBase $rootDn -Server $pdc |
        Select-Object -ExpandProperty DistinguishedName |
        Sort-Object @{ Expression = { ($_ -split ',(?=OU=|DC=)').Count } }, @{ Expression = { $_ } }
)
foreach ($dn in $somDns) {
    $inh = Get-GPInheritance -Target $dn -Domain $Domain -Server $pdc
    $blocked = [bool]$inh.GpoInheritanceBlocked
    $links = @(
        $inh.GpoLinks | Sort-Object Order | ForEach-Object {
            [ordered]@{
                gpo = $_.DisplayName
                enforced = [bool]$_.Enforced
                enabled = [bool]$_.Enabled
            }
        }
    )
    if ($links.Count -gt 0 -or $blocked) {
        $manifest.soms += , ([ordered]@{
                target = ConvertTo-RelativeDn -Dn $dn -RootDn $rootDn
                block_inheritance = $blocked
                links = $links
            })
    }
}

$manifestJson = $manifest | ConvertTo-Json -Depth 10
Write-Utf8File -Path (Join-Path $exportRoot 'gpo-manifest.json') -Content $manifestJson
$manifestHash = Get-StringHash -Text $manifestJson
$newState.manifest_hash = $manifestHash
$manifestChanged = ($manifestHash -ne $state.manifest_hash)

# --- zip + state -------------------------------------------------------------
$zipPath = Join-Path $WorkDir 'gpo-export.zip'
if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
New-ZipFromDirectory -Source $exportRoot -Destination $zipPath

$changed = ($shipped.Count -gt 0) -or ($deleted.Count -gt 0) -or $manifestChanged
# A failed GPO must not be "used up": with errors, keep the old state so the
# next run re-exports everything that changed.
if (-not $checkMode -and $backupErrors.Count -eq 0) {
    $stateOut = [ordered]@{ gpos = [ordered]@{}; manifest_hash = $newState.manifest_hash }
    foreach ($name in ($newState.gpos.Keys | Sort-Object)) {
        $stateOut.gpos[$name] = [ordered]@{
            hash = $newState.gpos[$name].hash
            dir = $newState.gpos[$name].dir
        }
    }
    Write-Utf8File -Path $stateFile -Content ($stateOut | ConvertTo-Json -Depth 10)
}

$result = @{
    changed = $changed
    shipped = @($shipped)
    deleted = @($deleted)
    manifest_changed = $manifestChanged
    gpo_count = @($live).Count
    zip = $zipPath
    server = $pdc
    errors = @($backupErrors)
}

if ($inAnsible) {
    $Ansible.Changed = $changed
    $Ansible.Result = $result
    if ($backupErrors.Count -gt 0) { $Ansible.Failed = $true }
}
else {
    $result | ConvertTo-Json -Depth 6
    if ($backupErrors.Count -gt 0) { throw "gpo_backup failed for $($backupErrors.Count) GPO(s); see result.errors" }
}
