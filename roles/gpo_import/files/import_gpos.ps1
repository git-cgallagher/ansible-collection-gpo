# import_gpos.ps1 — converge a domain on a git_cgallagher.gpo export.
#
# Runs on a Windows management host with RSAT (GroupPolicy + ActiveDirectory
# modules) in the TARGET domain. Invoked by roles/gpo_import via
# ansible.windows.win_powershell; also runnable standalone for debugging.
#
# Order of operations:
#   0. refuse any backup containing GPP cpassword
#   1. WMI filters (create missing ones only with -CreateWmiFilters)
#   2. GPO contents: Import-GPO -CreateIfNeeded [-MigrationTable] when the GPO
#      is missing, its backup content-hash changed since the last import
#      (state file, per domain), or -ForceImport
#   3. GPO properties: status, WMI filter link, security filtering (removed
#      Apply trustees are downgraded to Read, never stripped — MS16-072)
#   4. links: each manifest SOM's whole ordered list (order = precedence),
#      block-inheritance; unmanaged links reported, removed only with
#      -RemoveUnmanagedLinks
#
# -ReportOnly (and Ansible check mode) reports every action without touching
# the domain.
#
# Windows PowerShell 5.1-compatible. Keep '# region common' in sync with
# roles/gpo_backup/files/backup_gpos.ps1.

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)][string]$Domain,
    [string]$Server = '',
    [Parameter(Mandatory = $true)][string]$SourceDir,
    [string]$ManifestPath = 'gpo-manifest.json',
    [string]$MigrationTablePath = '',
    [string]$StateDir = 'C:\ProgramData\gpo-iac',
    [bool]$ReportOnly = $false,
    [bool]$RemoveUnmanagedLinks = $false,
    [bool]$CreateWmiFilters = $false,
    [bool]$ForceImport = $false,
    [string[]]$GpoNames = @()
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$inAnsible = $null -ne (Get-Variable -Name Ansible -ErrorAction SilentlyContinue)
$checkMode = $false
if ($inAnsible -and $Ansible.CheckMode) { $checkMode = $true }
if ($checkMode) { $ReportOnly = $true }

try {
    Import-Module GroupPolicy, ActiveDirectory
}
catch {
    throw "The GroupPolicy and ActiveDirectory PowerShell modules are required (install RSAT): $_"
}

# region common — keep in sync with backup_gpos.ps1
function ConvertTo-SafeName {
    param([string]$Name)
    $safe = $Name -replace '[\\/:*?"<>|]', '_'
    $safe = $safe.TrimEnd('.', ' ')
    if (-not $safe) { $safe = '_' }
    $safe
}

function Get-DirContentHash {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return '' }
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
    param([string]$BackupDir)
    $guidDir = Get-ChildItem -LiteralPath $BackupDir -Directory |
        Where-Object { $_.Name -match '^\{.+\}$' } | Select-Object -First 1
    if ($null -eq $guidDir) { return $BackupDir }
    $sysvol = Join-Path $guidDir.FullName 'DomainSysvol'
    if (Test-Path -LiteralPath $sysvol) { return $sysvol }
    return $guidDir.FullName
}

function Write-Utf8File {
    param([string]$Path, [string]$Content)
    $enc = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($Path, $Content, $enc)
}
# endregion common

function Get-YesNo { param([bool]$Value) if ($Value) { 'Yes' } else { 'No' } }

function ConvertTo-WmiFilterParm2 {
    # Single-query encoder; inverse of the parser in backup_gpos.ps1.
    param([string]$Namespace, [string]$Query)
    '1;3;{0};{1};WQL;{2};{3};' -f $Namespace.Length, $Query.Length, $Namespace, $Query
}

function Get-RelativeTrusteeName {
    param([string]$Name, [string]$NetBiosName)
    if ($Name -and $Name.Contains('\')) {
        $parts = $Name.Split('\', 2)
        if ($parts[0] -eq $NetBiosName) { return $parts[1] }
    }
    $Name
}

$actions = New-Object System.Collections.ArrayList
$warnings = New-Object System.Collections.ArrayList
$errors = New-Object System.Collections.ArrayList

function Invoke-Change {
    # Record the action; perform it unless this is a report-only run.
    param([string]$Description, [scriptblock]$Action)
    [void]$script:actions.Add($Description)
    if (-not $ReportOnly) { & $Action }
}

# --- load manifest + guardrails ----------------------------------------------
$manifestFile = Join-Path $SourceDir $ManifestPath
if (-not (Test-Path -LiteralPath $manifestFile)) {
    throw "Manifest not found: $manifestFile"
}
$manifest = Get-Content -LiteralPath $manifestFile -Raw -Encoding UTF8 | ConvertFrom-Json

$gposRoot = Join-Path $SourceDir 'gpos'
if (Test-Path -LiteralPath $gposRoot) {
    # GPP cpassword is deprecated, trivially decryptable, and a secret in Git.
    $hits = @(
        Get-ChildItem -LiteralPath $gposRoot -Recurse -Filter '*.xml' -File |
            Select-String -Pattern 'cpassword' -List
    )
    if ($hits.Count -gt 0) {
        $paths = ($hits | ForEach-Object { $_.Path }) -join '; '
        throw "Refusing to import: GPP cpassword found in: $paths. Remove the preference (use LAPS/gMSA instead) and re-export."
    }
}

$migTable = ''
if ($MigrationTablePath) {
    $migTable = $MigrationTablePath
    if (-not [System.IO.Path]::IsPathRooted($migTable)) {
        $migTable = Join-Path $SourceDir $MigrationTablePath
    }
    if (-not (Test-Path -LiteralPath $migTable)) {
        throw "Migration table not found: $migTable"
    }
}

# --- domain context + state ---------------------------------------------------
$adDomain = Get-ADDomain -Identity $Domain
$pdc = $Server
if (-not $pdc) { $pdc = $adDomain.PDCEmulator }
$rootDn = $adDomain.DistinguishedName
$netbios = $adDomain.NetBIOSName

if (-not (Test-Path -LiteralPath $StateDir)) {
    New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
}
$stateFile = Join-Path $StateDir ("import-state-{0}.json" -f $Domain.ToLowerInvariant())
$state = @{}
if (Test-Path -LiteralPath $stateFile) {
    $rawState = Get-Content -LiteralPath $stateFile -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($rawState.PSObject.Properties['gpos']) {
        foreach ($p in $rawState.gpos.PSObject.Properties) {
            $state[$p.Name] = [string]$p.Value.imported_hash
        }
    }
}
$newState = @{}

# --- 1. WMI filters ------------------------------------------------------------
$somContainer = "CN=SOM,CN=WMIPolicy,CN=System,$rootDn"
$liveFilters = @{}
foreach ($f in @(
        Get-ADObject -SearchBase $somContainer -SearchScope OneLevel -Server $pdc `
            -LDAPFilter '(objectClass=msWMI-Som)' -Properties msWMI-Name -ErrorAction SilentlyContinue
    )) {
    $liveFilters[[string]$f.'msWMI-Name'] = $f
}

$manifestFilters = @{}
if ($manifest.PSObject.Properties['wmi_filters'] -and $manifest.wmi_filters) {
    foreach ($p in $manifest.wmi_filters.PSObject.Properties) { $manifestFilters[$p.Name] = $p.Value }
}
foreach ($name in ($manifestFilters.Keys | Sort-Object)) {
    if ($liveFilters.ContainsKey($name)) { continue }
    $def = $manifestFilters[$name]
    if (-not $CreateWmiFilters) {
        [void]$warnings.Add("WMI filter '$name' does not exist in $Domain (set gpo_import_create_wmi_filters to create it)")
        continue
    }
    if (-not $def.query) {
        [void]$errors.Add("WMI filter '$name' has no parsed query in the manifest (multi-query filters are unsupported); create it manually")
        continue
    }
    $ns = $def.namespace
    if (-not $ns) { $ns = 'root\CIMv2' }
    Invoke-Change -Description "create WMI filter '$name'" -Action {
        $id = '{' + [guid]::NewGuid().ToString() + '}'
        $now = (Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss.ffffff-000')
        $desc = [string]$def.description
        if (-not $desc) { $desc = ' ' }   # empty msWMI-Parm1 breaks GPMC's filter list
        New-ADObject -Type 'msWMI-Som' -Name $id -Path $somContainer -Server $pdc -OtherAttributes @{
            'msWMI-Name' = $name
            'msWMI-Parm1' = $desc
            'msWMI-Parm2' = (ConvertTo-WmiFilterParm2 -Namespace $ns -Query ([string]$def.query))
            'msWMI-ID' = $id
            'msWMI-Author' = 'git_cgallagher.gpo'
            'msWMI-ChangeDate' = $now
            'msWMI-CreationDate' = $now
        } | Out-Null
    }
    if (-not $ReportOnly) {
        $created = Get-ADObject -SearchBase $somContainer -SearchScope OneLevel -Server $pdc `
            -LDAPFilter "(&(objectClass=msWMI-Som)(msWMI-Name=$name))" -Properties msWMI-Name |
            Select-Object -First 1
        if ($created) { $liveFilters[$name] = $created }
    }
}

# --- 2 + 3. GPO contents and properties ----------------------------------------
$manifestGpos = @{}
foreach ($p in $manifest.gpos.PSObject.Properties) { $manifestGpos[$p.Name] = $p.Value }
$gpoOrder = @($manifestGpos.Keys | Sort-Object)
if ($GpoNames.Count -gt 0) {
    $gpoOrder = @($gpoOrder | Where-Object { $GpoNames -contains $_ })
}

$importedCount = 0
foreach ($name in $gpoOrder) {
    try {
        $entry = $manifestGpos[$name]
        $backupDir = [string]$entry.backup_dir
        if (-not $backupDir) { $backupDir = ConvertTo-SafeName -Name $name }
        $wrapper = Join-Path $gposRoot $backupDir

        $liveGpo = Get-GPO -Name $name -Domain $Domain -Server $pdc -ErrorAction SilentlyContinue

        # -- contents --
        if (-not (Test-Path -LiteralPath $wrapper)) {
            if ($liveGpo) {
                [void]$warnings.Add("GPO '$name': no backup folder in the export; contents unmanaged, reconciling properties only")
            }
            else {
                [void]$errors.Add("GPO '$name': does not exist in $Domain and the export has no backup folder to create it from")
                continue
            }
        }
        else {
            $backupHash = Get-DirContentHash -Path (Get-GpoSysvolPath -BackupDir $wrapper)
            $newState[$name] = $backupHash
            $reason = ''
            if ($ForceImport) { $reason = 'forced' }
            elseif (-not $liveGpo) { $reason = 'GPO missing in target' }
            elseif (-not $state.ContainsKey($name)) { $reason = 'never imported by this pipeline' }
            elseif ($state[$name] -ne $backupHash) { $reason = 'backup content changed' }
            if ($reason) {
                $desc = "import GPO '$name' ($reason)"
                if ($migTable) { $desc += ' [migration table]' }
                Invoke-Change -Description $desc -Action {
                    $importArgs = @{
                        BackupGpoName = $name
                        Path = $wrapper
                        TargetName = $name
                        CreateIfNeeded = $true
                        Domain = $Domain
                        Server = $pdc
                    }
                    if ($migTable) { $importArgs.MigrationTable = $migTable }
                    Import-GPO @importArgs | Out-Null
                }
                $importedCount++
                if (-not $ReportOnly) {
                    $liveGpo = Get-GPO -Name $name -Domain $Domain -Server $pdc
                }
            }
            elseif (-not $ReportOnly) {
                # unchanged — keep the recorded hash
                $newState[$name] = $state[$name]
            }
        }

        if (-not $liveGpo) {
            # Report-only run against a GPO that doesn't exist yet: the
            # property/link work below needs the live object, so just plan it.
            [void]$actions.Add("set status/filtering/WMI filter on '$name' (after create)")
            continue
        }

        # -- status --
        $desiredStatus = [string]$entry.status
        if ($desiredStatus -and ($liveGpo.GpoStatus.ToString() -ne $desiredStatus)) {
            Invoke-Change -Description "GPO '$name': status $($liveGpo.GpoStatus) -> $desiredStatus" -Action {
                $liveGpo.GpoStatus = [Microsoft.GroupPolicy.GpoStatus]$desiredStatus
            }
        }

        # -- WMI filter link (gPCWQLFilter on the GPO's AD object) --
        $desiredFilter = $null
        if ($entry.PSObject.Properties['wmi_filter']) { $desiredFilter = $entry.wmi_filter }
        $currentFilter = $null
        if ($liveGpo.WmiFilter) { $currentFilter = $liveGpo.WmiFilter.Name }
        if ([string]$desiredFilter -ne [string]$currentFilter) {
            $gpoDn = 'CN={' + $liveGpo.Id.ToString() + '},CN=Policies,CN=System,' + $rootDn
            if (-not $desiredFilter) {
                Invoke-Change -Description "GPO '$name': clear WMI filter (was '$currentFilter')" -Action {
                    Set-ADObject -Identity $gpoDn -Clear 'gPCWQLFilter' -Server $pdc
                }
            }
            elseif ($liveFilters.ContainsKey([string]$desiredFilter)) {
                $filterCn = $liveFilters[[string]$desiredFilter].Name   # "{guid}"
                $value = '[{0};{1};0]' -f $Domain, $filterCn
                Invoke-Change -Description "GPO '$name': WMI filter '$currentFilter' -> '$desiredFilter'" -Action {
                    Set-ADObject -Identity $gpoDn -Replace @{ gPCWQLFilter = $value } -Server $pdc
                }
            }
            elseif ($ReportOnly -and $CreateWmiFilters) {
                [void]$actions.Add("GPO '$name': link WMI filter '$desiredFilter' (after create)")
            }
            else {
                [void]$errors.Add("GPO '$name': WMI filter '$desiredFilter' not found in $Domain; filter link not set")
            }
        }

        # -- security filtering (GpoApply) --
        if ($entry.PSObject.Properties['apply_to'] -and $null -ne $entry.apply_to) {
            $desiredApply = @{}
            foreach ($t in @($entry.apply_to)) { $desiredApply[([string]$t.name).ToLowerInvariant()] = $t }
            $currentApply = @{}
            foreach ($perm in @(
                    Get-GPPermission -Guid $liveGpo.Id -All -Domain $Domain -Server $pdc |
                        Where-Object { [string]$_.Permission -eq 'GpoApply' }
                )) {
                $relName = Get-RelativeTrusteeName -Name ([string]$perm.Trustee.Name) -NetBiosName $netbios
                $sidType = [string]$perm.Trustee.SidType
                $relType = 'Group'
                if ($sidType -eq 'User') { $relType = 'User' }
                elseif ($sidType -eq 'Computer') { $relType = 'Computer' }
                $currentApply[$relName.ToLowerInvariant()] = @{ name = $relName; type = $relType }
            }
            foreach ($key in ($desiredApply.Keys | Sort-Object)) {
                if ($currentApply.ContainsKey($key)) { continue }
                $t = $desiredApply[$key]
                Invoke-Change -Description "GPO '$name': grant Apply to $($t.type) '$($t.name)'" -Action {
                    Set-GPPermission -Guid $liveGpo.Id -Domain $Domain -Server $pdc `
                        -TargetName ([string]$t.name) -TargetType ([string]$t.type) `
                        -PermissionLevel GpoApply | Out-Null
                }
            }
            foreach ($key in ($currentApply.Keys | Sort-Object)) {
                if ($desiredApply.ContainsKey($key)) { continue }
                $t = $currentApply[$key]
                # Downgrade to Read, never remove outright: a principal that
                # cannot read a GPO cannot process it at all (MS16-072).
                Invoke-Change -Description "GPO '$name': downgrade '$($t.name)' from Apply to Read" -Action {
                    Set-GPPermission -Guid $liveGpo.Id -Domain $Domain -Server $pdc `
                        -TargetName ([string]$t.name) -TargetType ([string]$t.type) `
                        -PermissionLevel GpoRead -Replace | Out-Null
                }
            }
        }
    }
    catch {
        [void]$errors.Add("GPO '$name': $($_.Exception.Message)")
    }
}

# --- 4. links, precedence, inheritance ------------------------------------------
$soms = @()
if ($manifest.PSObject.Properties['soms'] -and $manifest.soms) { $soms = @($manifest.soms) }
foreach ($som in $soms) {
    $target = [string]$som.target
    try {
        try {
            Get-ADObject -Identity $target -Server $pdc | Out-Null
        }
        catch {
            [void]$errors.Add("SOM '$target' does not exist in $Domain; links not applied")
            continue
        }

        $inh = Get-GPInheritance -Target $target -Domain $Domain -Server $pdc
        $blocked = [bool]$inh.GpoInheritanceBlocked
        $desiredBlocked = [bool]$som.block_inheritance
        if ($blocked -ne $desiredBlocked) {
            Invoke-Change -Description "SOM '$target': block inheritance -> $desiredBlocked" -Action {
                Set-GPInheritance -Target $target -Domain $Domain -Server $pdc `
                    -IsBlocked (Get-YesNo $desiredBlocked) | Out-Null
            }
        }

        # Reconcile the whole ordered list against a simulated work-list:
        # Set-GPLink -Order renumbers neighbours, so per-link checks against a
        # stale snapshot don't converge — tracking positions locally does.
        $work = New-Object System.Collections.ArrayList
        foreach ($l in @($inh.GpoLinks | Sort-Object Order)) {
            [void]$work.Add(@{ name = $l.DisplayName; enforced = [bool]$l.Enforced; enabled = [bool]$l.Enabled })
        }
        $desired = @($som.links)
        for ($i = 0; $i -lt $desired.Count; $i++) {
            $d = $desired[$i]
            $dName = [string]$d.gpo
            $dEnf = [bool]$d.enforced
            $dEna = [bool]$d.enabled
            $pos = $i + 1
            $idx = -1
            for ($j = 0; $j -lt $work.Count; $j++) {
                if ([string]$work[$j].name -ieq $dName) { $idx = $j; break }
            }
            try {
                if ($idx -lt 0) {
                    Invoke-Change -Description "SOM '$target': link '$dName' at order $pos (enforced=$dEnf, enabled=$dEna)" -Action {
                        New-GPLink -Name $dName -Target $target -Domain $Domain -Server $pdc `
                            -LinkEnabled (Get-YesNo $dEna) -Enforced (Get-YesNo $dEnf) -Order $pos | Out-Null
                    }
                    $work.Insert([Math]::Min($i, $work.Count), @{ name = $dName; enforced = $dEnf; enabled = $dEna })
                }
                else {
                    $cur = $work[$idx]
                    if (($idx -ne $i) -or ($cur.enforced -ne $dEnf) -or ($cur.enabled -ne $dEna)) {
                        Invoke-Change -Description "SOM '$target': set link '$dName' order $pos (enforced=$dEnf, enabled=$dEna)" -Action {
                            Set-GPLink -Name $dName -Target $target -Domain $Domain -Server $pdc `
                                -LinkEnabled (Get-YesNo $dEna) -Enforced (Get-YesNo $dEnf) -Order $pos | Out-Null
                        }
                        $work.RemoveAt($idx)
                        $work.Insert([Math]::Min($i, $work.Count), @{ name = $dName; enforced = $dEnf; enabled = $dEna })
                    }
                }
            }
            catch {
                [void]$errors.Add("SOM '$target', link '$dName': $($_.Exception.Message)")
            }
        }

        $desiredNames = @($desired | ForEach-Object { ([string]$_.gpo).ToLowerInvariant() })
        foreach ($w in @($work)) {
            if ($desiredNames -contains ([string]$w.name).ToLowerInvariant()) { continue }
            if ($RemoveUnmanagedLinks) {
                $wName = [string]$w.name
                Invoke-Change -Description "SOM '$target': remove unmanaged link '$wName'" -Action {
                    Remove-GPLink -Name $wName -Target $target -Domain $Domain -Server $pdc | Out-Null
                }
            }
            else {
                [void]$warnings.Add("SOM '$target': unmanaged link '$($w.name)' left in place (gpo_import_remove_unmanaged_links not set)")
            }
        }
    }
    catch {
        [void]$errors.Add("SOM '$target': $($_.Exception.Message)")
    }
}

# --- state + result -------------------------------------------------------------
if (-not $ReportOnly) {
    $stateOut = [ordered]@{ gpos = [ordered]@{} }
    foreach ($name in ($newState.Keys | Sort-Object)) {
        $stateOut.gpos[$name] = [ordered]@{ imported_hash = $newState[$name] }
    }
    Write-Utf8File -Path $stateFile -Content ($stateOut | ConvertTo-Json -Depth 10)
}

$failed = ($errors.Count -gt 0)
$changed = $false
if ($ReportOnly) {
    if ($checkMode) { $changed = ($actions.Count -gt 0) }
}
else {
    $changed = ($actions.Count -gt 0)
}

$result = @{
    report_only = $ReportOnly
    actions = @($actions)
    warnings = @($warnings)
    errors = @($errors)
    imported = $importedCount
    gpo_count = $gpoOrder.Count
    som_count = $soms.Count
    server = $pdc
}

if ($inAnsible) {
    $Ansible.Changed = $changed
    $Ansible.Result = $result
    if ($failed) { $Ansible.Failed = $true }
}
else {
    $result | ConvertTo-Json -Depth 6
    if ($failed) { throw "gpo_import finished with $($errors.Count) error(s); see result.errors" }
}
