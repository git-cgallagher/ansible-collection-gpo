# lab_fixture.ps1 — test fixture for the domain_lab Molecule scenario.
#
#   -Action Seed   the "authored" domain state that gpo_backup exports:
#                  OUs, a group, a WMI filter and three GPOs covering three
#                  setting types (Admin Templates, Preferences, security
#                  settings), with link order, enforcement, a disabled link,
#                  block-inheritance, security filtering and GPO status.
#   -Action Drift  out-of-band changes that gpo_import must undo.
#
# Wherever GPMC has an API (WMI filter linking, links, permissions, status)
# the fixture uses it, so the roles are checked against GPMC rather than
# against themselves.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet('Seed', 'Drift')][string]$Action,
    [Parameter(Mandatory = $true)][string]$Domain,
    [Parameter(Mandatory = $true)][string]$FixtureJson
)

$ErrorActionPreference = 'Stop'
Import-Module GroupPolicy, ActiveDirectory

$fx = $FixtureJson | ConvertFrom-Json
$adDomain = Get-ADDomain -Identity $Domain
$pdc = $adDomain.PDCEmulator
$rootDn = $adDomain.DistinguishedName
$ouDn = "OU=$($fx.ou),$rootDn"
$serversDn = "OU=Servers,$ouDn"
$workstationsDn = "OU=Workstations,$ouDn"
$somContainer = "CN=SOM,CN=WMIPolicy,CN=System,$rootDn"
$done = New-Object System.Collections.ArrayList
$diag = [ordered]@{}

function Get-LdapEntry {
    param([string]$Dn)
    New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList "LDAP://$pdc/$Dn"
}

function Set-AdAttributeLdap {
    # ADSI/LDAP: the mechanism GPMC itself uses. In the lab, Set-ADObject
    # (AD Web Services) was refused (8344) writing a GPO's AD object as Domain
    # Admin while GPMC's writes to the same objects succeeded; cause unconfirmed.
    param([string]$Dn, [hashtable]$Values)
    $entry = Get-LdapEntry -Dn $Dn
    try {
        foreach ($key in $Values.Keys) { $entry.Properties[$key].Value = $Values[$key] }
        $entry.CommitChanges()
    }
    catch {
        $aces = @($entry.ObjectSecurity.Access | ForEach-Object {
                '{0}:{1}:{2}' -f $_.IdentityReference, $_.AccessControlType, $_.ActiveDirectoryRights
            })
        throw "LDAP write to $Dn failed: $($_.Exception.Message) ACL: $($aces -join ' | ')"
    }
    finally { $entry.Dispose() }
}

function Get-SessionDiagnostic {
    # Which groups this session's token carries, and whether an AD Web
    # Services modify of a GPO's AD object is allowed (writes back the same
    # versionNumber; non-fatal).
    param([Guid]$GpoId)
    $groups = @(whoami.exe /groups /fo csv | ConvertFrom-Csv |
            Where-Object { $_.'Group Name' -match 'Domain Admins|Enterprise Admins|Administrators|Policy Creator' } |
            ForEach-Object { $_.'Group Name' })
    $dn = Get-GpoDn -Id $GpoId
    $probe = 'allowed'
    try {
        $current = (Get-ADObject -Identity $dn -Properties versionNumber -Server $pdc).versionNumber
        Set-ADObject -Identity $dn -Replace @{ versionNumber = $current } -Server $pdc
    }
    catch {
        $probe = "denied: $($_.Exception.Message)"
    }
    [ordered]@{ user = (whoami.exe); groups = $groups; adws_modify_gpc = $probe }
}

function Test-AdObject {
    param([string]$Dn)
    try {
        $null = Get-ADObject -Identity $Dn -Server $pdc
        $true
    }
    catch {
        $false
    }
}

function Get-GpoOrNull {
    param([string]$Name)
    try {
        Get-GPO -Name $Name -Domain $Domain -Server $pdc -ErrorAction Stop
    }
    catch {
        if ($_.FullyQualifiedErrorId -like 'GpoWithNameNotFound*') { return $null }
        throw
    }
}

function Get-GpoDn {
    param([Guid]$Id)
    'CN={' + $Id.ToString().ToUpperInvariant() + '},CN=Policies,CN=System,' + $rootDn
}

function Get-WmiFilterObject {
    param([string]$Name)
    Get-ADObject -SearchBase $somContainer -SearchScope OneLevel -Server $pdc `
        -LDAPFilter "(&(objectClass=msWMI-Som)(msWMI-Name=$Name))" -Properties 'msWMI-Name', 'msWMI-Parm2'
}

function Set-LabPasswordPolicy {
    # Security settings have no GPMC cmdlet. Do what the Security Settings
    # editor does: write GptTmpl.inf (UTF-16LE + BOM, CRLF), register the
    # Security CSE on the GPO, and bump the computer version in AD and GPT.INI.
    param([Guid]$GpoId, [int]$MinimumLength)
    $folder = Join-Path $env:SystemRoot ('SYSVOL\domain\Policies\{' + $GpoId.ToString().ToUpperInvariant() + '}')
    $secEdit = Join-Path $folder 'Machine\Microsoft\Windows NT\SecEdit'
    New-Item -ItemType Directory -Path $secEdit -Force | Out-Null
    $inf = @(
        '[Unicode]'
        'Unicode=yes'
        '[System Access]'
        "MinimumPasswordLength = $MinimumLength"
        '[Version]'
        'signature="$CHICAGO$"'
        'Revision=1'
        ''
    ) -join "`r`n"
    [System.IO.File]::WriteAllText((Join-Path $secEdit 'GptTmpl.inf'), $inf, [System.Text.Encoding]::Unicode)

    $dn = Get-GpoDn -Id $GpoId
    $gpc = Get-ADObject -Identity $dn -Properties versionNumber -Server $pdc
    $version = [int]$gpc.versionNumber + 1
    Set-AdAttributeLdap -Dn $dn -Values @{
        versionNumber = $version
        gPCMachineExtensionNames = '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]'
    }
    [System.IO.File]::WriteAllText((Join-Path $folder 'GPT.INI'), "[General]`r`nVersion=$version`r`n", [System.Text.Encoding]::ASCII)
}

function Set-LabLink {
    param([string]$GpoName, [string]$Target, [int]$Order, [string]$Enforced, [string]$Enabled)
    $linkArgs = @{
        Name = $GpoName
        Target = $Target
        Order = $Order
        Enforced = $Enforced
        LinkEnabled = $Enabled
        Domain = $Domain
        Server = $pdc
    }
    $existing = @((Get-GPInheritance -Target $Target -Domain $Domain -Server $pdc).GpoLinks |
            Where-Object { $_.DisplayName -eq $GpoName })
    if ($existing.Count -gt 0) {
        Set-GPLink @linkArgs | Out-Null
    }
    else {
        New-GPLink @linkArgs | Out-Null
    }
}

function Invoke-Seed {
    foreach ($ou in @(@($fx.ou, $rootDn), @('Servers', $ouDn), @('Workstations', $ouDn))) {
        if (-not (Test-AdObject -Dn "OU=$($ou[0]),$($ou[1])")) {
            New-ADOrganizationalUnit -Name $ou[0] -Path $ou[1] -ProtectedFromAccidentalDeletion $false -Server $pdc
            [void]$done.Add("OU $($ou[0])")
        }
    }
    if (-not (Test-AdObject -Dn "CN=$($fx.group),$ouDn")) {
        New-ADGroup -Name $fx.group -GroupScope Global -GroupCategory Security -Path $ouDn -Server $pdc
        [void]$done.Add("group $($fx.group)")
    }

    # WMI filter, encoded the way GPMC writes msWMI-Parm2.
    if (-not (Get-WmiFilterObject -Name $fx.wmi_filter)) {
        $id = '{' + [guid]::NewGuid().ToString().ToUpperInvariant() + '}'
        $now = (Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss.ffffff-000')
        $parm2 = '1;3;{0};{1};WQL;{2};{3};' -f $fx.wmi_namespace.Length, $fx.wmi_query.Length, $fx.wmi_namespace, $fx.wmi_query
        New-ADObject -Type 'msWMI-Som' -Name $id -Path $somContainer -Server $pdc -OtherAttributes @{
            'msWMI-Name' = $fx.wmi_filter
            'msWMI-Parm1' = $fx.wmi_description
            'msWMI-Parm2' = $parm2
            'msWMI-ID' = $id
            'msWMI-Author' = 'domain_lab fixture'
            'msWMI-ChangeDate' = $now
            'msWMI-CreationDate' = $now
        }
        [void]$done.Add("WMI filter $($fx.wmi_filter)")
    }

    $gpos = @{}
    foreach ($name in @($fx.gpo_baseline, $fx.gpo_rdp, $fx.gpo_password)) {
        $gpo = Get-GpoOrNull -Name $name
        if (-not $gpo) {
            $gpo = New-GPO -Name $name -Domain $Domain -Server $pdc
            [void]$done.Add("GPO $name")
        }
        $gpos[$name] = $gpo
    }

    # Baseline: Admin Templates + Preferences settings, security filtering to
    # a group (Authenticated Users kept at Read — MS16-072), WMI filter.
    $baseline = $gpos[$fx.gpo_baseline]
    Set-GPRegistryValue -Guid $baseline.Id -Domain $Domain -Server $pdc `
        -Key 'HKLM\Software\Policies\GpoIacLab' -ValueName 'Baseline' -Type DWord -Value 1 | Out-Null
    $hasPref = $true
    try {
        $null = Get-GPPrefRegistryValue -Guid $baseline.Id -Domain $Domain -Server $pdc -Context Computer `
            -Key 'HKLM\Software\GpoIacLab' -ValueName 'FromPreferences' -ErrorAction Stop
    }
    catch {
        $hasPref = $false
    }
    if (-not $hasPref) {
        Set-GPPrefRegistryValue -Guid $baseline.Id -Domain $Domain -Server $pdc -Context Computer -Action Update `
            -Key 'HKLM\Software\GpoIacLab' -ValueName 'FromPreferences' -Type String -Value 'gpp' | Out-Null
    }
    Set-GPPermission -Guid $baseline.Id -Domain $Domain -Server $pdc `
        -TargetName $fx.group -TargetType Group -PermissionLevel GpoApply | Out-Null
    Set-GPPermission -Guid $baseline.Id -Domain $Domain -Server $pdc `
        -TargetName 'Authenticated Users' -TargetType Group -PermissionLevel GpoRead -Replace | Out-Null
    $gpDomain = New-Object -TypeName Microsoft.GroupPolicy.GPDomain -ArgumentList $Domain, $pdc
    $criteria = New-Object -TypeName Microsoft.GroupPolicy.GPSearchCriteria
    $filter = $gpDomain.SearchWmiFilters($criteria) | Where-Object { $_.Name -eq $fx.wmi_filter } | Select-Object -First 1
    if (-not $filter) { throw "GPMC cannot see WMI filter '$($fx.wmi_filter)'" }
    $baseline = Get-GPO -Guid $baseline.Id -Domain $Domain -Server $pdc
    $baseline.WmiFilter = $filter

    # RDP Settings: Admin Templates only, user half disabled.
    $rdp = $gpos[$fx.gpo_rdp]
    Set-GPRegistryValue -Guid $rdp.Id -Domain $Domain -Server $pdc `
        -Key 'HKLM\Software\Policies\GpoIacLab' -ValueName 'Rdp' -Type String -Value 'enabled' | Out-Null
    $rdp = Get-GPO -Guid $rdp.Id -Domain $Domain -Server $pdc
    $rdp.GpoStatus = [Microsoft.GroupPolicy.GpoStatus]::UserSettingsDisabled

    # Password Policy: security settings only (GptTmpl.inf).
    $diag['session'] = Get-SessionDiagnostic -GpoId $gpos[$fx.gpo_password].Id
    Set-LabPasswordPolicy -GpoId $gpos[$fx.gpo_password].Id -MinimumLength 14

    # Links: order = precedence. Servers: Baseline (enforced) above RDP.
    # Workstations: RDP linked but disabled, inheritance blocked.
    Set-LabLink -GpoName $fx.gpo_baseline -Target $serversDn -Order 1 -Enforced Yes -Enabled Yes
    Set-LabLink -GpoName $fx.gpo_rdp -Target $serversDn -Order 2 -Enforced No -Enabled Yes
    Set-LabLink -GpoName $fx.gpo_rdp -Target $workstationsDn -Order 1 -Enforced No -Enabled No
    Set-LabLink -GpoName $fx.gpo_password -Target $ouDn -Order 1 -Enforced No -Enabled Yes
    Set-GPInheritance -Target $workstationsDn -IsBlocked Yes -Domain $Domain -Server $pdc | Out-Null
    [void]$done.Add('settings, filtering, links')
}

function Invoke-Drift {
    # 1. Delete a GPO outright (its links go with it).
    $rdp = Get-GpoOrNull -Name $fx.gpo_rdp
    if ($rdp) {
        Remove-GPO -Guid $rdp.Id -Domain $Domain -Server $pdc
        [void]$done.Add("deleted GPO $($fx.gpo_rdp)")
    }

    # 2. Baseline: status off, filtering inverted, WMI filter unlinked and
    #    deleted, link no longer enforced.
    $baseline = Get-GPO -Name $fx.gpo_baseline -Domain $Domain -Server $pdc
    $baseline.GpoStatus = [Microsoft.GroupPolicy.GpoStatus]::AllSettingsDisabled
    Set-GPPermission -Guid $baseline.Id -Domain $Domain -Server $pdc `
        -TargetName 'Authenticated Users' -TargetType Group -PermissionLevel GpoApply | Out-Null
    Set-GPPermission -Guid $baseline.Id -Domain $Domain -Server $pdc `
        -TargetName $fx.group -TargetType Group -PermissionLevel GpoRead -Replace | Out-Null
    # Unlink through GPMC (the path gpo_import uses to clear a filter), falling
    # back to a raw LDAP clear; the result records which one worked.
    $cleared = $false
    try {
        $baseline.WmiFilter = $null
        $cleared = $null -eq (Get-GPO -Guid $baseline.Id -Domain $Domain -Server $pdc).WmiFilter
        if ($cleared) { $how = 'gpmc' } else { $how = 'gpmc set returned but the filter is still linked' }
    }
    catch {
        $how = "gpmc failed: $($_.Exception.Message)"
    }
    if (-not $cleared) {
        $entry = Get-LdapEntry -Dn (Get-GpoDn -Id $baseline.Id)
        try {
            $entry.Properties['gPCWQLFilter'].Clear()
            $entry.CommitChanges()
        }
        finally { $entry.Dispose() }
        $how = "ldap ($how)"
    }
    $diag['wmi_clear'] = $how
    $filterObject = Get-WmiFilterObject -Name $fx.wmi_filter
    if ($filterObject) {
        $parent = Get-LdapEntry -Dn $somContainer
        try {
            $parent.Children.Remove($parent.Children.Find("CN=$($filterObject.Name)", 'msWMI-Som'))
        }
        finally { $parent.Dispose() }
    }
    Set-GPLink -Name $fx.gpo_baseline -Target $serversDn -Enforced No -Domain $Domain -Server $pdc | Out-Null
    [void]$done.Add("drifted $($fx.gpo_baseline)")

    # 3. An unmanaged link at the top of a managed OU.
    New-GPLink -Name $fx.gpo_password -Target $serversDn -Order 1 -Domain $Domain -Server $pdc | Out-Null

    # 4. Inheritance unblocked.
    Set-GPInheritance -Target $workstationsDn -IsBlocked No -Domain $Domain -Server $pdc | Out-Null

    # 5. Content drift on the security-settings GPO.
    $passwordGpo = Get-GPO -Name $fx.gpo_password -Domain $Domain -Server $pdc
    Set-LabPasswordPolicy -GpoId $passwordGpo.Id -MinimumLength 8
    [void]$done.Add('links, inheritance, password policy content')
}

if ($Action -eq 'Seed') { Invoke-Seed } else { Invoke-Drift }

$inAnsible = $null -ne (Get-Variable -Name Ansible -ErrorAction SilentlyContinue)
$out = @{ done = @($done); diagnostics = $diag }
if ($inAnsible) {
    $Ansible.Changed = $done.Count -gt 0
    $Ansible.Result = $out
}
else {
    $out | ConvertTo-Json -Depth 5
}
