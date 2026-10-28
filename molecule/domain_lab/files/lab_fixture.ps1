# lab_fixture.ps1 — test fixture for the domain_lab Molecule scenario.
#
#   -Action Seed   the "authored" domain state that gpo_backup exports:
#                  OUs, groups, a WMI filter and five GPOs covering four
#                  setting types (Admin Templates, Preferences, security
#                  settings, Restricted Groups), with link order (including
#                  above Default Domain Policy), enforcement, a disabled link,
#                  block-inheritance, security filtering and GPO status.
#                  Real-world scenarios: a domain password/lockout policy,
#                  local Administrators via GPP and via Restricted Groups.
#   -Action Drift  out-of-band changes that gpo_import must undo.
#
# Wherever GPMC has an API (WMI filter linking, links, permissions, status)
# the fixture uses it, so the roles are checked against GPMC rather than
# against themselves. Settings GPMC can't author (security templates,
# Preferences XML) are written the way their editors write them.

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
$netbios = $adDomain.NetBIOSName
$ouDn = "OU=$($fx.ou),$rootDn"
$serversDn = "OU=Servers,$ouDn"
$workstationsDn = "OU=Workstations,$ouDn"
$somContainer = "CN=SOM,CN=WMIPolicy,CN=System,$rootDn"
$securityCse = '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]'
$gppGroupsCse = '[{00000000-0000-0000-0000-000000000000}{79F92669-4224-476C-9C5C-6EFB4D87DF4A}]' +
'[{17D89FEC-5C44-4972-B12D-241CAEF74509}{79F92669-4224-476C-9C5C-6EFB4D87DF4A}]'
$done = New-Object System.Collections.ArrayList
$diag = [ordered]@{}

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

function Get-GpoFolder {
    param([Guid]$Id)
    Join-Path $env:SystemRoot ('SYSVOL\domain\Policies\{' + $Id.ToString().ToUpperInvariant() + '}')
}

function Get-GroupSid {
    param([string]$Name)
    (Get-ADGroup -Identity $Name -Server $pdc).SID.Value
}

function Get-WmiFilterObject {
    param([string]$Name)
    Get-ADObject -SearchBase $somContainer -SearchScope OneLevel -Server $pdc `
        -LDAPFilter "(&(objectClass=msWMI-Som)(msWMI-Name=$Name))" -Properties 'msWMI-Name', 'msWMI-Parm2'
}

function Get-LdapEntry {
    param([string]$Dn)
    New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList "LDAP://$pdc/$Dn"
}

function Set-AdAttributeLdap {
    # ADSI/LDAP: the mechanism GPMC itself uses. Set-ADObject (AD Web
    # Services) is refused (8344) writing a GPO's AD object here even with
    # Domain Admins in the token; LDAP and GPMC writes succeed (see AGENTS.md).
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

function Update-LabGpoVersion {
    # After writing a GPO's SYSVOL files directly: register the client-side
    # extensions that process them and bump the computer version in both AD
    # and GPT.INI, as the editors do, so clients (and gpupdate) pick it up.
    param([Guid]$GpoId, [string]$ExtensionNames)
    $dn = Get-GpoDn -Id $GpoId
    $version = [int](Get-ADObject -Identity $dn -Properties versionNumber -Server $pdc).versionNumber + 1
    Set-AdAttributeLdap -Dn $dn -Values @{ versionNumber = $version; gPCMachineExtensionNames = $ExtensionNames }
    [System.IO.File]::WriteAllText((Join-Path (Get-GpoFolder -Id $GpoId) 'GPT.INI'), "[General]`r`nVersion=$version`r`n",
        [System.Text.Encoding]::ASCII)
}

function Set-LabSecurityTemplate {
    # Security settings have no GPMC cmdlet: write GptTmpl.inf the way the
    # Security Settings editor does (UTF-16LE + BOM, CRLF).
    param([Guid]$GpoId, [string[]]$Body)
    $secEdit = Join-Path (Get-GpoFolder -Id $GpoId) 'Machine\Microsoft\Windows NT\SecEdit'
    New-Item -ItemType Directory -Path $secEdit -Force | Out-Null
    $inf = (@('[Unicode]', 'Unicode=yes') + $Body + @('[Version]', 'signature="$CHICAGO$"', 'Revision=1', '')) -join "`r`n"
    [System.IO.File]::WriteAllText((Join-Path $secEdit 'GptTmpl.inf'), $inf, [System.Text.Encoding]::Unicode)
    Update-LabGpoVersion -GpoId $GpoId -ExtensionNames $securityCse
}

function Set-LabPasswordPolicy {
    # Domain password + lockout policy. Applies to domain accounts only from
    # a GPO linked at the domain root, where the highest-precedence GPO that
    # defines a setting wins it.
    param([Guid]$GpoId, [int]$MinimumLength)
    Set-LabSecurityTemplate -GpoId $GpoId -Body @(
        '[System Access]'
        'MinimumPasswordAge = 1'
        'MaximumPasswordAge = 90'
        "MinimumPasswordLength = $MinimumLength"
        'PasswordComplexity = 1'
        'PasswordHistorySize = 24'
        'LockoutBadCount = 5'
        'ResetLockoutCount = 15'
        'LockoutDuration = 15'
    )
}

function Set-LabRestrictedAdmin {
    # Restricted Groups: the *exact* membership of the built-in Administrators
    # group (anything else is removed). Members are SIDs in a security
    # setting, so a migration table translates them on import.
    param([Guid]$GpoId, [string[]]$MemberSids)
    Set-LabSecurityTemplate -GpoId $GpoId -Body @(
        '[Group Membership]'
        '*S-1-5-32-544__Memberof ='
        ('*S-1-5-32-544__Members = ' + (($MemberSids | ForEach-Object { "*$_" }) -join ','))
    )
}

function Set-LabLocalAdminsPreference {
    # Group Policy Preferences > Local Users and Groups: add one member to the
    # built-in Administrators group and leave existing members alone. The SID
    # sits in Groups.xml, which migration tables do NOT translate.
    param([Guid]$GpoId, [string]$MemberName, [string]$MemberSid)
    $dir = Join-Path (Get-GpoFolder -Id $GpoId) 'Machine\Preferences\Groups'
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $uid = '{' + [guid]::NewGuid().ToString().ToUpperInvariant() + '}'
    $changed = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    $xml = @"
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="Administrators (built-in)" image="2" changed="$changed" uid="$uid">
    <Properties action="U" newName="" description="" deleteAllUsers="0" deleteAllGroups="0" removeAccounts="0"
      groupSid="S-1-5-32-544" groupName="Administrators (built-in)">
      <Members>
        <Member name="$MemberName" action="ADD" sid="$MemberSid"/>
      </Members>
    </Properties>
  </Group>
</Groups>
"@
    [System.IO.File]::WriteAllText((Join-Path $dir 'Groups.xml'), $xml, (New-Object System.Text.UTF8Encoding $false))
    Update-LabGpoVersion -GpoId $GpoId -ExtensionNames $gppGroupsCse
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
    foreach ($group in @($fx.group, $fx.server_admins_group, $fx.ws_admins_group, $fx.helpdesk_group)) {
        if (-not (Test-AdObject -Dn "CN=$group,$ouDn")) {
            New-ADGroup -Name $group -GroupScope Global -GroupCategory Security -Path $ouDn -Server $pdc
            [void]$done.Add("group $group")
        }
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
    foreach ($name in @($fx.gpo_baseline, $fx.gpo_rdp, $fx.gpo_password, $fx.gpo_server_admins, $fx.gpo_ws_admins)) {
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

    # Scenario: domain password + lockout policy (security settings).
    $diag['session'] = Get-SessionDiagnostic -GpoId $gpos[$fx.gpo_password].Id
    Set-LabPasswordPolicy -GpoId $gpos[$fx.gpo_password].Id -MinimumLength 14

    # Scenario: local Administrators. Servers get a group *added* (GPP);
    # workstations get an *exact* membership (Restricted Groups).
    Set-LabLocalAdminsPreference -GpoId $gpos[$fx.gpo_server_admins].Id `
        -MemberName "$netbios\$($fx.server_admins_group)" -MemberSid (Get-GroupSid -Name $fx.server_admins_group)
    Set-LabRestrictedAdmin -GpoId $gpos[$fx.gpo_ws_admins].Id `
        -MemberSids @((Get-GroupSid -Name 'Domain Admins'), (Get-GroupSid -Name $fx.ws_admins_group))

    # Links: order = precedence. Domain root: the password policy above
    # Default Domain Policy. Servers: Baseline (enforced) > RDP > local admins.
    # Workstations: RDP linked but disabled, local admins; inheritance blocked.
    Set-LabLink -GpoName $fx.gpo_password -Target $rootDn -Order 1 -Enforced No -Enabled Yes
    Set-LabLink -GpoName $fx.gpo_baseline -Target $serversDn -Order 1 -Enforced Yes -Enabled Yes
    Set-LabLink -GpoName $fx.gpo_rdp -Target $serversDn -Order 2 -Enforced No -Enabled Yes
    Set-LabLink -GpoName $fx.gpo_server_admins -Target $serversDn -Order 3 -Enforced No -Enabled Yes
    Set-LabLink -GpoName $fx.gpo_rdp -Target $workstationsDn -Order 1 -Enforced No -Enabled No
    Set-LabLink -GpoName $fx.gpo_ws_admins -Target $workstationsDn -Order 2 -Enforced No -Enabled Yes
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

    # 3. An unmanaged link at the top of a managed OU; inheritance unblocked.
    New-GPLink -Name $fx.gpo_password -Target $serversDn -Order 1 -Domain $Domain -Server $pdc | Out-Null
    Set-GPInheritance -Target $workstationsDn -IsBlocked No -Domain $Domain -Server $pdc | Out-Null

    # 4. Password policy: Default Domain Policy moved back above it (so its
    #    weaker settings win again) and the GPO's own minimum lowered.
    Set-GPLink -Name 'Default Domain Policy' -Target $rootDn -Order 1 -Domain $Domain -Server $pdc | Out-Null
    $passwordGpo = Get-GPO -Name $fx.gpo_password -Domain $Domain -Server $pdc
    Set-LabPasswordPolicy -GpoId $passwordGpo.Id -MinimumLength 8

    # 5. The classic local-admin incident: someone points the servers'
    #    local-Administrators preference at Domain Users.
    $serverAdmins = Get-GPO -Name $fx.gpo_server_admins -Domain $Domain -Server $pdc
    Set-LabLocalAdminsPreference -GpoId $serverAdmins.Id -MemberName "$netbios\Domain Users" `
        -MemberSid (Get-GroupSid -Name 'Domain Users')

    # 6. The workstation Restricted Groups GPO unlinked.
    Remove-GPLink -Name $fx.gpo_ws_admins -Target $workstationsDn -Domain $Domain -Server $pdc | Out-Null
    [void]$done.Add('links, inheritance, password policy, local admins')
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
