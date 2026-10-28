# assert_domain.ps1 — check the live domain against the domain_lab fixture's
# authored state, through GPMC and AD directly (never through the roles).
# Returns { failures = [...]; observed = {...} }; the playbook asserts that
# failures is empty and prints observed either way.

[CmdletBinding()]
param(
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
$failures = New-Object System.Collections.ArrayList
$observed = [ordered]@{}

function Test-Lab {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { [void]$script:failures.Add($Message) }
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

function Get-LinkList {
    param([string]$Target)
    @((Get-GPInheritance -Target $Target -Domain $Domain -Server $pdc).GpoLinks | Sort-Object Order | ForEach-Object {
            '{0}|enforced={1}|enabled={2}' -f $_.DisplayName, $_.Enforced, $_.Enabled
        })
}

function Get-ApplyTrustee {
    param([Guid]$Id)
    @(Get-GPPermission -Guid $Id -All -Domain $Domain -Server $pdc |
            Where-Object { [string]$_.Permission -eq 'GpoApply' } |
            ForEach-Object { $_.Trustee.Name } | Sort-Object)
}

function Get-GpoFile {
    param($Gpo, [string]$RelativePath)
    $file = Join-Path $env:SystemRoot ('SYSVOL\domain\Policies\{' + $Gpo.Id.ToString().ToUpperInvariant() + '}\' + $RelativePath)
    if (Test-Path -LiteralPath $file) { Get-Content -LiteralPath $file -Raw } else { '' }
}

function Get-GroupSid {
    param([string]$Name)
    (Get-ADGroup -Identity $Name -Server $pdc).SID.Value
}

# --- links, precedence, inheritance ---------------------------------------------
$expectedLinks = [ordered]@{
    $rootDn = @(
        "$($fx.gpo_password)|enforced=False|enabled=True"
        'Default Domain Policy|enforced=False|enabled=True'
    )
    $serversDn = @(
        "$($fx.gpo_baseline)|enforced=True|enabled=True"
        "$($fx.gpo_rdp)|enforced=False|enabled=True"
        "$($fx.gpo_server_admins)|enforced=False|enabled=True"
    )
    $workstationsDn = @(
        "$($fx.gpo_rdp)|enforced=False|enabled=False"
        "$($fx.gpo_ws_admins)|enforced=False|enabled=True"
    )
    $ouDn = @()
}
foreach ($target in $expectedLinks.Keys) {
    $got = Get-LinkList -Target $target
    $observed["links $target"] = $got
    $want = $expectedLinks[$target]
    Test-Lab (($got -join ' ; ') -eq ($want -join ' ; ')) "links on ${target}: got [$($got -join ' ; ')], want [$($want -join ' ; ')]"
}
$blocked = [bool](Get-GPInheritance -Target $workstationsDn -Domain $Domain -Server $pdc).GpoInheritanceBlocked
$observed['workstations inheritance blocked'] = $blocked
Test-Lab $blocked "inheritance on $workstationsDn is not blocked"

# --- Server Baseline: status, settings, filtering, WMI filter ---------------------
$baseline = Get-GpoOrNull -Name $fx.gpo_baseline
Test-Lab ($null -ne $baseline) "GPO '$($fx.gpo_baseline)' is missing"
if ($baseline) {
    $observed['baseline status'] = $baseline.GpoStatus.ToString()
    Test-Lab ($baseline.GpoStatus.ToString() -eq 'AllSettingsEnabled') "baseline status is $($baseline.GpoStatus)"

    $value = (Get-GPRegistryValue -Guid $baseline.Id -Domain $Domain -Server $pdc `
            -Key 'HKLM\Software\Policies\GpoIacLab' -ValueName 'Baseline').Value
    Test-Lab ($value -eq 1) "baseline Admin Templates value is '$value', want 1"
    try {
        $pref = Get-GPPrefRegistryValue -Guid $baseline.Id -Domain $Domain -Server $pdc -Context Computer `
            -Key 'HKLM\Software\GpoIacLab' -ValueName 'FromPreferences' -ErrorAction Stop
        Test-Lab (@($pref)[0].Value -eq 'gpp') "baseline Preferences value is '$(@($pref)[0].Value)', want 'gpp'"
    }
    catch {
        [void]$failures.Add("baseline Preferences item missing: $($_.Exception.Message)")
    }

    $apply = Get-ApplyTrustee -Id $baseline.Id
    $observed['baseline apply'] = $apply
    Test-Lab (($apply -join ',') -eq $fx.group) "baseline Apply trustees are [$($apply -join ', ')], want [$($fx.group)]"
    $authUsers = Get-GPPermission -Guid $baseline.Id -TargetName 'Authenticated Users' -TargetType Group `
        -Domain $Domain -Server $pdc -ErrorAction SilentlyContinue
    Test-Lab ($authUsers -and [string]$authUsers.Permission -eq 'GpoRead') `
        "Authenticated Users on baseline: '$($authUsers.Permission)', want GpoRead (MS16-072: never none)"

    $wmi = $baseline.WmiFilter
    $observed['baseline wmi filter'] = if ($wmi) { $wmi.Name } else { $null }
    Test-Lab ($wmi -and $wmi.Name -eq $fx.wmi_filter) "baseline WMI filter is '$($observed['baseline wmi filter'])', want '$($fx.wmi_filter)'"
    if ($wmi) {
        # GPMC's own parser must read back the query the import encoded.
        try {
            $gpm = New-Object -ComObject GPMgmt.GPM
            $constants = $gpm.GetConstants()
            $gpmDomain = $gpm.GetDomain($Domain, '', $constants.UseAnyDC)
            $queries = @($gpmDomain.GetWMIFilter($wmi.Path).GetQueryList())
            $observed['wmi queries (GPMC)'] = $queries
            $hits = @($queries | Where-Object { ([string]$_).EndsWith($fx.wmi_query) })
            Test-Lab ($hits.Count -eq 1) "GPMC reads the WMI filter queries as [$($queries -join ' | ')]"
        }
        catch {
            [void]$failures.Add("GPMC could not read the WMI filter: $($_.Exception.Message)")
        }
    }
}

$som = @(Get-ADObject -SearchBase $somContainer -SearchScope OneLevel -Server $pdc `
        -LDAPFilter '(objectClass=msWMI-Som)' -Properties 'msWMI-Name', 'msWMI-Parm1', 'msWMI-Parm2' |
        Where-Object { $_.'msWMI-Name' -eq $fx.wmi_filter })
Test-Lab ($som.Count -eq 1) "found $($som.Count) WMI filters named '$($fx.wmi_filter)', want 1"
if ($som.Count -eq 1) {
    $wantParm2 = '1;3;{0};{1};WQL;{2};{3};' -f $fx.wmi_namespace.Length, $fx.wmi_query.Length, $fx.wmi_namespace, $fx.wmi_query
    $observed['wmi parm2'] = [string]$som[0].'msWMI-Parm2'
    Test-Lab ([string]$som[0].'msWMI-Parm2' -eq $wantParm2) "msWMI-Parm2 is '$($som[0].'msWMI-Parm2')', want '$wantParm2'"
    Test-Lab ([string]$som[0].'msWMI-Parm1' -eq $fx.wmi_description) "msWMI-Parm1 is '$($som[0].'msWMI-Parm1')'"
}

# --- RDP Settings: recreated from its backup ---------------------------------------
$rdp = Get-GpoOrNull -Name $fx.gpo_rdp
Test-Lab ($null -ne $rdp) "GPO '$($fx.gpo_rdp)' is missing (should be recreated from its backup)"
if ($rdp) {
    $observed['rdp status'] = $rdp.GpoStatus.ToString()
    Test-Lab ($rdp.GpoStatus.ToString() -eq 'UserSettingsDisabled') "rdp status is $($rdp.GpoStatus)"
    $value = (Get-GPRegistryValue -Guid $rdp.Id -Domain $Domain -Server $pdc `
            -Key 'HKLM\Software\Policies\GpoIacLab' -ValueName 'Rdp').Value
    Test-Lab ($value -eq 'enabled') "rdp Admin Templates value is '$value', want 'enabled'"
    $apply = Get-ApplyTrustee -Id $rdp.Id
    Test-Lab (($apply -join ',') -eq 'Authenticated Users') "rdp Apply trustees are [$($apply -join ', ')]"
}

# --- Scenario: domain password + lockout policy (content restored) ------------------
$secEditInf = 'Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
$passwordGpo = Get-GpoOrNull -Name $fx.gpo_password
Test-Lab ($null -ne $passwordGpo) "GPO '$($fx.gpo_password)' is missing"
if ($passwordGpo) {
    $text = Get-GpoFile -Gpo $passwordGpo -RelativePath $secEditInf
    $observed['password GptTmpl.inf'] = $text
    Test-Lab ($text -match 'MinimumPasswordLength\s*=\s*14') 'password GPO does not set MinimumPasswordLength = 14'
    Test-Lab ($text -match 'LockoutBadCount\s*=\s*5') 'password GPO does not set LockoutBadCount = 5'
}

# --- Scenario: local Administrators via GPP (additive) ------------------------------
$serverAdminsSid = Get-GroupSid -Name $fx.server_admins_group
$serverAdmins = Get-GpoOrNull -Name $fx.gpo_server_admins
Test-Lab ($null -ne $serverAdmins) "GPO '$($fx.gpo_server_admins)' is missing"
if ($serverAdmins) {
    $text = Get-GpoFile -Gpo $serverAdmins -RelativePath 'Machine\Preferences\Groups\Groups.xml'
    $observed['server local admins Groups.xml'] = $text
    try {
        $group = ([xml]$text).Groups.Group
        $members = @($group.Properties.Members.Member)
        $memberList = @($members | ForEach-Object { '{0} {1} {2}' -f $_.action, $_.name, $_.sid }) -join '; '
        Test-Lab ($group.Properties.groupSid -eq 'S-1-5-32-544') "GPP item targets $($group.Properties.groupSid), want S-1-5-32-544"
        Test-Lab ($members.Count -eq 1 -and $members[0].sid -eq $serverAdminsSid -and $members[0].action -eq 'ADD') `
            "GPP local Administrators members are [$memberList], want ADD $($fx.server_admins_group) only"
    }
    catch {
        [void]$failures.Add("Server Local Admins Groups.xml unreadable: $($_.Exception.Message)")
    }
}

# --- Scenario: local Administrators via Restricted Groups (exact membership) --------
$wsAdmins = Get-GpoOrNull -Name $fx.gpo_ws_admins
Test-Lab ($null -ne $wsAdmins) "GPO '$($fx.gpo_ws_admins)' is missing"
if ($wsAdmins) {
    $text = Get-GpoFile -Gpo $wsAdmins -RelativePath $secEditInf
    $observed['workstation local admins GptTmpl.inf'] = $text
    $want = '*S-1-5-32-544__Members = *{0},*{1}' -f (Get-GroupSid -Name 'Domain Admins'), (Get-GroupSid -Name $fx.ws_admins_group)
    Test-Lab ($text.Contains($want)) "Restricted Groups line missing: want '$want'"
}

$inAnsible = $null -ne (Get-Variable -Name Ansible -ErrorAction SilentlyContinue)
$out = @{ failures = @($failures); observed = $observed }
if ($inAnsible) {
    $Ansible.Changed = $false
    $Ansible.Result = $out
}
else {
    $out | ConvertTo-Json -Depth 5
}
