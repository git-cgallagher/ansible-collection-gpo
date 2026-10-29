# effective_password_policy.ps1 — refresh computer policy on this DC, then
# report the domain's *effective* password and lockout policy. That's the
# outcome of link order at the domain root, not just what a GPO contains.

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$refresh = (gpupdate.exe /target:computer /force 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0) { throw "gpupdate failed ($LASTEXITCODE): $refresh" }
$policy = Get-ADDefaultDomainPasswordPolicy

$Ansible.Changed = $false
$Ansible.Result = [ordered]@{
    min_length = [int]$policy.MinPasswordLength
    lockout_threshold = [int]$policy.LockoutThreshold
    complexity = [bool]$policy.ComplexityEnabled
    gpupdate = $refresh
}
