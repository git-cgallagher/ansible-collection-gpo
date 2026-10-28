# new_migtable.ps1 — build a GPMC migration table from a GPO's settings and
# retarget one security principal, the way you'd prepare a lab -> prod import.
# The table is populated by GPMC itself (so source names are in whatever
# format GPMC writes); only the chosen entry's destination is changed.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Domain,
    [Parameter(Mandatory = $true)][string]$GpoName,
    [Parameter(Mandatory = $true)][string]$SourceName,
    [Parameter(Mandatory = $true)][string]$DestinationName,
    [Parameter(Mandatory = $true)][string]$Path
)

$ErrorActionPreference = 'Stop'
Import-Module GroupPolicy

$gpo = Get-GPO -Name $GpoName -Domain $Domain
$gpm = New-Object -ComObject GPMgmt.GPM
$constants = $gpm.GetConstants()
$gpmDomain = $gpm.GetDomain($Domain, '', $constants.UseAnyDC)
$table = $gpm.CreateMigrationTable()
[void]$table.Add(0, $gpmDomain.GetGPO('{' + $gpo.Id.ToString() + '}'))

$pattern = [regex]::Escape($SourceName)
$mapped = @()
foreach ($entry in @($table.GetEntries())) {
    $source = [string]$entry.Source
    if ($source -match $pattern) {
        $destination = $source -replace $pattern, $DestinationName
        [void]$table.UpdateDestination($source, $destination)
        $mapped += "$source -> $destination"
    }
}
$entries = @($table.GetEntries() | ForEach-Object { '{0} -> {1}' -f $_.Source, $_.Destination })
if ($mapped.Count -eq 0) {
    throw "No migration table entry matches '$SourceName' in '$GpoName'. Entries: $($entries -join '; ')"
}
$folder = Split-Path -Parent $Path
if (-not (Test-Path -LiteralPath $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
$table.Save($Path)

$Ansible.Changed = $true
$Ansible.Result = [ordered]@{ mapped = $mapped; entries = $entries; path = $Path }
