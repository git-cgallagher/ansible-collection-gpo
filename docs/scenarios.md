# Real-world scenarios

Worked examples of common Group Policy changes managed with this collection.
Each one is part of the `domain_lab` test (`molecule/domain_lab`), which
builds it on a real Windows Server 2022 domain controller in CI, exports it,
breaks it the way it breaks in real life, and checks `gpo_import` puts it back.
The fixture that builds them is `molecule/domain_lab/files/lab_fixture.ps1`.

The workflow is the same every time: **edit the GPO in GPMC in your authoring
(lab) domain → run `gpo_backup` → review the diff and merge → run `gpo_import`
against each target domain.** What changes between scenarios is where the
setting lives, and what that means for links, precedence and migration
tables.

## 1. Domain password and lockout policy

**The change:** minimum length 14, complexity on, 24 remembered passwords,
lock out after 5 bad attempts for 15 minutes.

**Where it lives:** *Computer Configuration → Policies → Windows Settings →
Security Settings → Account Policies*, stored as `[System Access]` in the
GPO's `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf`. GPMC has no cmdlet
for it, which is why backup/import, not `Set-GPRegistryValue`, is the
mechanism here.

**What makes it tricky:**

- Account policy only applies to **domain** accounts from a GPO linked at the
  **domain root**. Linked to an OU it only affects local accounts on the
  computers in that OU. (Fine-grained password policies are AD objects, not
  GPOs, and are out of scope.)
- Several domain-root GPOs can define the same setting; the one with the
  **highest link precedence wins it**. Leaving the setting in Default Domain
  Policy and adding a stricter GPO *below* it does nothing.

**In this collection:** a dedicated GPO linked at the domain root at order 1,
above Default Domain Policy. The manifest records that order:

```jsonc
{
  "target": "",                // the domain root (targets are relative to it)
  "block_inheritance": false,
  "links": [
    { "gpo": "SEC - Domain Password Policy", "enforced": false, "enabled": true },
    { "gpo": "Default Domain Policy",        "enforced": false, "enabled": true }
  ]
}
```

**What the lab proves:** after seeding, the domain's *effective* policy
(`Get-ADDefaultDomainPasswordPolicy` after `gpupdate`) is 14 characters and
lockout at 5. The drift moves Default Domain Policy back to the top and lowers
the GPO's own minimum; the effective policy drops to Default Domain Policy's
7 characters and no lockout, which shows the order really decides the
outcome. After `gpo_import` the link order and the GPO's content are
restored, and the effective policy is back to 14 and 5.

## 2. Local Administrators membership

Two mechanisms, both common. Pick one per group per computer, because they
fight each other if they overlap.

### 2a. Add a group without touching other members — Group Policy Preferences

**The change:** add `CORP\GG-Server-Admins` to the built-in Administrators
group on every server, leaving whatever else is there.

**Where it lives:** *Computer Configuration → Preferences → Control Panel
Settings → Local Users and Groups*, action **Update** on "Administrators
(built-in)" (`S-1-5-32-544`), stored in
`Machine\Preferences\Groups\Groups.xml` with the member's **SID embedded**.

**The incident it guards against:** someone edits the GPO in GPMC and adds
*Domain Users*. The next `gpo_backup` shows that as a diff in
`Groups.xml`. In a domain the pipeline owns, `gpo_import` reverts it from Git.

**What the lab proves:** the drift rewrites the preference to add Domain
Users; after `gpo_import` the preference adds exactly `GG-IacLab-Server-Admins`
again.

⚠️ **Migration tables do not translate Group Policy Preferences.** Imported
into another domain, `Groups.xml` still names the *source* domain's group
(`LAB\…`) and SID, so the preference fails or targets the wrong account.
Template the member's name and SID per environment before importing, and
after a first cross-domain import search the target GPO's report for the
source domain's SID prefix. Restricted Groups (2b) doesn't have this
problem.

### 2b. Enforce exact membership — Restricted Groups

**The change:** on workstations, the built-in Administrators group contains
*exactly* Domain Admins and `CORP\GG-Workstation-Admins`. Anything else,
including a helpdesk tech's "temporary" addition, is removed at the next
policy refresh.

**Where it lives:** *Computer Configuration → Policies → Windows Settings →
Security Settings → Restricted Groups*, stored in `GptTmpl.inf`:

```ini
[Group Membership]
*S-1-5-32-544__Memberof =
*S-1-5-32-544__Members = *S-1-5-21-…-512,*S-1-5-21-…-1106
```

**What the lab proves:** the drift unlinks the GPO; `gpo_import` relinks it
in the right position and the `[Group Membership]` members are intact.

**Migration tables do translate these.** Restricted Groups members are
security settings, so `Import-GPO -MigrationTable` rewrites the SIDs. See
scenario 3.

## 3. Promoting a GPO from lab to production (migration tables)

**The change:** the Restricted Groups GPO from 2b, authored in the lab domain
where the group is `LAB\GG-Workstation-Admins`, imported into production
where the equivalent group is `PROD\GG-Workstation-Admins` (a different SID).

**How:** commit one migration table per target environment and pass it to
the import:

```yaml
- role: git_cgallagher.gpo.gpo_import
  vars:
    gpo_import_domain: prod.example.com
    gpo_import_source_dir: "{{ playbook_dir }}/gpo-repo"
    gpo_import_migration_table: migtables/prod.migtable
```

**Building the table:** let GPMC write it so the format and source names are
exactly what `Import-GPO` expects. Use the Migration Table Editor
(`mtedit.exe`, "Populate from Backup"), or script it with the GPMC COM API,
as the lab does (`molecule/domain_lab/files/new_migtable.ps1`):

```powershell
$gpm = New-Object -ComObject GPMgmt.GPM
$k = $gpm.GetConstants()
$domain = $gpm.GetDomain('lab.example.com', '', $k.UseAnyDC)
$table = $gpm.CreateMigrationTable()
[void]$table.Add(0, $domain.GetGPO('{GPO-GUID}'))     # populate from the GPO
foreach ($e in @($table.GetEntries())) {                # retarget what differs
    if ($e.Source -match 'GG-Workstation-Admins') {
        [void]$table.UpdateDestination($e.Source, ($e.Source -replace 'lab\.example\.com', 'prod.example.com'))
    }
}
$table.Save('C:\work\prod.migtable')
```

**What the lab proves:** within one domain, a table mapping
`GG-IacLab-Workstation-Admins` → `GG-IacLab-Helpdesk` makes `gpo_import` (with
`gpo_import_migration_table`, `gpo_import_force` and a `gpo_import_gpos`
filter) write the helpdesk group's SID into `[Group Membership]`; importing
again without the table restores the original. Importing into a genuinely
separate forest needs a second domain controller and isn't covered by the
lab yet (issue #16).

## Not covered (yet)

- Site-linked GPOs, starter GPOs, and IPsec policy (see the README).
- Multi-query WMI filters (single-query only).
- Fine-grained password policies: AD objects (`msDS-PasswordSettings`),
  not GPOs, so manage them with `microsoft.ad`, not this collection.
