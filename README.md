# git_cgallagher.gpo — Windows Group Policy as code

Export a domain's GPOs — **and** their links, precedence, filtering and WMI
filters — into Git, review changes as pull requests, and import them into a
target domain (the same one, or a different/untrusted one via migration
tables).

> **Status: early (0.x).** Both roles are tested end to end against a real
> Windows Server 2022 domain controller in CI (`molecule/domain_lab`), within
> one domain. Importing into a *different* domain isn't lab-tested yet
> ([issue #16](https://github.com/git-cgallagher/ansible-collection-gpo/issues/16)),
> so try that in a lab of your own first. Known gaps are listed under
> [What this doesn't do (yet)](#what-this-doesnt-do-yet).

## The problem

Domain Group Policy resists infrastructure-as-code because a GPO is not one
format. Each setting category is a different client-side extension with its
own on-disk representation, and the only write API Microsoft ships covers one
of them:

| Setting type | Stored as | Writable as code? |
|---|---|---|
| Admin Templates (registry) | `registry.pol` (binary) | `Set-GPRegistryValue` |
| Security settings (user rights, password policy, restricted groups) | `GptTmpl.inf` | no cmdlet |
| Advanced audit policy | `audit.csv` | no cmdlet |
| Group Policy Preferences | per-CSE XML | registry prefs only |
| Links, precedence, enforcement, filtering, WMI filters | AD attributes | PowerShell (separate from the GPO) |

DSC resources and Ansible's `win_security_policy` / `win_audit_policy_system`
manage **local** policy on each host, not domain GPOs. The Terraform `ad`
provider covers a sliver. The one mechanism that handles *every* setting type
is the one that never parses settings at all: `Backup-GPO` / `Import-GPO`,
which copy the GPO's files verbatim. That's how Microsoft distributes its own
security baselines.

This collection operationalizes that: **GPMC is the editor, Git is the store,
`Import-GPO` is the deployer** — plus a JSON manifest for everything an
import doesn't carry (links, order, enforcement, block-inheritance, security
filtering, WMI filters, GPO status). The full analysis, including the
cross-domain story and what was rejected, is in
[docs/design.md](docs/design.md).

## How it works

```
   lab / authoring domain                      Git                       target domain(s)
 ┌───────────────────────┐        ┌─────────────────────────┐        ┌──────────────────────┐
 │ edit GPOs in GPMC     │ backup │ gpos/<Name>/{guid}/…    │ import │ Import-GPO           │
 │                       │ ─────► │ gpo-manifest.json       │ ─────► │ + reconcile links,   │
 │ gpo_backup (role)     │        │ <env>.migtable          │        │   order, filtering…  │
 └───────────────────────┘        │   (reviewed as PRs)     │        │ gpo_import (role)    │
                                  └─────────────────────────┘        └──────────────────────┘
```

- `roles/gpo_backup` runs on a Windows management host with RSAT (GPMC +
  ActiveDirectory modules). It backs up every GPO (each into its own
  self-contained backup folder), generates `gpo-manifest.json` from the live
  domain, and ships a zip back to the controller, which unpacks it into your
  repo working copy. Only GPOs whose *content* changed are re-exported, so
  `git diff` lists exactly the GPOs that changed, not timestamp churn.
- You review and merge the change like any other code change. (The payload
  formats are binary or UTF-16, so for the settings themselves review
  `gpreport.xml` or `Get-GPOReport`; see
  [docs/design.md](docs/design.md#7-format-notes-for-reviewers).)
- `roles/gpo_import` copies the tree to a management host in the target
  domain and converges the domain on it: `Import-GPO -CreateIfNeeded`
  (optionally through a [migration table](docs/design.md#cross-domain)),
  then GPO status, WMI filter links, security filtering, and each
  container's whole ordered link list.

## Requirements

- A Windows management host (or DC) in each domain, reachable over
  WinRM/PSRP, with the **GroupPolicy** and **ActiveDirectory** PowerShell
  modules (RSAT) and rights to read/write GPOs and OU `gPLink` attributes.
- Imports and backups run against the **PDC emulator** by default (found
  automatically) to avoid replication races.
- Controller: `ansible.windows` collection; `unzip` available for
  `ansible.builtin.unarchive`.

## Quickstart

Backup (authoring domain → repo working copy):

```yaml
- hosts: mgmt_lab
  roles:
    - role: git_cgallagher.gpo.gpo_backup
      vars:
        gpo_backup_domain: lab.example.com
        gpo_backup_repo_dir: "{{ playbook_dir }}/gpo-repo"   # controller path
```

Review `git diff`, commit, merge. Then import (repo → target domain):

```yaml
- hosts: mgmt_prod
  roles:
    - role: git_cgallagher.gpo.gpo_import
      vars:
        gpo_import_domain: prod.example.com
        gpo_import_source_dir: "{{ playbook_dir }}/gpo-repo"
        gpo_import_migration_table: migtables/prod.migtable   # optional, repo-relative
        gpo_import_report_only: true    # plan first; flip to false to apply
```

Example playbooks are in [examples/](examples/), including a commented
sample manifest. [docs/scenarios.md](docs/scenarios.md) walks through
real-world changes end to end: a domain password and lockout policy (and why
it must sit above Default Domain Policy), local Administrators membership via
Group Policy Preferences and via Restricted Groups, and promoting a GPO from
lab to production with a migration table. All of them are exercised against
a real domain controller by the `domain_lab` test.

## The manifest

`gpo_backup` regenerates `gpo-manifest.json` on every run; `gpo_import`
treats it as the desired state. Shape:

```jsonc
{
  "domain": "lab.example.com",                   // source domain, for reference
  "netbios": "LAB",
  "root_dn": "DC=lab,DC=example,DC=com",
  "domain_sid": "S-1-5-21-…",
  "gpos": {
    "SEC - Server Baseline": {
      "backup_dir": "SEC - Server Baseline",     // folder under gpos/
      "status": "AllSettingsEnabled",            // or UserSettingsDisabled / ComputerSettingsDisabled / AllSettingsDisabled
      "wmi_filter": "Server OS only",            // or null
      "apply_to": [                              // security filtering (allow GpoApply)
        { "name": "GG-Servers-Prod", "type": "Group" }
      ],
      "denied": []                               // Deny entries, checked but never created
    }
  },
  "wmi_filters": {
    "Server OS only": {
      "description": "Member servers and domain controllers",
      "namespace": "root\\CIMv2",
      "query": "SELECT * FROM Win32_OperatingSystem WHERE ProductType > 1",
      "raw_parm2": "1;3;10;57;WQL;root\\CIMv2;SELECT * FROM Win32_OperatingSystem WHERE ProductType > 1;"
    }
  },
  "soms": [                                      // scopes of management, i.e. link targets
    {
      "target": "OU=Servers",                    // relative to the domain root; "" = the root
      "block_inheritance": false,
      "links": [                                 // order = precedence; first wins
        { "gpo": "SEC - Server Baseline", "enforced": true,  "enabled": true },
        { "gpo": "CFG - RDP Settings",    "enforced": false, "enabled": true }
      ]
    }
  ]
}
```

Conventions worth knowing:

- **Link targets are relative to the domain root** (`OU=Servers,OU=Corp`;
  `""` is the root itself), so one manifest rebases onto any domain with the
  same OU structure.
- **Containers absent from `soms` are unmanaged**: the import never touches
  their links. An OU appears only while it has links or blocks inheritance,
  so unlinking an OU's *last* GPO, or unblocking an OU with no links, doesn't
  propagate yet (tracked in the issues).
- **Deny entries** (e.g. "Deny Apply group policy" for admins) are recorded
  under `denied`, never treated as Apply, and never created: if the target
  GPO lacks one, the import fails and asks you to add it in GPMC.
- **Trustee names are stored domain-relative** (no `DOMAIN\` prefix for the
  source domain's own principals), so the same manifest imports into any
  domain that follows the same group-naming convention — the manifest-level
  analogue of a migration table's "map by relative name".
- When the import downgrades a trustee's Apply permission it sets **Read**,
  never none: a GPO unreadable by Authenticated Users / Domain Computers
  breaks processing entirely (MS16-072).

## Role variables

The main ones. Each role declares every variable in
`meta/argument_specs.yml`, so Ansible checks types and required variables
before the role's first task, and
`ansible-doc -t role git_cgallagher.gpo.gpo_import` (or `gpo_backup`) prints
the full reference. CI checks that the specs agree with `defaults/main.yml`
and that bad input is rejected.

| Variable | Default | Description |
|---|---|---|
| `gpo_backup_domain` / `gpo_import_domain` | — | DNS name of the domain (required) |
| `gpo_backup_server` / `gpo_import_server` | `""` | DC to use; empty = PDC emulator |
| `gpo_backup_repo_dir` | — | Controller directory the export lands in (your repo working copy) |
| `gpo_backup_gpos` | `[]` | Limit to these GPO display names (empty = all) |
| `gpo_backup_full_export` | `false` | Re-ship every GPO even if unchanged |
| `gpo_backup_prune_deleted` | `false` | Delete repo folders for GPOs gone from the domain |
| `gpo_import_source_dir` | — | Controller directory holding `gpos/` + manifest |
| `gpo_import_migration_table` | `""` | `.migtable` path relative to source dir (cross-domain) |
| `gpo_import_report_only` | `false` | Report every action without touching the domain |
| `gpo_import_remove_unmanaged_links` | `false` | Remove links not in the manifest (on managed containers) |
| `gpo_import_create_wmi_filters` | `false` | Create missing WMI filters from the manifest |
| `gpo_import_force` | `false` | Re-import every GPO regardless of state |

## What this doesn't do (yet)

Known gaps, each tracked as a repository issue:

- **Out-of-band content drift in a target domain** isn't detected: the
  import decides from what it last imported, not from the live GPO. The
  first import into a domain therefore re-imports every GPO (bumping their
  versions) even when the content already matches.
- **The change state of a backup lives on the management host**, not in the
  repository: a failed fetch, or exporting into a second working copy,
  "uses up" a change. Export into one working copy per domain from one host.
- **GPOs are identified by display name**: a rename creates a second GPO in
  the target, and GPOs removed from the manifest aren't deleted or unlinked.
- **Unlinking an OU's last GPO** (or unblocking an OU with no links) doesn't
  propagate.
- **Cross-domain guard rails**: nothing yet refuses an import whose payload
  still references the source domain's SIDs, and the two Default GPOs are
  imported like any other. Review migration tables carefully, and see
  [docs/scenarios.md](docs/scenarios.md).
- **Group Policy Preferences XML** isn't translated by migration tables;
  template it per environment before import.
- **Reviewability**: `registry.pol` is binary and `GptTmpl.inf`/`gpreport.xml`
  are UTF-16, so pull-request diffs of those files aren't readable yet.
- Delegation (who may edit a GPO), WMI filters whose query changed (only
  missing filters are created), settings stored in AD rather than SYSVOL
  (wired/wireless and IPsec policies), site-linked GPOs, starter GPOs,
  NETLOGON scripts, the ADMX Central Store, and fine-grained password
  policies (AD objects, not GPOs).
- **Public repositories**: backups contain SIDs, group names, each GPO's
  full ACL, and settings such as firewall and AppLocker rules in plain text.
  Keep the repository that stores your GPOs private.

## License

MIT.
