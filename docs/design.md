# Design: why backup/import, and what it doesn't solve

This document is the problem statement behind the collection: why domain
Group Policy resists infrastructure-as-code, which approaches were
considered, and the decisions that shaped the two roles.

## 1. The problem

The goal is ordinary IaC hygiene for Group Policy: settings in Git, changes
as reviewed pull requests, repeatable deployment to lab → staging → prod,
drift visible, and precedence (link order, enforcement, inheritance) treated
as part of the configuration rather than tribal GPMC knowledge.

A GPO is an AD object (`groupPolicyContainer`) plus a SYSVOL folder, and the
SYSVOL half is a *bundle of unrelated formats*, one per client-side
extension (CSE):

| Setting type | Where it lives | Authorable as code? |
|---|---|---|
| Admin Templates (registry-based) | `registry.pol` (binary) | yes — `Set-GPRegistryValue` |
| Security settings: user rights, password/lockout/Kerberos policy, restricted groups, services, registry/file ACLs | `GptTmpl.inf` (UTF-16 INI) | no GPMC cmdlet |
| Advanced audit policy | `audit.csv` | no cmdlet |
| Group Policy Preferences (drives, tasks, files, local users, …) | XML under `Preferences\` | only registry prefs (`Set-GPPrefRegistryValue`) |
| Links, order, enforcement, block-inheritance, security filtering, WMI filters | AD attributes (`gPLink`, `gPOptions`, DACL, `gPCWQLFilter`) | yes — GroupPolicy module |

Because the write API covers only the registry-based formats, every
"declarative GPO" tool inherits the same ceiling:

- **DSC** (`SecurityPolicyDsc`, `AuditPolicyDsc`, `GPRegistryPolicyDsc`) and
  **Ansible** (`win_security_policy`, `win_audit_policy_system`, `win_dsc`)
  manage *local* policy on each host — useful, but not domain GPOs, and a
  setting managed both ways has two owners (domain GPO wins).
- **Terraform**'s `hashicorp/ad` provider has `ad_gpo` / `ad_gplink` /
  `ad_gpo_security` with partial security-settings support, no Admin
  Templates, and little maintenance.
- **`Set-GPRegistryValue`** authors most Admin Templates cleanly but nothing
  else.

The one mechanism that covers *every* setting type is `Backup-GPO` /
`Import-GPO`, because it copies the files verbatim without parsing them.
Microsoft ships its own security baselines exactly this way (GPO backup
folders plus an import script). The trade-off is that the artifacts are
opaque-ish blobs rather than readable source — mitigated below.

**Decision:** backup/import is the only write path for GPO *contents*; a
declarative JSON manifest handles GPO *topology* (everything an import
doesn't carry); GPMC in an authoring/lab domain is the editor. One workflow,
all setting types.

## 2. What `Import-GPO` does and doesn't carry

`Import-GPO` writes a backup's settings into a new or existing GPO — in any
domain, trusted or not, since a backup is just files (`Restore-GPO`, by
contrast, is same-domain/same-GUID disaster recovery). It does **not**
carry:

- links to OUs/domain (and their order, enforcement, enabled flags)
- block-inheritance on containers
- the GPO's own ACL → security filtering
- WMI filter objects and the GPO→filter link
- GPO status (computer/user halves enabled)

Those live in the manifest (`gpo-manifest.json`), generated from the live
domain by `gpo_backup` and converged by `gpo_import`:

- **Links**: per scope-of-management (domain root + every OU), the *whole
  ordered list* is reconciled, not individual links — `Set-GPLink -Order`
  renumbers its neighbours, so per-link reconciliation never converges
  reliably. Setting positions 1..N in manifest order against a simulated
  work-list does.
- **Security filtering**: trustees with `GpoApply`. Removed trustees are
  downgraded to `GpoRead`, never stripped: after MS16-072, a computer that
  can't *read* a GPO can't process it at all.
- **WMI filters**: not part of any GPO backup (they're separate
  `msWMI-Som` objects). The manifest records name/namespace/query; the
  import can recreate them (`gpo_import_create_wmi_filters`) and relinks
  GPOs by name through GPMC's API (`Gpo.WmiFilter`), not a raw
  `gPCWQLFilter` write.
- **Unmanaged containers**: a container absent from the manifest is never
  touched; on managed containers, extra links are reported, and removed
  only with `gpo_import_remove_unmanaged_links: true` (adopt-then-enforce).

## 3. Idempotency without parsing settings

Importing on every run would be *convergent* but noisy: each import bumps
the GPO version, making every client reprocess it, and makes "what changed"
unanswerable. The usual fix — compare normalized `Get-GPOReport` XML — needs
semantic knowledge of the report format and can't be built blind, so v0.x
uses **content hashes + state files** instead:

- `gpo_backup` hashes each fresh backup's `DomainSysvol` subtree (the
  settings payload; the backup's `Backup.xml` / `bkupInfo.xml` /
  `gpreport.xml` carry timestamps and backup GUIDs that would churn). A GPO
  is re-shipped only when that hash changes, so unchanged GPOs stay
  byte-identical in Git.
- `gpo_import` hashes each backup folder in the repo and records, per GPO,
  the hash it last imported (state file on the management host, per
  domain). A GPO is imported when it's missing, its backup hash changed, or
  `gpo_import_force` is set.

Consequences to be aware of:

- Out-of-band edits in the *target* domain are *not* detected by the import
  (the state file only tracks what the pipeline did). Drift detection =
  re-run `gpo_backup` against the target and diff, or the future
  normalized-report compare (tracked issue).
- The state lives on the management host: use the same host per domain, or
  accept a one-time re-import after moving hosts.
- `GPT.INI`-level version bumps inside `DomainSysvol` mean some
  non-settings edits still re-ship a GPO. Harmless: the Git diff shows
  exactly how trivial the change was.

## 4. Cross-domain

A backup from domain A imports into domain B (lab → prod promotion, or one
baseline stamped into many domains). Domain-specific data inside settings is
the hazard:

| Content | Behaviour |
|---|---|
| Registry values, audit CSV, security-policy *numbers* | import as-is |
| Security principals in security settings (user rights, restricted groups, services, file/registry ACLs) | **migration table** (`Import-GPO -MigrationTable`) |
| UNC paths (folder redirection, software installation, scripts) | migration table |
| **GPP XML** (item-level targeting SIDs, embedded domain names, UNCs) | **migration tables do not process GPP** — template `Preferences\*.xml` per environment before import |
| well-known SIDs (Authenticated Users, SYSTEM, …) | identical everywhere, no mapping |

Supporting conventions in this collection:

- The manifest stores trustee names **domain-relative** (the source domain's
  `NETBIOS\` prefix is stripped), so security filtering maps by relative
  name automatically. Destination groups must exist first.
- Build migration tables with `mtedit.exe` ("Populate from Backup") or the
  `GPMgmt.GPM` COM API; commit one per target environment. `Import-GPO` has
  no "use table exclusively" switch, so unmapped principals import as
  orphaned SIDs — after a first cross-domain import, grep
  `Get-GPOReport` output for the *source* domain's SID prefix
  (`S-1-5-21-…`) and NetBIOS name to catch anything the table missed.
- ADMX parity does not gate application: clients apply `registry.pol`
  regardless of the target's Central Store; GPMC just shows "Extra Registry
  Settings" until the ADMX files are synced.
- `gpo_import` **refuses any backup containing `cpassword`** (GPP
  passwords: deprecated, trivially decryptable, and a secret in Git).

## 5. Operational rules

- **Backup and import run against the PDC emulator** (default when
  `*_server` is empty) so AD writes and SYSVOL (DFSR) reads don't race
  replication.
- **One write path.** Once a GPO is pipeline-managed, hand edits in the
  target domain get overwritten by the next changed import, and
  `Set-GPRegistryValue`-style edits on top create two sources of truth.
  Restrict GPMC edit rights in target domains to the pipeline account plus
  break-glass.
- **Adopt before enforcing.** First runs against an existing domain: backup
  it, commit as the baseline, and keep
  `gpo_import_remove_unmanaged_links: false` until the manifest is
  deliberately complete.
- **Don't manage the same setting at two layers** (domain GPO here, local
  policy via Ansible/DSC there) — domain wins and the loser flaps.

## 6. Rejected / deferred alternatives

| Option | Verdict |
|---|---|
| Pure `Set-GPRegistryValue` authoring | fine for Admin Templates, can't reach the rest; kept as a complement, not the write path |
| Terraform `ad` provider | partial coverage, stale; not worth a second toolchain next to Ansible |
| DSC / `win_dsc` / local-policy modules | manages local policy, not domain GPOs; still the right answer for hosts where a domain GPO isn't required |
| AGPM | change control for GPMC, not code; end-of-life |
| SDM Software GPAE | the one commercial tool that authors ~every setting type as code; the buy-option if this pipeline isn't enough |
| `Get-GPOReport` normalized diff for drift | right idea, needs a live domain to build against — tracked as an issue |
| Readable diffs of `registry.pol` (`LGPO.exe /parse` textconv) and `GptTmpl.inf` (UTF-16 gitattributes) | recommended in the consuming repo; tracked as an issue to document |

## 7. Format notes for reviewers

The committed artifacts under `gpos/<Name>/` are a verbatim
`Backup-GPO` output: `manifest.xml` + `{backup-guid}/` containing
`Backup.xml`, `bkupInfo.xml`, `gpreport.xml` (human-readable XML report —
**start here when reviewing a diff**) and `DomainSysvol/` (the actual
payload). `GptTmpl.inf` is UTF-16; add

```gitattributes
*.inf working-tree-encoding=UTF-16LE
*.pol -text
```

to the consuming repo so security-settings diffs render as text and
`registry.pol` is never newline-mangled.
