# AGENTS.md — ansible-collection-gpo

> Read `~/Code/AGENTS.md` first (workspace-wide rules). This file covers only
> this repo.

## What this is

Public Ansible collection **`git_cgallagher.gpo`** (MIT): Windows Group
Policy as code via `Backup-GPO`/`Import-GPO` plus a JSON manifest for links,
precedence, filtering, WMI filters and status. Problem statement + decisions:
`docs/design.md`. Two roles:

- `roles/gpo_backup` — export GPOs + manifest from a domain into a Git
  working copy (zip over WinRM, content-hash state so only changes ship).
- `roles/gpo_import` — converge a target domain on the repo (import +
  reconcile topology; migration-table aware; report-only mode).

## ⚠️ Maturity — read before relying on it

**Lab-tested within one domain.** The `domain_lab` Molecule scenario
(`molecule/domain_lab/`, the `domain-lab` workflow) boots a real Windows
Server 2022 VM under KVM, promotes it to a DC and runs both roles against
it: seed, export, out-of-band drift, report-only plan, import, verify,
re-export round trip, and an import through a migration table. It first
passed on 2026-10-28 (PR #1, the initial collection), which closed the
lab-validation issue (#2). It can't run on macOS. Other CI:
ansible-lint/yamllint, ansible-test sanity (including pslint), PowerShell
parse + PSScriptAnalyzer, a `cpassword` grep, and the `argument-specs`
workflow. Known gaps found by review are tracked as repo issues and listed
in the README's "What this doesn't do (yet)".

Not covered by the lab yet (issue #16 unless noted):

- importing into a *different* domain: link targets rebased onto another
  root DN, domain-relative trustee names, a migration table between domains
- `--check` runs (`gpo_import` maps check mode onto report-only, which is
  covered; `gpo_backup` has its own check-mode path)
- security filtering on trustees other than domain groups and Authenticated
  Users, and Deny entries (the lab's GPOs have none)
- a member-server management host and a least-privilege account (#15);
  multi-query WMI filters aren't supported (#13)

`domain-lab` is deliberately not a required check: it's path-filtered (a
required check that never starts blocks merges forever) and depends on a
third-party box download. Promote it after four consecutive green weekly
runs, and replace the path filter with a job that always reports and skips
the lab when nothing relevant changed.

When the lab disagrees with the scripts, fix the scripts — don't bend the
lab to the scripts — and record the surprise below as a gotcha.

## Conventions

- PowerShell lives in `roles/*/files/*.ps1`, executed via
  `ansible.windows.win_powershell` with `parameters:`; scripts must stay
  **Windows PowerShell 5.1-compatible** (no `??`, no ternary, no
  `ConvertFrom-Json -AsHashtable`).
- Both scripts duplicate a small `# region common` helper block — keep the
  copies in sync.
- The manifest (`gpo-manifest.json`) is the contract between the roles.
  Round-trip symmetry is the invariant: whatever `gpo_backup` writes,
  `gpo_import` consumes verbatim. Change both sides and the README together.
- The backup zip is built entry by entry (`New-ZipFromDirectory`), never with
  `Compress-Archive` (drops empty directories, which GPO backups contain) or
  `ZipFile::CreateFromDirectory` (some .NET Framework/PowerShell 5.1
  combinations write backslash separators, which Linux `unzip` warns about
  and `unarchive` treats as failure). Entries use `/`; empty directories get
  explicit entries.
- **Role variables are declared in `roles/*/meta/argument_specs.yml`** (the
  reference, and what Ansible validates against). Required variables have no
  entry in `defaults/main.yml`; every other variable's spec `default` must
  equal its `defaults/main.yml` value. The `argument-specs` workflow
  (`tests/argument_specs/`) enforces both. Add or change a variable in the
  spec, defaults, README table and tasks together.
- Release flow mirrors `ansible-collection-isc`: every merge that changes
  shipped files must bump `galaxy.yml` + add a `CHANGELOG.md` entry
  (CI-enforced). `release.yml` is **workflow_dispatch-only** until
  `GALAXY_API_KEY` exists in a main-only `galaxy` environment (issue #3);
  the lab validation it also waited for passed on 2026-10-28. Then restore
  the `workflow_run` trigger.

## Commands

```bash
# lint (what CI runs)
pip install ansible-core ansible-lint yamllint
ansible-galaxy collection install -r requirements.yml
yamllint . && ansible-lint

# PowerShell lint exactly as CI's `ansible-test sanity` pslint runs it — the
# settings ship inside ansible-core; Invoke-Formatter with the same -Settings
# auto-fixes brace/whitespace/indentation findings (how 0.1.0 was styled):
S=$(python3 -c 'import ansible_test, pathlib; print(pathlib.Path(ansible_test.__file__).parent / "_util/controller/sanity/pslint/settings.psd1")')
pwsh -c "Invoke-ScriptAnalyzer -Path roles -Recurse -Settings '$S'"

# argument specs (what the argument-specs workflow runs): build + install the
# collection, render the role docs, check specs vs defaults and validation
ansible-galaxy collection build --force --output-path /tmp/dist
ansible-galaxy collection install /tmp/dist/git_cgallagher-gpo-*.tar.gz -p /tmp/colls --force
ANSIBLE_COLLECTIONS_PATH=/tmp/colls:~/.ansible/collections ansible-doc -t role git_cgallagher.gpo.gpo_import
ANSIBLE_COLLECTIONS_PATH=/tmp/colls:~/.ansible/collections ansible-playbook tests/argument_specs/validate.yml

# build the tarball
ansible-galaxy collection build --force
```

## ⚠️ Gotchas

- **Write GPO AD objects through GPMC (or LDAP), never `Set-ADObject`.**
  Confirmed in the domain_lab runs of 2026-10-28: `Set-ADObject` (AD Web
  Services) on a GPO's `groupPolicyContainer` fails with 8344 "insufficient
  access rights" even though the session's token holds Domain Admins,
  BUILTIN\Administrators and Group Policy Creator Owners (checked with
  `whoami /groups` on the DC itself, so not a double hop). GPMC's writes and
  ADSI/LDAP writes to the same objects succeed. The exact ADWS cause is
  unknown. The roles link and clear WMI filters with `Gpo.WmiFilter` (clearing
  with `$null` is verified); the fixture uses ADSI for writes GPMC can't
  express. ADWS *creates* (`New-ADObject` for `msWMI-Som`) do work.
- **`Import-GPO` re-serializes security templates.** An imported GPO's
  `GptTmpl.inf` has GPMC's canonical section order and sorted Restricted
  Groups members, so it's byte-different from the backup even when every
  setting matches. Compare security templates semantically, and expect the
  first export after an import to re-ship such GPOs once (the next one ships
  nothing). Matters for the "adopt without reimporting" design (issue #9).
- **`Import-GPO` restores GPO status** (the computer/user halves), unlike
  links, filtering and the WMI filter link.
- **After promoting a DC, wait for `\\<domain>\SYSVOL` itself**, not just
  the SYSVOL share and `SysvolReady`. Group Policy Preferences cmdlets write
  through the domain's DFS path, which failed with "The network path was not
  found" in one lab run 6 seconds after the other checks passed.
  `prepare.yml` polls `Test-Path \\<domain>\SYSVOL\<domain>\Policies`.
- **The effective domain password policy** follows link order at the domain
  root after `gpupdate /target:computer /force` on the PDC (the first refresh
  after promotion took about 90 seconds in the lab).

- **`ansible-test sanity` runs pslint over every `*.ps1` in the collection**,
  `roles/*/files/` included, with ansible-core's own `settings.psd1`:
  uncuddled `else`/`catch`/`finally` (close brace gets its own line), no
  aligned `=` columns, 4-space pipeline indentation. PR #1 (the initial
  collection PR) failed all five sanity jobs on 72 style findings; the fix is
  the `Invoke-Formatter` command above, not hand-editing.
- **On a pull request, `domain-lab`'s `paths:` filter matches the whole PR
  diff, not the pushed commit.** Once a PR touches `roles/**` or
  `molecule/**`, every push to it re-runs the 14-minute lab, docs-only
  pushes included (PR #1's last docs commit did). Batch the doc edits.
- `Import-GPO` **replaces the whole GPO** and bumps its version (clients
  reprocess). That's why both roles hash content and keep state files
  (`C:\ProgramData\gpo-iac\*-state-<domain>.json` on the management host) —
  don't "simplify" that away.
- Security filtering: never remove a trustee's last permission — downgrade
  Apply→Read (MS16-072). The import does this; keep it that way.
- Trustee names in the manifest are domain-relative (source NetBIOS prefix
  stripped) — that's deliberate cross-domain behaviour, not a bug.
- GPP `cpassword`: the import hard-fails on it, CI greps for it. Never
  weaken either check.
- GPO backups embed SIDs/domain names. Fine for the *consuming* (usually
  private) repo; never commit real-domain backups to THIS public repo —
  examples use `example.com` placeholders only.
