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

**Nothing here has run against a live AD domain yet.** There is no Molecule
scenario because a domain controller can't run in a container. CI covers:
ansible-lint/yamllint, ansible-test sanity, PowerShell parse +
PSScriptAnalyzer, and a `cpassword` grep. The first lab-domain validation is
tracked in the repo issues; until it closes, treat these as the known-blind
spots:

- `msWMI-Som` creation (`msWMI-Parm2` encoding) and `gPCWQLFilter` format.
- `Backup-GPO`-folder-per-GPO layout assumptions (`manifest.xml` +
  single `{guid}` dir) and `Import-GPO -BackupGpoName` against it.
- `Get-GPInheritance`/`Set-GPLink` property shapes (`GpoInheritanceBlocked`,
  Yes/No enums) and the link-order work-list reconciliation.
- Multi-query WMI filters (parser/encoder handle the single-query form).

When validating, fix the scripts — don't bend the lab to the scripts — and
record surprises here as gotchas.

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
- Release flow mirrors `ansible-collection-isc`: every merge that changes
  shipped files must bump `galaxy.yml` + add a `CHANGELOG.md` entry
  (CI-enforced). `release.yml` is **workflow_dispatch-only** until
  `GALAXY_API_KEY` exists in a main-only `galaxy` environment and the
  collection has been lab-validated — then restore the `workflow_run`
  trigger (see the tracking issue).

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

# build the tarball
ansible-galaxy collection build --force
```

## ⚠️ Gotchas

- **`ansible-test sanity` runs pslint over every `*.ps1` in the collection**,
  `roles/*/files/` included, with ansible-core's own `settings.psd1`:
  uncuddled `else`/`catch`/`finally` (close brace gets its own line), no
  aligned `=` columns, 4-space pipeline indentation. PR #1 (the initial
  collection PR) failed all five sanity jobs on 72 style findings; the fix is
  the `Invoke-Formatter` command above, not hand-editing.
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
