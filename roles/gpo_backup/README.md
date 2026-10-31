# git_cgallagher.gpo.gpo_backup

Exports every GPO in a domain (`Backup-GPO`, one self-contained backup folder
per GPO) plus `gpo-manifest.json` — links, precedence, enforcement,
block-inheritance, security filtering, WMI filters, GPO status — from a
Windows management host into a directory on the controller (your repo working
copy). Only GPOs whose settings content changed since the last run are
re-shipped, so Git diffs stay reviewable.

Runs against the domain's PDC emulator unless `gpo_backup_server` is set.
Requires RSAT (GroupPolicy + ActiveDirectory modules) on the target host and
`unzip` on the controller.

All variables are documented in
[meta/argument_specs.yml](meta/argument_specs.yml), which Ansible also uses to
validate them (`ansible-doc -t role git_cgallagher.gpo.gpo_backup`); the
workflow and manifest format are in the
[collection README](../../README.md).

Its Molecule scenario,
[`molecule/default`](https://github.com/git-cgallagher/ansible-collection-gpo/tree/main/roles/gpo_backup/molecule/default),
tests the export end to end against a real domain controller.
