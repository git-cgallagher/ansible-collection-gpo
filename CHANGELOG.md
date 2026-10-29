# Changelog

## 0.1.0 — 2026-10-28

Initial release of `git_cgallagher.gpo`, tested end to end against a real
Windows Server 2022 domain controller in CI (`molecule/domain_lab`), within
one domain. Importing into a different domain isn't lab-tested yet (issue
#16).

- `gpo_backup`: exports every GPO in a domain (`Backup-GPO`, one
  self-contained backup folder per GPO) plus a `gpo-manifest.json` capturing
  what `Import-GPO` can't: link targets, link order (precedence), enforced /
  enabled flags, block-inheritance, security filtering, WMI filters and GPO
  status. Ships only what changed since the last export (content-hash state
  on the management host) so Git diffs stay reviewable.
- Manifest link targets are relative to the domain root (`""` = the root),
  so one export rebases onto another domain; the manifest also records the
  source `root_dn` and `domain_sid`, and each GPO's Deny entries (`denied`),
  which are never treated as Apply and, when missing in a target, fail the
  import (they can't be created through GPMC's cmdlets).
- `gpo_import`: imports backups into a (possibly different) target domain
  with `Import-GPO -CreateIfNeeded`, optional migration table, then
  reconciles GPO status, WMI filter links, security filtering (keeping Read
  for removed Apply trustees — MS16-072) and each container's whole ordered
  link list. Refuses any backup containing GPP `cpassword`. Report-only mode
  for plan-style runs.
- Both roles declare their variables in `meta/argument_specs.yml`: Ansible
  validates types and required variables before the first task, and
  `ansible-doc -t role git_cgallagher.gpo.<role>` documents them.
- `docs/design.md`: the problem statement — why domain GPOs resist IaC, why
  backup/import is the only mechanism covering every setting type, and what
  it still doesn't cover.
- `docs/scenarios.md`: worked real-world examples — a domain password and
  lockout policy above Default Domain Policy, local Administrators via Group
  Policy Preferences and via Restricted Groups, and lab → production
  promotion with a migration table.
