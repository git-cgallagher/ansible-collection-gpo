# Changelog

## 0.1.0 — 2026-10-27

Initial release of `git_cgallagher.gpo`. **Not yet validated against a live
domain** — see the tracking issue before using in anger.

- `gpo_backup`: exports every GPO in a domain (`Backup-GPO`, one
  self-contained backup folder per GPO) plus a `gpo-manifest.json` capturing
  what `Import-GPO` can't: link targets, link order (precedence), enforced /
  enabled flags, block-inheritance, security filtering, WMI filters and GPO
  status. Ships only what changed since the last export (content-hash state
  on the management host) so Git diffs stay reviewable.
- `gpo_import`: imports backups into a (possibly different) target domain
  with `Import-GPO -CreateIfNeeded`, optional migration table, then
  reconciles GPO status, WMI filter links, security filtering (keeping Read
  for removed Apply trustees — MS16-072) and each container's whole ordered
  link list. Refuses any backup containing GPP `cpassword`. Report-only mode
  for plan-style runs.
- `docs/design.md`: the problem statement — why domain GPOs resist IaC, why
  backup/import is the only mechanism covering every setting type, and what
  it still doesn't cover.
