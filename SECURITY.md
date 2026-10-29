# Security policy

## Reporting a vulnerability

Please report security issues **privately** through GitHub:
[Report a vulnerability](https://github.com/git-cgallagher/ansible-collection-gpo/security/advisories/new)
(the **Security** tab, then **Report a vulnerability**). Don't open a public issue for a security problem.

You can expect an acknowledgement within a week. This is a one-person project, so fixes are best effort.

## Supported versions

Only the latest release gets fixes.

## Scope

This collection exports and imports Windows Group Policy Objects with the privileges your
playbook gives it (typically Domain Admin-equivalent on a management host). In scope:

- how it handles GPO backup contents, which embed security principals, SIDs and UNC paths;
- the `cpassword` refusal check (`gpo_import` must never deploy a backup containing
  Group Policy Preferences passwords);
- the AD objects it writes (GPOs, gPLink/gPOptions, WMI filters, GPO permissions).

Vulnerabilities in Windows, GPMC or the GroupPolicy PowerShell module itself belong with
Microsoft.

## A note on backup contents

GPO backups you commit to a repository can contain domain names, SIDs, group names and UNC
paths. That is usually acceptable for a private repo and a deliberate decision for a public
one — but never commit a backup containing secrets (GPP `cpassword`, embedded scripts with
credentials). The import role refuses `cpassword`; nothing scans your scripts for you.
