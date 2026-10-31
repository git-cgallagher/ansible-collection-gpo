# gpo_import's Molecule scenario

Drifts a real domain away from a `gpo_backup` export and checks that
`gpo_import` puts it back. The domain controller, the fixture and how to run
it are described in [tests/domain_lab](../../../../tests/domain_lab/README.md);
run this scenario from `roles/gpo_import` with `molecule test`.

| Step | What happens | What's asserted |
|---|---|---|
| create | Boot the VM (the box is cached and SHA-256 pinned) and wait for its first boot to finish | WinRM/PSRP answers *and* the box's setup script is gone |
| prepare | Promote it to a DC; reboot until AD Web Services, SYSVOL and GPMC all answer | — |
| | Seed the authored state (`lab_fixture.ps1 -Action Seed`): five GPOs including the [real-world scenarios](../../../../docs/scenarios.md) | The seeded domain password policy, linked above Default Domain Policy, is the *effective* policy (14 characters, lockout at 5) |
| | Export it with `gpo_backup` (`gpo_backup`'s own scenario checks the export) | — |
| | Drift the domain out-of-band (`-Action Drift`): delete a GPO and the WMI filter, reorder the domain root, add Domain Users to the servers' local Administrators preference, unlink the Restricted Groups GPO, and more | Default Domain Policy's weaker settings now win (7 characters, no lockout) |
| | `gpo_import` in report-only mode | Plans the drift's fixes; touches nothing |
| | `gpo_import` on a copy with a GPP `cpassword` planted | Refuses |
| converge | `gpo_import` from the export | — |
| idempotence | Converge again | No task reports a change |
| verify | `files/assert_domain.ps1` reads the domain through GPMC and AD | Links, precedence, inheritance, status, filtering (Authenticated Users kept at Read), WMI filter (GPMC's own parser reads the query back), and settings of four types: Admin Templates, Preferences (including local Administrators), security settings and Restricted Groups |
| | Read the effective domain password policy | Back to 14 characters and lockout at 5 |
| | `gpo_import` report-only again | Zero planned actions |
| | Re-export twice | Manifest identical to the pre-drift export; the second export ships nothing |
| | Build a migration table with GPMC's API, import the Restricted Groups GPO through it, export, then import it again without the table | The table rewrote the member's SID; the export shipped exactly that GPO; the plain import restored the original |
