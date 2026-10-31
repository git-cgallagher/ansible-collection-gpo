# gpo_backup's Molecule scenario

Exports a real domain with `gpo_backup` and checks the export. The domain
controller, the fixture and how to run it are described in
[tests/domain_lab](../../../../tests/domain_lab/README.md); run this scenario
from `roles/gpo_backup` with `molecule test`.

| Step | What happens | What's asserted |
|---|---|---|
| create | Boot the VM (the box is cached and SHA-256 pinned) and wait for its first boot to finish | WinRM/PSRP answers *and* the box's setup script is gone |
| prepare | Promote it to a DC; seed the authored state: five GPOs, including the [real-world scenarios](../../../../docs/scenarios.md); clear any previous export and the host's backup state | — |
| converge | `gpo_backup` exports the domain into an empty repo | — |
| idempotence | Export again | No task reports a change: an unchanged domain ships nothing |
| verify | Read the export | The manifest has the exact link order (domain root included), enforced and disabled links, block-inheritance, security filtering, the WMI filter and GPO status; every GPO has a backup folder |
| | Change a setting in one GPO through GPMC, then export again | That GPO ships, and only it; the manifest doesn't change |
