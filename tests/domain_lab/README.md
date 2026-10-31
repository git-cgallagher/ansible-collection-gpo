# domain lab — the domain controller the roles' Molecule scenarios test against

Each role has its own Molecule scenario next to it, and both run against a
real domain controller:

| Scenario | What it tests |
|---|---|
| [`roles/gpo_backup/molecule/default`](../../roles/gpo_backup/molecule/default/README.md) | The export: the manifest, the backup folders, that an unchanged domain ships nothing and that a changed GPO ships |
| [`roles/gpo_import/molecule/default`](../../roles/gpo_import/molecule/default/README.md) | The import round trip: out-of-band drift, a report-only plan, the import, the domain read back through GPMC, a re-export, and an import through a migration table |

Each one boots its own Windows Server 2022 VM under QEMU/KVM, promotes it to
the first DC of a new forest (`gpolab.test`) and runs its role against it.
CI runs both in
[`.github/workflows/domain-lab.yml`](../../.github/workflows/domain-lab.yml)
on `ubuntu-latest`, one job per role, in parallel (about 14 minutes).

## What the scenarios share

| Path | What it is |
|---|---|
| [`.config/molecule/config.yml`](../../.config/molecule/config.yml) | Molecule's base config: the pinned box, the provisioner, the inventory, the fixture's names (`lab_fixture`) and the test sequence. Molecule merges it under every scenario's `molecule.yml`, because `--base-config` defaults to that file at the repository root. |
| [`create.yml`](create.yml), [`destroy.yml`](destroy.yml) | Boot and tear down the VM |
| [`promote.yml`](promote.yml) | Promote it to a DC, then wait until AD Web Services, SYSVOL (the domain's DFS path included) and GPMC answer |
| [`seed.yml`](seed.yml), [`files/lab_fixture.ps1`](files/lab_fixture.ps1) | Seed the authored state: OUs, groups, a WMI filter and five GPOs with links and filtering, including the [real-world scenarios](../../docs/scenarios.md). `lab_fixture.ps1 -Action Drift` is the out-of-band drift that `gpo_import`'s scenario repairs. |
| [`requirements.yml`](requirements.yml) | The collections the lab uses: `ansible.windows` and `microsoft.ad` |

Each scenario's `prepare.yml` imports `promote.yml` and `seed.yml`, then adds
its own steps. The fixture uses GPMC's own APIs wherever one exists (WMI
filter linking, links, permissions, status), so the roles are checked against
GPMC rather than against themselves.

## The VM image

[`jborean93/WindowsServer2022`](https://portal.cloud.hashicorp.com/vagrant/discover/jborean93/WindowsServer2022)
1.2.0, libvirt provider, built by
[packer-windoze](https://github.com/jborean93/packer-windoze) — the same
image `microsoft.ad`'s own integration tests promote to a DC. Pinned by
version and SHA-256 in the base config; `create.yml` boots it the way it was
built (`pc` machine, BIOS, virtio disk and NIC, Hyper-V enlightenments).

- It's a sysprepped **evaluation** image. Its first boot rearms the licence
  (`slmgr /rearm`), giving a fresh 180-day window every run despite the
  image's age.
- First boot also reboots once and recreates the WinRM listeners, so
  `create.yml` waits for the setup script to delete itself
  (`C:\temp\setup.ps1`), polling from a fresh process each time, instead of
  trusting the first successful connection.
- The connection is PSRP with NTLM as `vagrant`/`vagrant` (the box's public
  defaults). After promotion that account is a domain account; NTLM, unlike
  Basic auth, keeps working. `promote.yml` adds it to Domain Admins.

## Running it locally

Needs Linux with `/dev/kvm`, `qemu-system-x86_64` + `qemu-img`, ~20 GB free
for the first run (box download + unpack + VM disk), and port 5985 free on
`127.0.0.1`. **It can't run on macOS / Apple Silicon** — no x86 hardware
virtualization.

```bash
pip install ansible-core molecule pypsrp
ansible-galaxy collection install -r tests/domain_lab/requirements.yml
mkdir -p .molecule-collections/ansible_collections/git_cgallagher
ln -sfn ../../.. .molecule-collections/ansible_collections/git_cgallagher/gpo
cd roles/gpo_import    # or roles/gpo_backup
GPO_LAB_DIR=/path/with/space molecule test
```

Run Molecule from the role's directory. That's where it finds the role's
scenario, and how its prerun tells a role inside a collection from a
standalone role: from `roles/<role>` it installs the collection from `../..`
instead of checking the role's name the way it would a standalone role's.

On a Mac, `molecule list` and `molecule syntax` still work from a role's
directory, and `molecule create` runs up to the `/dev/kvm` check.

`GPO_LAB_DIR` (default `~/.cache/gpo-domain-lab`) holds the cached box image,
the VM's copy-on-write disk, its pidfile and monitor socket, and the exported
GPO repos (`gpo-repo`, `gpo-repo-after`). The box image survives
`molecule destroy`; delete it by hand to reclaim ~6 GB. Both scenarios use
the same VM name and port, so run one at a time.

To iterate: `molecule create`, `molecule prepare`, then repeat
`molecule converge` / `molecule verify`; `molecule destroy` when done.

## When it fails in CI

The workflow keeps the VM until diagnostics are collected: a screen dump of
the VM console (`screen.ppm`) and the exported repos are uploaded as the
`domain-lab-diagnostics-<role>` artifact. A boot-stage failure (BSOD, stuck
OOBE) shows on the screen dump; a role failure shows in the Ansible output and
the exported manifests.
