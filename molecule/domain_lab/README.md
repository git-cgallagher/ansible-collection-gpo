# domain_lab — end-to-end test against a real domain controller

Molecule boots a Windows Server 2022 VM under QEMU/KVM, promotes it to the
first DC of a new forest (`gpolab.test`), and runs `gpo_backup` and
`gpo_import` against it for real. CI runs it in
[`.github/workflows/domain-lab.yml`](../../.github/workflows/domain-lab.yml)
on `ubuntu-latest` (~40 minutes).

## What it proves

| Step | What happens | What's asserted |
|---|---|---|
| create | Download the box (cached, SHA-256 pinned), boot it, wait for its first boot to finish | WinRM/PSRP answers *and* the box's setup script is gone |
| prepare | Promote to DC; reboot until ADWS, SYSVOL and GPMC all answer | — |
| | Seed the authored state (`files/lab_fixture.ps1 -Action Seed`) and export it with `gpo_backup` | Manifest has the exact link order, enforced/disabled links, block-inheritance, security filtering, WMI filter and GPO status; every GPO has a backup folder |
| | Export again | Nothing ships (backup idempotence) |
| | Drift the domain out-of-band (`-Action Drift`) | — |
| | `gpo_import` in report-only mode | Plans the drift's fixes; touches nothing |
| | `gpo_import` on a copy with a GPP `cpassword` planted | Refuses |
| converge | `gpo_import` from the export | — |
| idempotence | Converge again | No task reports a change |
| verify | `files/assert_domain.ps1` reads the domain through GPMC and AD | Links, precedence, inheritance, status, filtering (Authenticated Users kept at Read), WMI filter (GPMC's own parser reads the query back), and settings of three types: Admin Templates, Preferences and security settings (`GptTmpl.inf`) |
| | `gpo_import` report-only again | Zero planned actions |
| | Re-export twice | Manifest identical to the pre-drift export; the second export ships nothing |

The fixture uses GPMC's own APIs wherever one exists (WMI filter linking,
links, permissions, status), so the roles are checked against GPMC rather
than against themselves. The fixture's names live in `molecule.yml`
(`lab_fixture`), shared by both scripts and the YAML assertions.

## The VM image

[`jborean93/WindowsServer2022`](https://portal.cloud.hashicorp.com/vagrant/discover/jborean93/WindowsServer2022)
1.2.0, libvirt provider, built by
[packer-windoze](https://github.com/jborean93/packer-windoze) — the same
image `microsoft.ad`'s own integration tests promote to a DC. Pinned by
version and SHA-256 in `molecule.yml`; `create.yml` boots it the way it was
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
  Basic auth, keeps working. The scenario adds it to Domain Admins.

## Running it locally

Needs Linux with `/dev/kvm`, `qemu-system-x86_64` + `qemu-img`, ~20 GB free
for the first run (box download + unpack + VM disk), and port 5985 free on
`127.0.0.1`. **It can't run on macOS / Apple Silicon** — no x86 hardware
virtualization.

```bash
pip install ansible-core molecule pypsrp
ansible-galaxy collection install -r molecule/domain_lab/requirements.yml
mkdir -p .molecule-collections/ansible_collections/git_cgallagher
ln -sfn ../../.. .molecule-collections/ansible_collections/git_cgallagher/gpo
GPO_LAB_DIR=/path/with/space molecule test -s domain_lab
```

`GPO_LAB_DIR` (default `~/.cache/gpo-domain-lab`) holds the cached box image,
the VM's copy-on-write disk, its pidfile and monitor socket, and the exported
GPO repos (`gpo-repo`, `gpo-repo-after`). The box image survives
`molecule destroy`; delete it by hand to reclaim ~6 GB.

To iterate: `molecule create`, `molecule prepare`, then repeat
`molecule converge` / `molecule verify`; `molecule destroy` when done.

## When it fails in CI

The workflow keeps the VM until diagnostics are collected: a screen dump of
the VM console (`screen.ppm`) and the exported repos are uploaded as the
`domain-lab-diagnostics` artifact. A boot-stage failure (BSOD, stuck OOBE)
shows on the screen dump; a role failure shows in the Ansible output and the
exported manifests.
