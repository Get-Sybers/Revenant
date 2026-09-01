# Revenant

  Resurrect dead-box DFIR and range images into live Proxmox VMs, packaged as a Ludus source you can apply and deploy.

## Status

scoping.

## Overview

Revenant takes a powered-off forensic image (range capture, CTF, incident acquisition) and boots it back to life as a Proxmox VM, wrapped as a Ludus source so it deploys the same way as anything else in your range. It pulls the users and creds out of the image on the way, so you can log in and work the box instead of just reading it from outside.

Dead-box forensics is the analysis of a system that's powered off and inert. Revenant reverses that. A revenant comes back from the dead; so does your image.

## Why Proxmox and Ludus

Ludus builds ranges as code on Proxmox, but its templates are baked from clean ISOs with Packer. DFIR images are the opposite: a system that already existed, with real users and a real story. Revenant imports the existing image instead, registers it as a Proxmox template, and ships a blueprint that drops it into a range. Ludus is an overlay on Proxmox, so the result is a first-class Proxmox object either way.

## Repository layout

Revenant is packaged as a Ludus **source**: a catalog of blueprints, Packer templates, and Ansible roles and collections that `ludus source add` installs. Layout follows the Ludus source template.

```
revenant/                         Ludus source root
├── blueprints/                   one dir per resurrection scenario
│   └── <scenario>/
│       ├── blueprint.yml         name, description, what it deploys
│       ├── range-config.yml      Ludus range referencing the resurrected template
│       ├── requirements.yml      role + collection dependencies
│       ├── subscription_refs.yml pins to shared source content
│       ├── roles/                scenario-specific roles
│       ├── templates/            scenario-specific Packer templates, if any
│       └── README.md
├── templates/                    Packer templates shared across blueprints
├── ansible/
│   ├── roles/                    revenant_credential_reset, revenant_first_boot, etc.
│   └── collections/              vendored collections
├── LICENSE
└── README.md
```

Revenant has two halves. The CLI does the ingest, extract, and resurrect work against an image. The source ships the Ludus artifacts that wrap the result. The wrinkle: a Ludus `templates/` entry is normally a Packer build, but a resurrected host is imported, so Revenant registers it as a Proxmox template with `qm template` and the range-config references it by name. The `templates/` dirs are for companion VMs a scenario needs (an analyst box, a collector), not the resurrected host itself.

## How it works

**1. Ingest.** Read the image and convert to a Proxmox-friendly disk (qcow2 or raw, matching `proxmox_vm_storage_format`). Formats: E01/EWF, raw dd, VMDK, VHD/VHDX, qcow2. Memory captures handled separately.

**2. Extract.** Produce a users-and-creds report, plus the facts Resurrect needs to boot the box right:

- Users and hashes from the on-disk registry hives (SAM/SYSTEM).
- Creds and sessions from memory via Volatility, when a memory image exists.
- OS, hostname, and firmware type via Plaso (log2timeline to process, pinfo to report). The OS maps to the Proxmox `ostype`; the firmware type decides SeaBIOS vs OVMF.

**3. Resurrect.** Land the disk on the node and register it as a template, following the [qm](https://pve.proxmox.com/pve-docs/chapter-qm.html) chapter:

```
# Linux image: create the VM, import the disk, boot from it
qm create <vmid> \
  --name <scenario> --ostype l26 \
  --scsihw virtio-scsi-single \
  --scsi0 <storage>:0,import-from=<path/to/disk.qcow2> \
  --boot order=scsi0 --agent enabled=1
qm template <vmid>
```

- OVF/OVA sources import with `qm importovf <vmid> <file>.ovf <storage>` instead.
- `--ostype` comes from pinfo: `l26` for Linux, the matching `winXX` for Windows. Windows sets the RTC to local time and pins the machine version.
- UEFI images need `--bios ovmf` plus an EFI disk (`qm set <vmid> --efidisk0 <storage>:1,efitype=4m,pre-enrolled-keys=1`). Windows 11 also needs `--machine q35` and a TPM (`qm set <vmid> --tpmstate0 <storage>:1,version=v2.0`).
- Windows imaged off other hardware may not boot on virtio-scsi without drivers. Attach on SATA or IDE for first boot, or inject virtio drivers, then switch.
- Domain controllers get a fresh `--vmgenid 1` so the guest treats it as a clean restore.

Then the Ludus half:

- Reset or inject the recovered creds so the accounts actually log in (`revenant_credential_reset`).
- Emit the blueprint: `blueprint.yml` plus a `range-config.yml` referencing the template, so `ludus blueprint apply revenant/<scenario>` then `ludus range deploy` stands it up.

Networking, VLANs, and access stay with Ludus.

## Built on

- [Plaso](https://github.com/log2timeline/plaso) (log2timeline + pinfo) for OS and system details
- [Volatility](https://github.com/volatilityfoundation/volatility3) for memory analysis
- Registry/hive parsing for on-disk users and creds
- [Proxmox VE](https://pve.proxmox.com/pve-docs/chapter-qm.html) (`qm`, `qemu-img`) for import and templating
- Packer + Ansible for Ludus templates and provisioning
- [Ludus](https://docs.ludus.cloud/) for source packaging, blueprints, and deployment

## Scope & use

For authorized forensics, training, and range work on images you own or may analyze. Not for booting or cracking images you have no authorization for.
