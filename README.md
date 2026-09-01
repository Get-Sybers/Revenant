# Revenant

> Resurrect dead-box DFIR and range images into live Proxmox VMs, packaged as a Ludus source you can apply and deploy.

## Status

scoping.

## Overview

Revenant takes a forensic scenario, starting with [Digital Corpora](https://digitalcorpora.org): a disk image, often with a memory dump and packet captures alongside. It boots the disk back to life as a Proxmox VM, wrapped as a Ludus source so it deploys like anything else in your range. It recovers the users and creds on the way in, and when the scenario ships pcaps it replays them into the range. You get a live host and its original network traffic, instead of a dead file to read.

## Why Proxmox and Ludus

Ludus builds ranges as code on Proxmox, but its templates are baked from clean ISOs with Packer. DFIR images are the opposite: a system that already existed, with real users and a real story. Revenant imports the existing image instead, registers it as a Proxmox template, and ships a blueprint that drops it into a range. Ludus is an overlay on Proxmox, so the result is a first-class Proxmox object either way.

## Scenarios

Revenant starts from [Digital Corpora](https://digitalcorpora.org) scenarios: forensic datasets that are freely available for research and education, no prior authorization needed. Disks ship as EnCase E01, alongside memory dumps and PCAP where the scenario has them. Assets live in a public S3 bucket and pull with the AWS CLI:

```
aws s3 ls s3://digitalcorpora/corpora/scenarios/
aws s3 cp --recursive s3://digitalcorpora/corpora/scenarios/<scenario> ./<scenario>
```

The three-part bundle maps onto the pipeline: the disk gets resurrected, the memory feeds Volatility, and the pcap gets replayed.

## Repository layout

Revenant is packaged as a Ludus **source**: a catalog of blueprints, Packer templates, and Ansible roles and collections that `ludus source add` installs. Layout follows the [Ludus source template](https://gitlab.com/badsectorlabs/ludus-source-template).

```
revenant/                         Ludus source root
├── blueprints/                   one dir per scenario
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
│   ├── roles/                    revenant_credential_reset, revenant_first_boot, revenant_pcap_replay
│   └── collections/              vendored collections
├── LICENSE
└── README.md
```

Revenant has two halves. The CLI does the ingest, extract, resurrect, and replay work against a scenario. The source ships the Ludus artifacts that wrap the result. The wrinkle: a Ludus `templates/` entry is normally a Packer build, but a resurrected host is imported, so Revenant registers it as a Proxmox template with `qm template` and the range-config references it by name. Scenario assets (disk, memory, pcap) are pulled from Digital Corpora at ingest, not vendored into the repo.

## How it works

**1. Ingest.** Pull a scenario from Digital Corpora and convert its disk to a Proxmox-friendly image (qcow2 or raw, matching `proxmox_vm_storage_format`). Disk formats: E01/EWF, raw dd, VMDK, VHD/VHDX, qcow2. Memory and pcap are carried through for the later stages.

**2. Extract.** Produce a users-and-creds report, plus the facts Resurrect needs to boot the box right:

- Users and hashes from the on-disk registry hives (SAM/SYSTEM).
- Creds and sessions from memory via Volatility, when the scenario has a memory dump.
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

**4. Replay.** When the scenario ships pcaps, rewrite the capture to the deployed range and replay it onto the VLAN, so sensors and the resurrected host see the original traffic:

- `tcpprep` builds the client/server cache, `tcprewrite` remaps MACs and addresses to the range topology.
- `tcpreplay` pushes the packets onto the range bridge, preserving timing or at top speed.
- `tcpliveplay` does stateful replay against a live host when you want it to actually respond.

Then the Ludus half:

- Reset or inject the recovered creds so the accounts actually log in (`revenant_credential_reset`).
- Stage and replay the scenario pcaps (`revenant_pcap_replay`).
- Emit the blueprint: `blueprint.yml` plus a `range-config.yml` referencing the template, so `ludus blueprint apply revenant/<scenario>` then `ludus range deploy` stands it up.

Networking, VLANs, and access stay with Ludus.

## Built on

- [Plaso](https://github.com/log2timeline/plaso) (log2timeline + pinfo) for OS and system details
- [Volatility](https://github.com/volatilityfoundation/volatility3) for memory analysis
- Registry/hive parsing for on-disk users and creds
- [tcpreplay](https://tcpreplay.appneta.com/) (tcprewrite, tcpreplay, tcpliveplay) for pcap replay
- [Proxmox VE](https://pve.proxmox.com/pve-docs/chapter-qm.html) (`qm`, `qemu-img`) for import and templating
- Packer + Ansible for Ludus templates and provisioning
- [Ludus](https://docs.ludus.cloud/) for source packaging, blueprints, and deployment
- [Digital Corpora](https://digitalcorpora.org) for source scenarios, pulled with the AWS CLI

## Design notes

**Replay onto a sensor VLAN, not the host.** The default replay path pushes traffic onto the range VLAN, where a sensor VM (Zeek, Suricata, Security Onion, Elastic Agent) ingests it, so any pcap scenario's blueprint should carry that sensor host. Stateful replay straight at the resurrected host with `tcpliveplay` is a secondary path: the captured IPs won't match the deployed host, and replaying to a live target is finicky. Build the sensor path first.

**Drive the rewrite from the range config.** A Digital Corpora capture carries the original scenario's IPs and MACs, while Ludus hands each user an isolated 10.x range on their own bridge. So `revenant_pcap_replay` reads the deployed `range-config.yml` and builds the `tcprewrite` map from it, rather than hardcoding addresses per scenario. Keep that coupling between the range config and the rewrite map explicit, since it's the part most likely to rot if left implicit.

## Scope & use

Digital Corpora scenarios are freely available for research and education. Beyond those, Revenant is for authorized forensics, training, and range work on images you own or may analyze. Not for booting or cracking images you have no authorization for.
