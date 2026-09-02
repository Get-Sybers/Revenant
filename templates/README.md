# templates/

Proxmox templates shared across blueprints.

**Revenant's templates are imported, not built.** A normal Ludus `templates/`
entry is a Packer build from a clean ISO (`.pkr.hcl` + `iso_url`/`iso_checksum`).
Revenant is the opposite: it takes a system that already existed — a forensic
disk image — lands it on a node, and registers it as a Proxmox template with
`qm`:

```
qm create <vmid> --name <scenario> --ostype <l26|winXX> \
  --scsihw virtio-scsi-single \
  --scsi0 <storage>:0,import-from=<path/to/disk.qcow2> \
  --boot order=scsi0 --agent enabled=1
qm template <vmid>
```

(OVF/OVA import with `qm importovf`; UEFI images add `--bios ovmf` + an EFI
disk; see the top-level `README.md` for the firmware, driver, and DC-restore
notes.) The blueprint's `range-config.yml` then references the template by name.

## Consequences for this repo

- There are **no `.pkr.hcl` files** here, so the Packer/ISO-compliance gate does
  not apply to Revenant and is not shipped (see `scripts/gates.yml`).
- Provenance for an **imported disk image** — where it came from, its checksum,
  the Digital Corpora scenario it belongs to — is Revenant-specific and is
  recorded per template descriptor. A disk-image provenance check (the analogue
  of the ISO-compliance gate) is planned once the ingest format is settled.

What lands in a `templates/<name>/` directory is the descriptor the CLI needs to
re-create the import deterministically (source scenario + expected checksum +
`qm` parameters), not the image bytes — those are pulled from Digital Corpora at
ingest.

*(No templates are committed yet — this is the foundation scaffold.)*
