# Revenant — remaining work

The Ludus-source **foundation** is in place. This tracks what's left to make
Revenant actually resurrect a scenario and deploy it end-to-end. Grouped by area;
roughly in dependency order within each group.

## Done — foundation

- Repository scaffold (`blueprints/`, `templates/`, `ansible/roles/`,
  `ansible/collections/`, `docs/`) with documented placeholder READMEs.
- `source.yml`, `LICENSE` (AGPL-3.0), `.gitignore` (blocks forensic scenario assets).
- QA gates: `check-upstream.py` (provenance) + `sync-ludus-stock-pins.py` (drift,
  synced to Ludus 2.3.1) active, with `run-gates.sh` + CI (`.github/workflows/gates.yml`).
- `docs/standards/` (robust-ansible) + `CONTRIBUTING.md` (branch model, PR workflow).

## 1. CLI — the ingest → extract → resurrect → replay engine

The novel engineering. First decide where it lives (a `revenant/` Python package
or `cli/`), its entry points, and its test layout.

- [ ] **Ingest** — convert a source disk (E01/EWF, raw dd, VMDK, VHD/VHDX, OVA/OVF,
      qcow2) to a Proxmox-friendly image matching `proxmox_vm_storage_format`; carry
      the memory dump and pcap through to the later stages.
- [x] **Extract (passwords)** — `revenant extract` sub-command uses
      [VMkatz](https://github.com/nikaiw/VMkatz) (v1.4.1, pinned + SHA-256
      verified) to pull NT/LM hashes, Kerberos tickets, WDigest plaintext,
      cached domain creds, LSA secrets, DPAPI master keys, and NTDS.dit hashes
      directly from VM memory snapshots (`.vmsn`, `.vmem`, `.sav`, QEMU savevm)
      and virtual disks (`.vmdk`, `.qcow2`, `.vhd`, `.vhdx`, `.vdi`).  Output
      in JSON (default) or pwdump format.  Implemented in
      `revenant/extract/vmkatz.py`; entry point wired in `pyproject.toml`.
- [ ] **Extract (OS metadata)** — OS + hostname + firmware via Plaso
      (log2timeline → pinfo), mapping OS → `ostype` and firmware →
      SeaBIOS/OVMF. Emit a complete users-and-creds + host-metadata report.
- [ ] **Resurrect** — `qm create` / `qm importovf` + `qm template`; handle ostype,
      firmware (UEFI EFI disk; Win11 `q35` + TPM), virtio-vs-SATA first boot / driver
      injection, and a fresh `--vmgenid` for DC clean-restore.
- [ ] **Replay** — `tcpprep` → `tcprewrite` (remap to the deployed range topology,
      map built from `range-config.yml`, not hardcoded) → `tcpreplay` / `tcpliveplay`.
- [ ] **Provenance descriptor** — the CLI emits, per imported template, a record of
      source scenario + expected checksum + `qm` parameters (feeds the gate in §4).
- [ ] Packaging: entry points, unit tests, lint/format, and CI wiring for the CLI.

## 2. DFIR roles (`ansible/roles/`)

Each role: `meta/main.yml` (galaxy_info + `min_ansible_version`) +
`meta/argument_specs.yml` + `README.md` that **states what it changes or exposes on
the resurrected host** + a Molecule scenario. (See §5 for the standard.)

- [ ] `revenant_first_boot` — first-boot fixups (disk controller, guest agent,
      network) so an imported image boots and is reachable in the range.
- [ ] `revenant_credential_reset` — reset or inject the recovered accounts so they
      log in.
- [ ] `revenant_pcap_replay` — stage and replay the scenario captures onto the range
      VLAN, rewritten to the deployed topology.

## 3. First scenario blueprint (`blueprints/<scenario>/`)

- [ ] Pick a Digital Corpora scenario (disk + memory + pcap).
- [ ] `blueprint.yml`, `range-config.yml` (references the resurrected template by
      name; include a **sensor VLAN host** — Zeek / Suricata / Security Onion /
      Elastic — as the primary pcap-replay target), `requirements.yml`,
      `subscription_refs.yml`, `README.md`.

## 4. QA gates — activate / adapt as content lands

Full inventory and rationale in [`scripts/gates.yml`](scripts/gates.yml).

- [ ] **Disk-image provenance gate (NEW)** — Revenant's analogue of the dropped
      `check-iso-compliance.py`: verify each imported template records its source
      scenario, checksum, and `qm` parameters. Design once the ingest descriptor
      format (§1) is settled.
- [ ] `check-module-availability.py` — flip `applicable: true` when the first
      blueprint `requirements.yml` lands; add `ansible` to the CI dependencies.
- [ ] `check-closure.py` — adapt the FQCN namespace + fixed blueprint path off the
      FGNW defaults, then ship + run it once a collection exists.
- [ ] `check-one-action.py` — set `one_action.scope_root` / `scope_globs`; run with
      the roles.
- [ ] `check-range-infra-boundary.py` — set `boundary.scan_trees`; run if Revenant
      ships range surfaces alongside a separate infra tier.
- [ ] `check-density.py` — adapt the namespace; add (informational) with the roles.

## 5. Standards docs owed (`docs/standards/`)

- [ ] `one-action-per-task.md` — port and rewrite the examples to Revenant (lands
      with the one-action gate).
- [ ] **DFIR role standard** — a short doc formalizing "state what the role modifies
      or exposes on the resurrected host" (the Revenant analogue of the range
      standard's "what it deliberately weakens").

## 6. Decisions / housekeeping

- [ ] **License** — `AGPL-3.0-only` is set in `source.yml` + `LICENSE` as the
      proposal; confirm, or switch to MIT/Apache-2.0.
- [ ] **Backport** the `check-upstream.py` / `check-module-availability.py` hardening
      (from PR #1) to the FGNW and bits-n-bobs copies — the same bugs exist there.
- [ ] (optional) Decide the `Co-Authored-By` model-name policy for commits.
