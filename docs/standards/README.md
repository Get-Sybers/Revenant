# Revenant engineering standards

The bar Revenant's Ansible, CLI, and scenario content are held to. These are
adapted from the Get-Sybers Ludus-source standards, scoped to Revenant's model
(imported disk images + a Python CLI + DFIR roles), and kept public-safe (no
internal hosts, credentials, or operational specifics).

## Active now

| Standard | What it covers |
|---|---|
| [`ansible/robust-ansible.md`](ansible/robust-ansible.md) | Role & collection robustness review: separation of logic and action, input validation via `meta/argument_specs.yml`, idempotence, check-mode, failure behaviour, structure, testing & docs. |

Which of these are machine-enforced, and how, is in
[`../../scripts/gates.yml`](../../scripts/gates.yml). The provenance and
stock-pin gates run today; the rest activate as content lands (below).

## Lands with the first roles / collections / blueprints

These are deferred deliberately — the tooling they describe is coupled to
content Revenant does not have yet, and porting it empty would either misfire or
sit permanently disabled:

- **One task, one action** (`one-action-per-task.md` + the `check-one-action.py`
  gate) — the rule that a task does one action and contains no logic. Lands with
  the first Ansible roles, with examples written to Revenant's roles rather than
  another source's.
- **DFIR role standard** — the Revenant analogue of the range standard's "state
  what the role deliberately weakens": every role that resets credentials or
  alters the security posture of a resurrected host must state, in its README,
  **what it changes or exposes on that host**. Resurrecting a real system and
  logging into its recovered accounts is the point; making that explicit per role
  is the discipline.
- **Imported-disk-image provenance** — the analogue of the Packer/ISO-compliance
  gate that Revenant drops (there are no `.pkr.hcl` builds here). Each imported
  template records its source Digital Corpora scenario, expected checksum, and
  `qm` import parameters so a resurrection is reproducible and its origin is
  verifiable. The gate lands once the ingest descriptor format is settled.

## Namespace / path adaptations still owed

Some shared checkers are hardwired to another source's namespace and paths and
need adapting before they can run here: `check-closure.py` (FQCN namespace +
blueprint path), `check-range-infra-boundary.py` (`scan_trees`), and
`check-one-action.py` (`scope_root`/`scope_globs`). See the inventory in
`scripts/gates.yml`.
