# ansible/roles/

Revenant's own Ansible task-roles, vendored at the **source root** so
`ludus source add` installs them into the per-user roles path
(`/opt/ludus/users/<user>/.ansible/roles`). This is the **only** roles path
`ludus source add` reads — it does **not** descend into
`blueprints/<scenario>/roles/`. A role a range-config or campaign playbook
resolves by name therefore has to live here, not under a blueprint.

Reference: <https://docs.ludus.cloud/docs/using-ludus/roles/>

## Roles planned for Revenant

| Role | What it does |
|---|---|
| `revenant_first_boot` | first-boot fixups so a resurrected image boots and is reachable in the range (disk controller, agent, network) |
| `revenant_credential_reset` | reset or inject the recovered accounts so they actually log in on the resurrected host |
| `revenant_pcap_replay` | stage the scenario captures and replay them onto the range VLAN, rewritten to the deployed topology |

*(None are committed yet — this is the foundation scaffold. Each lands with its
own role increment.)*

## Standard every role here follows

- `meta/main.yml` (galaxy_info: author, description, license, `min_ansible_version`, platforms) and `meta/argument_specs.yml` (runtime-validated spec for every variable).
- `README.md` stating what the role does and, for anything that resets creds or alters host security posture, **what it changes or exposes on the resurrected host** — the DFIR analogue of the range standard's "what it deliberately weakens".
- One action per task, idempotent, tagged. See `docs/standards/`.

## Third-party / vendored roles

A role authored elsewhere keeps its **upstream name** (never renamed into a
Revenant namespace) and carries `meta/upstream.yml` recording provenance
(`status: vendored|staged|promoted`, upstream URL + pinned ref, licence, and
hashes of any vendored files). `scripts/check-upstream.py` verifies it. Vendor
it **here**, at the source root — never only inside a blueprint, or
`ludus source add` will not install it.
