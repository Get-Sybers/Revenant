# blueprints/

One directory per scenario. A blueprint wraps a resurrected image (and its
replayed traffic) as a Ludus range you can `ludus blueprint apply` then
`ludus range deploy`.

Reference: <https://docs.ludus.cloud/docs/using-ludus/sources>

```
blueprints/<scenario>/
├── blueprint.yml          # display metadata: name, description, what it deploys
├── range-config.yml       # the Ludus range, referencing the resurrected template by name
├── requirements.yml       # role + collection dependencies (galaxy + vendored)
├── subscription_refs.yml  # pins to shared source content this scenario depends on
├── roles/                 # scenario-specific roles, if any (NOT read by ludus source add —
│                          #   see below; a role resolved by name must live at ../../ansible/roles/)
├── templates/             # scenario-specific template descriptors, if any
└── README.md
```

## What `ludus source add` reads

`ludus source add` discovers blueprints here, but it installs **roles and
collections only from the source-root `ansible/` tree** — never from
`blueprints/<scenario>/roles/`. So a role a `range-config.yml` resolves by name
has to be vendored at `../../ansible/roles/`. A `blueprints/<scenario>/roles/`
directory is only ever reached by a playbook run with that directory on its
role search path, and even then the source-root copy is what a `ludus range
deploy` resolves. Keep one copy, at the source root.

## Scenario assets are pulled, not vendored

The disk image, memory dump, and pcaps come from
[Digital Corpora](https://digitalcorpora.org) at ingest time — they are **not**
committed to this repo. A blueprint references the resurrected Proxmox template
by name; the CLI half produces that template. See the top-level `README.md`.

*(No scenarios are committed yet — this is the foundation scaffold.)*
