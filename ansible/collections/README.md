# ansible/collections/

Ansible **collections** shipped by this source, vendored at the source root so
`ludus source add` installs them into the per-user collections path. As with
roles, this top-level path is the only one `ludus source add` reads.

Reference: <https://docs.ludus.cloud/docs/using-ludus/sources>

Each collection lives at `ansible/collections/<namespace>/<name>/` with its own
`galaxy.yml`. Cross-collection use must be declared in `galaxy.yml`
`dependencies` so the closure check can resolve it.

## Vendored / third-party content

A collection carried in from elsewhere keeps its upstream identity and records
provenance in `meta/upstream.yml` (`status: vendored|staged|promoted`, upstream
URL + pinned ref, licence, vendored-file hashes). `scripts/check-upstream.py`
walks these and fails on drift or an undeclared upstream.

## Pinning and stock Ludus

If a collection declared here (or in a blueprint's `requirements.yml`) is one
that **stock Ludus also ships**, its version must match the stock pin exactly —
`ludus source add` overwrites the shared per-user Galaxy tree, so a mismatch
silently replaces stock's copy for every user on the host. The only sanctioned
place to carry a different version is a blueprint's own `requirements.yml`. This
is enforced by `scripts/sync-ludus-stock-pins.py check`; the policy and the
stock pin data live in `ansible/meta/`.

*(No collections are vendored yet — this is the foundation scaffold.)*
