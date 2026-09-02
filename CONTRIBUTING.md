# Contributing to Revenant

## Branch model

```
main  ←  integration  ←  feature branches
```

- **`main`** — released, stable. Protected; only updated by a PR from `integration`.
- **`integration`** — staging. Everything merges here first and is validated
  together before it reaches `main`. Updated by PRs from feature branches.
- **feature branches** — one per change, branched off `integration`. Named
  descriptively (e.g. `claude/foundation-ludus-source-scaffold`,
  `scenario/<name>`, `role/<name>`).

Never push directly to `main`. Never push directly to `integration` — it takes
PRs too.

## PR workflow

1. Branch off `integration`, make the change, run the gates (below).
2. Open a PR **into `integration`**. CI runs the gates; address review feedback
   (including automated review bots) until green.
3. Once merged and validated on `integration`, open a PR **`integration` →
   `main`** to release.

## Running the QA gates

The gates are plain Python checkers under `scripts/`, run from the repo root.
Run them all at once:

```bash
bash scripts/run-gates.sh
```

or individually:

```bash
python3 scripts/check-upstream.py                 # provenance of vendored content
python3 scripts/sync-ludus-stock-pins.py check    # stock-pin drift
python3 scripts/check-module-availability.py      # blueprint module availability
```

**Dependencies:** Python 3.11+ and `pyyaml` (`pip install pyyaml`). The
module-availability gate additionally needs `ansible` on `PATH` once it activates
(it is off until the first blueprint lands — see `scripts/gates.yml`).

The same `scripts/run-gates.sh` runs in CI on every PR to `integration`/`main`
(`.github/workflows/gates.yml`). What each gate covers, what is deferred, and
what is deliberately dropped for Revenant's imported-image model is documented in
[`scripts/gates.yml`](scripts/gates.yml).

## Keeping the stock pins current

Revenant pins its relationship to stock Ludus's own Galaxy collections so a
`ludus source add` never silently overwrites them. When a new Ludus release
appears, re-sync and commit the result in review:

```bash
python3 scripts/sync-ludus-stock-pins.py latest-tag        # what's newest upstream
python3 scripts/sync-ludus-stock-pins.py sync --ref <tag>  # regenerate the pin data
```

The policy (why, and the one sanctioned exception) is in
[`ansible/meta/ludus-stock-pins.yml`](ansible/meta/ludus-stock-pins.yml).

## Standards

New Ansible, CLI, and scenario content is held to the standards in
[`docs/standards/`](docs/standards/). Start with
[`docs/standards/ansible/robust-ansible.md`](docs/standards/ansible/robust-ansible.md).

## Never commit scenario assets

Disk images, memory dumps, and packet captures are pulled from Digital Corpora at
ingest time and are **never** committed — this repo is public, and the assets are
large and/or sensitive. `.gitignore` blocks the common formats; a blueprint
references the resurrected template by name and the bytes are re-pulled. Do not
commit credentials, recovered hashes, or any host-identifying data extracted from
a scenario.
