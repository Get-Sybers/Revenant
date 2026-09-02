#!/usr/bin/env python3
"""Sync the stock-Ludus pin data, and gate the repo's own release on drift.

Suggested home: scripts/sync-ludus-stock-pins.py

WHY
    Ludus installs its own collections/roles per-user from the requirements
    file baked into the server binary. A source declaring the SAME collection
    at a DIFFERENT version overwrites the stock pin at `ludus source add`
    time -- and `ludus ansible collection rm` later deletes the collection
    DIRECTORY outright, with no version awareness and no refcount. Removing
    "our" copy therefore takes Ludus's copy with it, and stock deploys fail
    on missing collections until they are reinstalled.

    Observed 2026-08-03: a source cleanse left the box with only
    ansible.posix, ansible.utils and vladgh.samba. Five collections stock
    Ludus requires were gone.

POLICY (operator, 2026-08-03)
    There must be NO drift between what this repo pins and what stock Ludus
    pins -- with exactly one sanctioned exception: a BLUEPRINT's own
    requirements.yml may declare a different version, because that is the
    mechanism by which a blueprint brings a newer collection than stock
    ships. Nothing else may differ. `check` enforces this as two rules:

      1. A requirements.yml (or equivalent) ANYWHERE ELSE in the repo that
         pins a name stock Ludus also pins, at a different version, is a
         HARD FAILURE. Zero tolerance -- there is no legitimate reason for
         this to happen outside a blueprint.
      2. A blueprint's requirements.yml pinning a different version is
         ALLOWED and does not fail the build -- but it is always printed as
         an OVERRIDE, because it has a real, permanent consequence: the
         differing version silently overwrites the shared per-user Galaxy
         install location `ludus source add` uses, and stock deploys break
         until the pins are restored. That consequence must be visible on
         every run, not just written down once in a doc nobody re-reads.

    This repo's own releases are bound to the Ludus version recorded in
    ansible/meta/ludus-stock-pins.generated.yml's `ludus_ref`. See `sync`.

UPSTREAM
    gitlab.com/badsectorlabs/ludus, file ludus-server/ansible/requirements.yml
    It reaches the server via `//go:embed all:ansible` (ludus-server/main.go)
    and is extracted to /opt/ludus/ansible/requirements.yml on install/update.
    Tags are UNPREFIXED: 2.3.0, 2.3.1 -- not v2.3.0.

USAGE
    # regenerate the pin data for the Ludus version you run
    ./scripts/sync-ludus-stock-pins.py sync --ref 2.3.1

    # ...or from a Ludus host, without network access
    ./scripts/sync-ludus-stock-pins.py sync --from-file /opt/ludus/ansible/requirements.yml

    # CI gate: non-zero exit only on drift OUTSIDE a blueprint
    ./scripts/sync-ludus-stock-pins.py check

    # HOST-ONLY, cannot run from CI: put the stock pins back after a blueprint
    # override has overwritten them (mirrors ludus-server's own restore exactly)
    ./scripts/sync-ludus-stock-pins.py restore --all
    ./scripts/sync-ludus-stock-pins.py restore --user range-admin

    # what the pipeline compares to decide whether pins are stale
    ./scripts/sync-ludus-stock-pins.py latest-tag     # newest tag upstream has
    ./scripts/sync-ludus-stock-pins.py current-ref    # ref this repo is synced to

FILES
    ansible/meta/ludus-stock-pins.generated.yml   machine-owned, never hand-edit
    ansible/meta/ludus-stock-pins.yml              hand-owned: policy prose
"""

from __future__ import annotations

import argparse
import re
import shlex
import subprocess
import sys
import urllib.request
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("PyYAML required: pip install pyyaml")

RAW_URL = ("https://gitlab.com/badsectorlabs/ludus/-/raw/{ref}"
           "/ludus-server/ansible/requirements.yml")
TAGS_API = "https://gitlab.com/api/v4/projects/badsectorlabs%2Fludus/repository/tags"
GALAXY_VERSIONS = ("https://galaxy.ansible.com/api/v3/plugin/ansible/content/published"
                   "/collections/index/{ns}/{name}/versions/?limit=100")

REPO_ROOT = Path(__file__).resolve().parents[1]
GENERATED = REPO_ROOT / "ansible/meta/ludus-stock-pins.generated.yml"

# Per-Ludus-version stock pins. The pins ship INSIDE the ludus-server binary and
# change per release, so "the stock pins" is not one fact — it is one fact PER
# VERSION. Keeping a file per release means:
#   * the ceiling can be resolved against the version actually running, and
#   * rolling the server back does not silently leave the repo asserting the
#     ceiling of a version that is no longer installed.
# Populated by `sync --ref <tag>` (one release) or `sync-all-releases`.
PINS_DIR = REPO_ROOT / "ansible/meta/ludus-stock-pins"


def pins_path(ref: str) -> Path:
    return PINS_DIR / f"{ref}.yml"


def load_pins(ref: str) -> dict | None:
    """Stock pins recorded for a specific Ludus release, or None if not captured."""
    f = pins_path(ref)
    if not f.is_file():
        return None
    return yaml.safe_load(f.read_text()) or {}


def captured_refs() -> list:
    if not PINS_DIR.is_dir():
        return []
    refs = [p.stem for p in PINS_DIR.glob("*.yml")]
    refs.sort(key=lambda v: tuple(int(x) for x in v.split(".")) if
              re.fullmatch(r"[0-9]+(\.[0-9]+)*", v) else (0,))
    return refs


def running_server_ref() -> str | None:
    """The Ludus SERVER version actually running here, or None off-host.

    NOT `ludus-server version` -- that is not a version subcommand; the binary
    ignores the argument and tries to start a second server. The CLI reports it.
    """
    import subprocess
    try:
        out = subprocess.run(["ludus", "version"], capture_output=True,
                             text=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"Ludus Server ([0-9]+\.[0-9]+\.[0-9]+)", out)
    return m.group(1) if m else None
POLICY = REPO_ROOT / "ansible/meta/ludus-stock-pins.yml"

# Directories under the repo root that are never a source of Galaxy pins to
# gate -- vendored dev tooling, git internals. Everything else is walked, so a
# new requirements.yml anywhere else is caught automatically without needing
# to be added to a list here (unlike the old per-blueprint allowlist this
# replaces: a NEW file outside a blueprint should be noticed by default, not
# opted into checking).
_SKIP_DIRS = {".git", ".dev", ".github"}


def _fetch(ref: str) -> str:
    url = RAW_URL.format(ref=ref)
    try:
        with urllib.request.urlopen(url, timeout=60) as r:
            if r.status != 200:
                sys.exit(f"upstream returned HTTP {r.status} for {url}")
            return r.read().decode()
    except Exception as exc:
        sys.exit(f"could not fetch {url}: {exc}\n"
                 f"Ludus tags are unprefixed -- use 2.3.0, not v2.3.0.")


def latest_upstream_tag() -> str:
    """The most recent Ludus tag, ordered by GitLab (newest first)."""
    try:
        with urllib.request.urlopen(TAGS_API + "?per_page=1", timeout=60) as r:
            import json
            tags = json.loads(r.read().decode())
    except Exception as exc:
        sys.exit(f"could not list tags from {TAGS_API}: {exc}")
    if not tags:
        sys.exit("upstream returned no tags")
    return tags[0]["name"]


def cmd_latest_tag(args: argparse.Namespace) -> int:
    print(latest_upstream_tag())
    return 0


def cmd_current_ref(args: argparse.Namespace) -> int:
    if not GENERATED.exists():
        sys.exit(f"{GENERATED} missing -- run `sync` first.")
    gen = yaml.safe_load(GENERATED.read_text())
    ref = (gen.get("ludus_stock_pins_meta") or {}).get("ludus_ref")
    if not ref:
        sys.exit(f"{GENERATED} has no ludus_ref recorded (was it synced with "
                 f"--from-file, which doesn't know a ref? re-sync with --ref).")
    print(ref)
    return 0


def _parse_strict(text: str) -> tuple[dict, dict]:
    """Collections/roles from a requirements file. Exits loudly if unparseable --
    used only where the caller named one specific, known-shaped file."""
    doc = yaml.safe_load(text) or {}
    cols, roles = {}, {}
    for entry in doc.get("collections") or []:
        if isinstance(entry, dict) and "name" in entry:
            cols[entry["name"]] = str(entry.get("version", ""))
    for entry in doc.get("roles") or []:
        if isinstance(entry, dict) and "name" in entry:
            roles[entry["name"]] = str(entry.get("version", ""))
    if not cols and not roles:
        sys.exit("parsed no collections or roles -- wrong file? Note the CI "
                 "fixtures under ludus-server/ci/fixtures/ are NOT stock pins.")
    return cols, roles


def _parse_lenient(text: str) -> tuple[dict, dict] | None:
    """Same, but returns None instead of exiting for a file that just isn't
    Galaxy-requirements-shaped (e.g. a platform checklist with the same
    filename convention). Used by `check`, which discovers files by name and
    cannot assume every hit is what it looks like."""
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        return None
    if not isinstance(doc, dict):
        return None
    cols, roles = {}, {}
    for entry in doc.get("collections") or []:
        if isinstance(entry, dict) and "name" in entry:
            cols[entry["name"]] = str(entry.get("version", ""))
    for entry in doc.get("roles") or []:
        if isinstance(entry, dict) and "name" in entry:
            roles[entry["name"]] = str(entry.get("version", ""))
    return (cols, roles) if (cols or roles) else None


def _discover_requirements_files() -> list[Path]:
    out = []
    for path in REPO_ROOT.rglob("*requirements*.yml"):
        rel = path.relative_to(REPO_ROOT)
        if any(part in _SKIP_DIRS for part in rel.parts):
            continue
        out.append(path)
    return sorted(out)


def cmd_sync(args: argparse.Namespace) -> int:
    if args.from_file:
        try:
            text = Path(args.from_file).read_text()
        except OSError as exc:
            sys.exit(f"cannot read {args.from_file}: {exc}")
        provenance = {"source": str(args.from_file), "ref": None}
    elif args.ref:
        text = _fetch(args.ref)
        provenance = {"source": RAW_URL.format(ref=args.ref), "ref": args.ref}
    else:
        sys.exit("sync: nothing pinned yet and no --ref given -- pass "
                 "--ref <tag> (or --from-file <path>).")

    cols, roles = _parse_strict(text)
    payload = {
        "ludus_stock_pins_meta": {
            "generated_by": "scripts/sync-ludus-stock-pins.py",
            "do_not_hand_edit": True,
            "ludus_ref": provenance["ref"],
            "upstream": provenance["source"],
            "note": ("Pins ship inside the ludus-server binary and change per "
                     "release. Re-run sync with --ref matching the server "
                     "version you actually run (`ludus version`). This repo's "
                     "own releases are bound to this ludus_ref -- see the "
                     "policy header in this script."),
        },
        "ludus_stock_collections": cols,
        "ludus_stock_roles": roles,
    }

    body = ("---\n# GENERATED FILE -- do not hand-edit.\n"
            "# Regenerate: scripts/sync-ludus-stock-pins.py sync --ref <ludus-tag>\n"
            + yaml.safe_dump(payload, sort_keys=False, default_flow_style=False))

    # Per-version file is the source of truth. `ludus-stock-pins.generated.yml`
    # is kept in step as the "pins for the version this repo currently targets"
    # pointer, so existing readers keep working.
    ref = provenance["ref"]
    if ref:
        PINS_DIR.mkdir(parents=True, exist_ok=True)
        pins_path(ref).write_text(body)
        print(f"wrote {pins_path(ref).relative_to(REPO_ROOT)} "
              f"({len(cols)} collections, {len(roles)} roles)")

    GENERATED.parent.mkdir(parents=True, exist_ok=True)
    GENERATED.write_text(body)
    print(f"wrote {GENERATED.relative_to(REPO_ROOT)} "
          f"({len(cols)} collections, {len(roles)} roles, ref={ref})")
    return 0


def cmd_sync_all(args: argparse.Namespace) -> int:
    """Capture the stock pins of EVERY release (or every release >= --since).

    One file per Ludus version, because the pins are a per-release fact. Without
    this, rolling the server back leaves the repo asserting a ceiling that
    belongs to a version no longer installed.
    """
    import json
    import urllib.request

    url = ("https://gitlab.com/api/v4/projects/badsectorlabs%2Fludus/"
           "releases?per_page=100")
    try:
        with urllib.request.urlopen(url, timeout=60) as r:
            releases = json.load(r)
    except Exception as exc:
        sys.exit(f"could not list releases: {exc}")

    def key(v):
        try:
            return tuple(int(x) for x in v.split("."))
        except ValueError:
            return None

    since = key(args.since) if args.since else None
    tags = [r["tag_name"] for r in releases if key(r["tag_name"])]
    tags = [t for t in tags if since is None or key(t) >= since]
    tags.sort(key=key)

    PINS_DIR.mkdir(parents=True, exist_ok=True)
    wrote, skipped, failed = 0, 0, []
    for tag in tags:
        if pins_path(tag).is_file() and not args.force:
            skipped += 1
            continue
        try:
            text = _fetch(tag)
            cols, roles = _parse_strict(text)
        except SystemExit:
            failed.append(tag)
            continue
        payload = {
            "ludus_stock_pins_meta": {
                "generated_by": "scripts/sync-ludus-stock-pins.py",
                "do_not_hand_edit": True,
                "ludus_ref": tag,
                "upstream": RAW_URL.format(ref=tag),
            },
            "ludus_stock_collections": cols,
            "ludus_stock_roles": roles,
        }
        pins_path(tag).write_text(
            "---\n# GENERATED FILE -- do not hand-edit.\n"
            + yaml.safe_dump(payload, sort_keys=False, default_flow_style=False))
        wrote += 1
    print(f"captured {wrote} release(s), {skipped} already present, "
          f"{len(failed)} without a fetchable requirements.yml"
          + (f": {', '.join(failed)}" if failed else ""))
    return 0


def published_versions(fqcn: str) -> list | None:
    """Versions Galaxy publishes for a collection.

    Returns None when the ANSWER IS UNKNOWN — no network, an HTTP error, an
    unparseable body. That is deliberately distinct from an empty list, which
    would mean "asked, and there are none". Conflating the two is how a check
    that could not run reports a pass.
    """
    ns, _, name = fqcn.partition(".")
    if not ns or not name:
        return None
    try:
        with urllib.request.urlopen(GALAXY_VERSIONS.format(ns=ns, name=name), timeout=30) as r:
            if r.status != 200:
                return None
            import json
            return [v["version"] for v in json.loads(r.read().decode()).get("data", [])]
    except Exception:
        return None


def _ver_tuple(v: str):
    return (tuple(int(x) for x in v.split("."))
            if re.fullmatch(r"\d+(\.\d+)*", v or "") else None)


def _spec_satisfiable(spec: str, available: list) -> bool:
    """Does at least one PUBLISHED version satisfy `spec`?

    Requirements now carry RANGES (">=5.0.1,<6.0.0"), not only exact pins,
    because the upper bound is where the stock ceiling is expressed and Galaxy
    is what picks the highest satisfying version. An exact-string membership
    test reads a range as an unpublished version and fails every ranged
    requirement -- so the question has to be "is anything published inside it",
    which is the property that actually matters: an unsatisfiable requirement is
    what makes `ludus source add` abort with NO collections installed.
    """
    spec = (spec or "").strip()
    if not spec or spec == "*":
        return bool(available)
    if not re.search(r"[<>=!,]", spec):          # a bare exact version
        return spec in available
    for cand in available:
        c = _ver_tuple(cand)
        if c is None:
            continue
        ok = True
        for part in spec.split(","):
            m = re.match(r"\s*(>=|<=|==|!=|>|<)?\s*([0-9]+(?:\.[0-9]+)*)\s*$", part)
            if not m:
                ok = False
                break
            op = m.group(1) or "=="
            want = _ver_tuple(m.group(2))
            want = want + (0,) * (3 - len(want))
            cc = c + (0,) * (3 - len(c))
            cmp = (cc > want) - (cc < want)
            if not {">=": cmp >= 0, "<=": cmp <= 0, "==": cmp == 0,
                    "!=": cmp != 0, ">": cmp > 0, "<": cmp < 0}[op]:
                ok = False
                break
        if ok:
            return True
    return False


def verify_pins_published(files: list) -> tuple[list, list]:
    """Check every pinned version actually exists. -> (bad, unchecked)

    WHY THIS EXISTS: the drift check compares blueprint pins against STOCK
    Ludus pins, so it only ever looks at names stock also pins. A collection
    stock does not ship — ansible.mysql — was pinned to 5.0.2, a version that
    was never published, and the drift check reported "no drift" while
    `ludus source add` aborted at dependency resolution and installed NO
    collections at all (main, until #111). Disagreeing with stock and existing
    are different properties; this checks the second.
    """
    bad, unchecked, seen = [], [], {}
    for req in files:
        parsed = _parse_lenient(req.read_text())
        if parsed is None:
            continue
        cols, roles = parsed
        for name, ver in cols.items():
            if not ver:
                continue
            if name not in seen:
                seen[name] = published_versions(name)
            avail = seen[name]
            if avail is None:
                unchecked.append((req, name, ver))
            elif not _spec_satisfiable(str(ver), avail):
                bad.append((req, name, ver, avail))
        # Roles are skipped: a role pin is a git tag or an scm ref, not a
        # Galaxy collection version, and the versions API does not describe it.
    return bad, unchecked


def cmd_check(args: argparse.Namespace) -> int:
    if not GENERATED.exists():
        # FAIL CLOSED, EXPLICITLY (board G-7, 2026-08-04). "Cannot check" is a
        # distinct outcome from both "checked, clean" (exit 0) and "checked,
        # drift" (exit 1), so it gets its own code. The previous shape here was
        # sys.exit(str) — non-zero only as an implicit side effect of passing a
        # string — and a deployed copy of this script was observed printing
        # this message and exiting 0. An implicit mechanism is exactly what
        # such a regression hides behind; the code and message are now
        # explicit, and the message states that nothing was compared.
        print(f"CANNOT CHECK: {GENERATED} is missing -- run `sync` first.\n"
              f"No pins were compared. This is a failure, not a pass.",
              file=sys.stderr)
        return 2
    gen = yaml.safe_load(GENERATED.read_text())
    stock = gen.get("ludus_stock_collections") or {}
    stock_roles = gen.get("ludus_stock_roles") or {}
    all_stock = {**stock, **stock_roles}

    all_files = _discover_requirements_files()
    overrides, violations, skipped = [], [], []
    for req in all_files:
        rel = req.relative_to(REPO_ROOT)
        is_blueprint = rel.parts[0] == "blueprints"
        parsed = _parse_lenient(req.read_text())
        if parsed is None:
            skipped.append(rel)
            continue
        cols, roles = parsed
        for name, ver in {**cols, **roles}.items():
            pin = all_stock.get(name)
            if pin is None or ver == pin:
                continue
            (overrides if is_blueprint else violations).append((rel, name, ver, pin))

    # Rows, not files -- one file can contribute several override/violation
    # rows, so file-level counts are taken from the distinct paths seen above.
    override_files = {rel for rel, *_ in overrides}
    violation_files = {rel for rel, *_ in violations}
    clean_files = len(all_files) - len(skipped) - len(override_files) - len(violation_files)

    if skipped:
        print(f"scanned {len(skipped)} requirements-named file(s) with no "
              f"collections:/roles: keys (not Galaxy pins, ignored):")
        for rel in skipped:
            print(f"  - {rel}")
        print()

    if overrides:
        print(f"--- {len(overrides)} blueprint override(s) in effect "
              f"(sanctioned by policy, not a failure) ---")
        for rel, name, ver, pin in overrides:
            print(f"  {rel}")
            print(f"    {name}: blueprint pins {ver}, stock pins {pin}")
        print()
        print("  CONSEQUENCE: on `ludus source add`, each of these overwrites the")
        print("  shared per-user Galaxy install stock Ludus relies on. Restore after")
        print("  any cleanse -- this is a repo script, run it on the Ludus host:")
        print("    scripts/sync-ludus-stock-pins.py restore --all")
        print()

    # ── Do the pinned versions actually EXIST? ───────────────────────────────
    # Network-dependent, so an outage must never fail a PR: an unreachable
    # Galaxy yields "unchecked" and is reported, not failed. Only an
    # authoritative "this version is not published" is fatal. Skip entirely
    # with --offline for a hermetic run.
    pub_bad, pub_unchecked = ([], [])
    if not args.offline:
        pub_bad, pub_unchecked = verify_pins_published(all_files)
        if pub_unchecked:
            print(f"NOT CHECKED — could not reach Galaxy for "
                  f"{len(pub_unchecked)} pin(s); existence unverified, not verified-good:")
            for req, name, ver in pub_unchecked:
                print(f"  {req.relative_to(REPO_ROOT)}: {name} {ver}")
            print()
        if pub_bad:
            print(f"UNPUBLISHED — {len(pub_bad)} pinned version(s) do not exist on Galaxy.\n")
            for req, name, ver, avail in pub_bad:
                print(f"  {req.relative_to(REPO_ROOT)}")
                print(f"    {name}: pinned {ver}, published: {', '.join(avail[:6]) or '(none)'}")
            print("\nGalaxy resolves a requirements file as ONE dependency map, so a single")
            print("unsatisfiable pin means NO collection in that file installs — `ludus source")
            print("add` aborts and leaves the source `partial`.")
            return 1

    if not violations:
        print(f"OK: no drift outside a blueprint "
              f"({len(override_files)} file(s) carrying a sanctioned override, "
              f"{clean_files} file(s) clean, {len(skipped)} skipped).")
        return 0

    print(f"DRIFT -- {len(violations)} pin(s) outside a blueprint differ from stock "
          f"Ludus. This is not permitted; only a blueprint's own requirements.yml "
          f"may differ.\n")
    for rel, name, ver, pin in violations:
        print(f"  {rel}")
        print(f"    {name}: pins {ver}, stock pins {pin}")
    print("\nFix one of two ways:")
    print("  1. Match the stock version.")
    print("  2. Move the declaration into the blueprint that actually needs it --")
    print("     that is the one place a differing version is sanctioned.")
    return 1


def _ludus_root(args: argparse.Namespace) -> Path:
    root = Path(args.ludus_root)
    req = root / "ansible/requirements.yml"
    if not req.exists():
        sys.exit(f"{req} does not exist -- this command is HOST-ONLY: it must "
                 f"run on a Ludus install, not from a repo checkout or CI. "
                 f"Pass --ludus-root if this host's install path differs.")
    return root


def _restore_one(root: Path, user: str, dry_run: bool) -> int:
    """Mirrors ludus-server/dependency_updates.go's updateAnsibleRoles() exactly:
    root runs the galaxy install directly; every other user runs it via
    `su ludus -c '...'` with ANSIBLE_HOME set as a shell prefix inside that
    invocation (not in this process's environment) -- matching the Go code's
    own command construction, which is the documented, load-bearing shape."""
    ansible_home = root / "users" / user / ".ansible"
    req = root / "ansible/requirements.yml"
    inner = (f"ANSIBLE_HOME={shlex.quote(str(ansible_home))} "
             f"ansible-galaxy install -r {shlex.quote(str(req))}")
    argv = ["su", "ludus", "-c", inner] if user != "root" else ["bash", "-c", inner]

    # argv is what actually runs (subprocess.run(argv), no shell), but for a
    # human reading dry-run output, ' '.join would print the -c argument as if
    # it were several separate words rather than one string. shlex.join quotes
    # it back into something both correct AND paste-safe into a real shell.
    print(f"[{user}] {shlex.join(argv)}")
    if dry_run:
        return 0
    result = subprocess.run(argv)
    return result.returncode


def cmd_restore(args: argparse.Namespace) -> int:
    root = _ludus_root(args)

    if args.all:
        users_dir = root / "users"
        targets = sorted(p.name for p in users_dir.iterdir()
                         if p.is_dir() and p.name != "root") if users_dir.exists() else []
        targets.append("root")
    else:
        if args.user != "root" and not (root / "users" / args.user).is_dir():
            sys.exit(f"{root}/users/{args.user} does not exist -- "
                     "--user must name an existing Ludus OS user directory.")
        targets = [args.user]

    rc = 0
    for user in targets:
        rc = _restore_one(root, user, args.dry_run) or rc
    if rc == 0:
        print("done." if not args.dry_run else "dry run -- nothing executed.")
    return rc


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    # Default --ref to the ref this repo is currently pinned to (from the
    # generated file), so a bare `sync` re-syncs the CURRENT target rather than a
    # hardcoded, quickly-stale older release. None (nothing pinned yet) means
    # --ref or --from-file must be given; cmd_sync enforces that.
    _synced_ref = None
    if GENERATED.exists():
        try:
            _synced_ref = ((yaml.safe_load(GENERATED.read_text()) or {})
                           .get("ludus_stock_pins_meta") or {}).get("ludus_ref")
        except yaml.YAMLError:
            _synced_ref = None
    s = sub.add_parser("sync", help="regenerate the stock pin data")
    s.add_argument("--ref", default=_synced_ref,
                   help="Ludus git tag, UNPREFIXED (default: the ref this repo "
                        "is pinned to; e.g. 2.3.1)")
    s.add_argument("--from-file",
                   help="read a local requirements.yml instead of fetching "
                        "(e.g. /opt/ludus/ansible/requirements.yml)")

    pa = sub.add_parser("sync-all-releases",
                        help="capture the stock pins of every Ludus release, "
                             "one file per version")
    pa.add_argument("--since", help="only releases >= this tag, e.g. 2.2.0")
    pa.add_argument("--force", action="store_true",
                    help="re-fetch releases already captured")
    pa.set_defaults(func=cmd_sync_all)
    s.set_defaults(func=cmd_sync)

    c = sub.add_parser("check",
                       help="fail on drift outside a blueprint, or a pin that is not published")
    c.add_argument("--offline", action="store_true",
                   help="skip the Galaxy published-version lookup (hermetic run)")
    c.set_defaults(func=cmd_check)

    lt = sub.add_parser("latest-tag",
                        help="print the newest Ludus tag known to upstream, nothing else")
    lt.set_defaults(func=cmd_latest_tag)

    cr = sub.add_parser("current-ref",
                        help="print the ludus_ref recorded in the generated pins file")
    cr.set_defaults(func=cmd_current_ref)

    r = sub.add_parser("restore",
                       help="HOST-ONLY: reinstall stock Galaxy pins (cannot run from CI)")
    g = r.add_mutually_exclusive_group(required=True)
    g.add_argument("--all", action="store_true",
                   help="every Ludus user plus root, matching ludus-server --update")
    g.add_argument("--user", help="one Ludus OS user directory under users/")
    r.add_argument("--ludus-root", default="/opt/ludus")
    r.add_argument("--dry-run", action="store_true", help="print commands, run nothing")
    r.set_defaults(func=cmd_restore)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
