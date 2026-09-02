#!/usr/bin/env python3
"""Fail the build when a play calls a module the PINNED collection no longer ships.

WHY THIS EXISTS
    sync-ludus-stock-pins.py answers "is the pinned VERSION allowed, and is it
    published?". It deliberately treats a blueprint pinning a newer version as
    sanctioned, because that is the one place an override is permitted.

    Nothing answered the next question: does that version still CONTAIN the
    modules our plays call? A major collection release removes modules, and the
    failure is invisible until the play runs on a host -- at which point it dies
    at parse time, mid-deploy.

    Found live on 2026-08-04. The FGNW blueprint pins ansible.windows 3.7.0;
    ansible.windows 3.0.0 REMOVED win_domain_membership; three of the
    blueprint's own files still call it:

        ERROR! [DEPRECATED]: ansible.windows.win_domain_membership has been
        removed. Use microsoft.ad.membership instead.
          campaign/ansible/FGNW-exchange.yml:135

    So the blueprint pinned a version that breaks its own playbook, and every
    existing gate passed. This script closes that gap: it is the
    "prevents newer versions becoming spare of the build" half of the
    dependency policy.

WHAT IT CHECKS
    For every `namespace.collection.module:` task key in the repo, resolve the
    version that will ACTUALLY be installed (blueprint override wins over the
    stock pin, exactly as Galaxy resolves it) and assert the module ships in
    that version.

    Then, for every module found TOMBSTONED, sweep again for UNQUALIFIED calls
    to the same name. An FQCN-only scan is a false negative: plays that write
    `win_domain_membership:` bare and let the `collections:` search path resolve
    it die at parse time identically. Measured 2026-08-04 that blind spot hid 7
    of 13 call sites, including the AD-join roles applied to every Windows VM.

HOW A VERSION IS RESOLVED TO FILES
    In order, stopping at the first that works:
      1. An already-installed copy at EXACTLY the pinned version -- offline,
         instant. Searched under the Ludus per-user collection roots and root's.
      2. `ansible-galaxy collection install <fqcn>:<ver>` into a temp dir.
      3. UNKNOWN -- reported as NOT CHECKED, never as a pass.

    (3) is deliberately distinct from "no missing modules". An outage must not
    look like a clean build; see the same convention in
    sync-ludus-stock-pins.py's published_versions().

EXIT CODES
    0  every referenced module resolves at its pinned version (or was NOT
       CHECKED). Deprecated-but-redirecting modules are reported, not failed.
    1  at least one module is TOMBSTONED or absent at its pinned version,
       qualified or not
    2  usage / unparseable inputs
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("PyYAML required: apt install python3-yaml")

REPO_ROOT = Path(__file__).resolve().parents[1]


def _gates(section: str) -> dict:
    """This repo's scope for the mirrored checkers, from scripts/gates.yml.

    The scripts/*.py family is byte-identical across the source repos; the
    per-repo piece is gates.yml alone. Missing file or section means the
    script's built-in defaults apply.
    """
    p = Path(__file__).resolve().parent / "gates.yml"
    if not p.is_file():
        return {}
    try:
        import yaml
    except ImportError:
        sys.exit("FAIL: PyYAML is required to read scripts/gates.yml "
                 "(python3 -m pip install pyyaml)")
    try:
        return (yaml.safe_load(p.read_text()) or {}).get(section) or {}
    except Exception as exc:  # a broken config must be loud, not a silent default
        sys.exit(f"FAIL: unreadable scripts/gates.yml: {exc}")


GATES = _gates("module_availability")

GENERATED = REPO_ROOT / "ansible/meta/ludus-stock-pins.generated.yml"
# Stock pins are a PER-RELEASE fact (they ship inside the ludus-server binary),
# so they are captured one file per Ludus version. The ceiling is resolved
# against the version this host actually runs.
PINS_DIR = REPO_ROOT / "ansible/meta/ludus-stock-pins"

# A task key is `ns.coll.module:` at some indentation, optionally after a list
# dash. Anchoring to a mapping key is what keeps prose and comments out: a
# module name mentioned in a sentence is not followed by a colon at line end.
FQCN_KEY = re.compile(
    r"^\s*-?\s*([a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*)\s*:\s*(?:#.*)?$"
)

# molecule/ holds a vendored role's OWN test scaffolding (converge.yml etc.),
# which references that role by a name only meaningful inside its test harness.
# Sweeping it reports failures that say nothing about our pinned versions.
SKIP_DIRS = {".git", ".github", "node_modules", "__pycache__", ".dev", "molecule"}


def stock_pins() -> tuple[dict, str]:
    """(collections, ref) for the Ludus version this host runs, else the newest captured.

    The pins ship inside the ludus-server binary and are therefore a PER-RELEASE
    fact, captured one file per version under ansible/meta/ludus-stock-pins/.
    """
    if PINS_DIR.is_dir():
        refs = sorted((p.stem for p in PINS_DIR.glob("*.yml")),
                      key=lambda v: tuple(int(x) for x in v.split("."))
                      if re.fullmatch(r"[0-9]+(\.[0-9]+)*", v) else (0,))
        want = running_server_ref()
        pick = want if want in refs else (refs[-1] if refs else None)
        if pick:
            data = yaml.safe_load((PINS_DIR / f"{pick}.yml").read_text()) or {}
            return dict(data.get("ludus_stock_collections") or {}), pick
    if GENERATED.exists():
        data = yaml.safe_load(GENERATED.read_text()) or {}
        return (dict(data.get("ludus_stock_collections") or {}),
                str((data.get("ludus_stock_pins_meta") or {}).get("ludus_ref") or "?"))
    sys.exit(f"no stock pins recorded -- run `sync-ludus-stock-pins.py sync --ref <tag>`.")


def running_server_ref() -> str | None:
    """Ludus SERVER version running here, or None off-host.

    NOT `ludus-server version`: that is not a version subcommand -- the binary
    ignores the argument and tries to START A SECOND SERVER.
    """
    try:
        out = subprocess.run(["ludus", "version"], capture_output=True,
                             text=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"Ludus Server ([0-9]+\.[0-9]+\.[0-9]+)", out)
    return m.group(1) if m else None


def requirement_files() -> list:
    return sorted(REPO_ROOT.glob("blueprints/*/requirements.yml"))


def resolve_set(dest: Path, stock: dict | None = None) -> dict | None:
    """Install every blueprint requirements.yml and return {fqcn: resolved version}.

    RESOLUTION IS GALAXY'S JOB, not ours. requirements.yml carries RANGES whose
    upper bound is the stock ceiling; `ansible-galaxy` picks the highest version
    satisfying the range and resolves transitive dependencies at the same time.
    Re-deriving that in Python would be reimplementing the resolver badly -- and
    would still not agree with what actually gets installed, which is the only
    thing that matters. So: install it, then read back what landed.

    `--force` is required: without it Galaxy leaves an already-satisfying install
    alone ("Nothing to do") and the read-back would describe the host's existing
    tree rather than the requirement set under test.
    """
    reqs = requirement_files()
    if not reqs:
        return {}
    # ONE merged requirements file. `ansible-galaxy` does not accept positional
    # collection names alongside -r, and more importantly Galaxy resolves a
    # requirements file as a SINGLE dependency map — merging is what lets a
    # blueprint range and a stock pin be reconciled against each other rather
    # than installed in two passes that can disagree.
    #
    # STOCK collections are included because Ludus installs them per-user on the
    # host, so plays here use them freely (ansible.posix, ansible.utils, ...)
    # without any blueprint declaring them. A sweep with only the blueprint's
    # requirements is not the host: it fails plays for collections merely absent
    # from the test env. That reads as version breakage and is not — and it runs
    # GREEN locally (host has them) and RED in CI, the worst kind of gate.
    merged: dict = {}
    for r in reqs:
        try:
            data = yaml.safe_load(r.read_text()) or {}
        except yaml.YAMLError:
            continue
        for e in data.get("collections") or []:
            if isinstance(e, dict) and e.get("name"):
                merged[e["name"]] = e.get("version")
    for name, ver in (stock or {}).items():
        merged.setdefault(name, ver)

    combined = dest / "merged-requirements.yml"
    combined.parent.mkdir(parents=True, exist_ok=True)
    combined.write_text(yaml.safe_dump(
        {"collections": [{"name": n, **({"version": v} if v else {})}
                         for n, v in sorted(merged.items())]},
        sort_keys=False))

    cmd = ["ansible-galaxy", "collection", "install", "-r", str(combined),
           "-p", str(dest), "--force"]
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          env={**os.environ, "HOME": str(dest)})
    if proc.returncode != 0:
        return None

    # Roles too. The same requirements.yml declares `roles:`, and a play that
    # calls one cannot be syntax-checked without it — the sweep would report
    # "role not found" and blame the pinned versions for a role that was simply
    # never installed. Non-fatal: a role that fails to fetch is reported by the
    # sweep as an external-role gap, not as version breakage.
    for r in reqs:
        subprocess.run(["ansible-galaxy", "role", "install", "-r", str(r),
                        "-p", str(dest / "roles")],
                       capture_output=True, text=True,
                       env={**os.environ, "HOME": str(dest)})
    out = {}
    import json
    for man in (dest / "ansible_collections").glob("*/*/MANIFEST.json"):
        try:
            info = json.loads(man.read_text())["collection_info"]
            out[f"{info['namespace']}.{info['name']}"] = info["version"]
        except Exception:
            continue
    return out


def collect_refs(pinned: set) -> dict:
    """{fqcn_module: [(relpath, lineno), ...]} for modules in pinned collections."""
    refs: dict[str, list] = {}
    for path in REPO_ROOT.rglob("*.yml"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            m = FQCN_KEY.match(line)
            if not m:
                continue
            fqcn = m.group(1)
            coll = ".".join(fqcn.split(".")[:2])
            if coll in pinned:
                refs.setdefault(fqcn, []).append(
                    (str(path.relative_to(REPO_ROOT)), i)
                )
    return refs


SHORT_KEY = re.compile(r"^\s*-?\s*([a-z][a-z0-9_]{2,})\s*:\s*(?:#.*)?$")


def collect_short_refs(names: set) -> dict:
    """{bare_module: [(relpath, lineno), ...]} for UNQUALIFIED task keys.

    ⚠️ Without this the gate has a false NEGATIVE, which is worse than no gate.
    Plenty of real plays still write `win_domain_membership:` unqualified and let
    the `collections:` search path resolve it — so an FQCN-only scan reports the
    file clean while it dies at parse time exactly like the qualified call.

    Measured 2026-08-04, pre-de-GOAD: the FQCN scan found win_domain_membership
    at 2 sites in FGNW-exchange.yml, and MISSED it in the then-present GOAD
    AD-join roles (member_server, commonwkstn — since removed) that applied to
    every Windows VM in the range.

    This is name-based, so it cannot know which collection an unqualified name
    would resolve to. It only fires for names already proven TOMBSTONED in a
    pinned collection, and says so, rather than guessing.
    """
    refs: dict[str, list] = {}
    for path in REPO_ROOT.rglob("*.yml"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            m = SHORT_KEY.match(line)
            if m and m.group(1) in names:
                refs.setdefault(m.group(1), []).append(
                    (str(path.relative_to(REPO_ROOT)), i)
                )
    return refs


def _installed_roots() -> list[Path]:
    roots = []
    users = Path("/opt/ludus/users")
    if users.is_dir():
        for u in sorted(users.iterdir()):
            p = u / ".ansible/collections/ansible_collections"
            if p.is_dir():
                roots.append(p)
    for extra in ("/root/.ansible/collections/ansible_collections",):
        p = Path(extra)
        if p.is_dir():
            roots.append(p)
    return roots


def _version_of(coll_dir: Path) -> str | None:
    manifest = coll_dir / "MANIFEST.json"
    if manifest.is_file():
        import json

        try:
            return json.loads(manifest.read_text())["collection_info"]["version"]
        except Exception:
            return None
    galaxy = coll_dir / "galaxy.yml"
    if galaxy.is_file():
        try:
            return str((yaml.safe_load(galaxy.read_text()) or {}).get("version"))
        except yaml.YAMLError:
            return None
    return None


def locate(coll: str, version: str, allow_install: bool, cache: dict) -> Path | None:
    """Directory of `coll` at exactly `version`, or None if it can't be obtained."""
    key = (coll, version)
    if key in cache:
        return cache[key]
    ns, name = coll.split(".", 1)

    for root in _installed_roots():
        cand = root / ns / name
        if cand.is_dir() and _version_of(cand) == version:
            cache[key] = cand
            return cand

    if allow_install:
        tmp = Path(tempfile.mkdtemp(prefix="modavail-"))
        proc = subprocess.run(
            ["ansible-galaxy", "collection", "install", f"{coll}:{version}",
             "-p", str(tmp)],
            capture_output=True, text=True,
            env={**os.environ, "ANSIBLE_COLLECTIONS_PATH": str(tmp)},
        )
        cand = tmp / "ansible_collections" / ns / name
        if proc.returncode == 0 and cand.is_dir():
            cache[key] = cand
            return cand
        shutil.rmtree(tmp, ignore_errors=True)

    cache[key] = None
    return None


def _routing(coll_dir: Path) -> dict:
    """`plugin_routing.modules` from the collection's meta/runtime.yml."""
    meta = coll_dir / "meta" / "runtime.yml"
    if not meta.is_file():
        return {}
    try:
        data = yaml.safe_load(meta.read_text()) or {}
    except yaml.YAMLError:
        return {}
    return dict((data.get("plugin_routing") or {}).get("modules") or {})


def classify(coll_dir: Path, module: str) -> tuple[str, str]:
    """(verdict, detail) — PRESENT | DEPRECATED | REDIRECT | TOMBSTONE | MISSING.

    ⚠️ A missing plugin FILE does NOT mean the FQCN fails. Collections keep a
    `plugin_routing` table in meta/runtime.yml, and there are two very different
    entries there:

      redirect:  the name still RESOLVES, to another collection's module. Ansible
                 emits a deprecation warning and runs it. Not a failure.
      tombstone: the name is HARD REMOVED. Ansible aborts at parse time with
                 "has been removed", which is the failure this gate exists for.

    Checking file presence alone reports every redirect as broken. Measured
    2026-08-04: that produced 10 "missing" of which most were routine redirects
    (e.g. community.windows.win_dns_zone -> ansible.windows.win_dns_zone), while
    the genuine breaks were tombstones (win_domain_membership, win_domain_user).

    DEPRECATED (issue #206, F7): a deprecation-ONLY routing entry — no redirect,
    no tombstone, plugin file still shipped. The module resolves and runs today,
    so this is NOT a failure; it is the earliest visible edge of the next
    removal cliff, surfaced so the pin can be planned instead of discovered
    the release the entry turns into a tombstone.
    """
    route = _routing(coll_dir).get(module)
    mods = coll_dir / "plugins" / "modules"
    # A module is <name>.py, <name>.ps1 (Windows), or <name>.yml (sidecar docs).
    shipped = mods.is_dir() and any((mods / f"{module}{ext}").exists()
                                    for ext in (".py", ".ps1", ".yml"))
    if isinstance(route, dict):
        if "tombstone" in route:
            t = route["tombstone"] or {}
            return "TOMBSTONE", (t.get("warning_text")
                                 or f"removed in {t.get('removal_version', '?')}")
        if "redirect" in route:
            dep = (route.get("deprecation") or {}).get("removal_version")
            tail = f"; deprecated, goes in {dep}" if dep else ""
            return "REDIRECT", f"{route['redirect']}{tail}"
        if "deprecation" in route and shipped:
            d = route["deprecation"] or {}
            return "DEPRECATED", (d.get("warning_text")
                                  or f"removal scheduled in {d.get('removal_version', '?')}")

    if shipped:
        return "PRESENT", ""
    return "MISSING", "no plugin file and no routing entry"


def parse_sweep(root: Path) -> list:
    """`ansible-playbook --syntax-check` every repo playbook against `root`.

    The version checks prove a MODULE exists. They cannot prove the play still
    LOADS -- a renamed parameter, a moved role, a removed lookup all survive a
    module-presence check and die at parse time. This is the sweep that proves it.
    """
    plays = []
    for f in sorted(REPO_ROOT.rglob("*.yml")):
        if any(part in SKIP_DIRS for part in f.parts):
            continue
        # A PLAYBOOK is a top-level list whose entries carry hosts:/import_playbook:.
        # Detecting on `- name:` instead matches every TASK FILE in every role and
        # reports "'ansible.builtin.slurp' is not a valid attribute for a Play".
        try:
            doc = yaml.safe_load(f.read_text(errors="replace"))
        except (yaml.YAMLError, OSError):
            continue
        if isinstance(doc, list) and any(
                isinstance(e, dict) and ("hosts" in e or "import_playbook" in e)
                for e in doc):
            plays.append(f)

    # The repo ships its own collections as ansible/collections/<ns>.<name>/ -- a
    # DOTTED directory, not the ansible_collections/<ns>/<name> layout FQCN
    # resolution needs. Without linking them in, every play calling
    # get_sybers.cluster.* fails for a reason unrelated to the versions under test.
    for own in sorted((REPO_ROOT / "ansible/collections").glob("*.*")):
        if not own.is_dir() or "." not in own.name:
            continue
        ns, _, nm = own.name.partition(".")
        dest = root / ns / nm
        if not dest.exists():
            dest.parent.mkdir(parents=True, exist_ok=True)
            try:
                dest.symlink_to(own)
            except OSError:
                pass

    env = {**os.environ, "ANSIBLE_COLLECTIONS_PATH": str(root.parent),
           # Vendored roles live in the repo (ansible/roles/<name>) and are
           # installed by `ludus source add`, never by ansible-galaxy — so they
           # must be on the path explicitly or every play using one fails the
           # sweep for a reason unrelated to the pinned versions.
           "ANSIBLE_ROLES_PATH": os.pathsep.join([
               str(root.parent / "roles"),
               str(REPO_ROOT / "ansible/roles"),
           ]),
           "ANSIBLE_LOCALHOST_WARNING": "False"}
    failures = []
    for f in plays:
        r = subprocess.run(
            ["ansible-playbook", "--syntax-check", "-i", "localhost,", str(f)],
            capture_output=True, text=True, env=env, cwd=str(f.parent))
        if r.returncode != 0:
            out = (r.stderr or "") + "\n" + (r.stdout or "")
            # Scan the WHOLE output for the missing-role name rather than
            # picking one line and hoping it is the message. Two earlier
            # attempts failed here: "first line starting with ERROR" came back
            # EMPTY in CI, and "last non-empty line" picked ansible's caret
            # marker ("^ column 7"). Either way the classifier below could not
            # tell an external-role gap from real version breakage and failed
            # the build on something it cannot fix.
            # Match the role name across ansible-core phrasings. The wording has
            # changed between releases ("the role 'X' was not found" vs
            # "the role X was not found in ..."), and a classifier keyed to one
            # of them fails on the other — which is precisely what happened when
            # CI ran a newer core than the host.
            role = None
            for pat in (r"the role '([^']+)' was not found",
                        r"[Tt]he role ([A-Za-z0-9_.\-]+) was not found",
                        r"role '([^']+)' is not found",
                        r"Could not find the role ['\"]?([A-Za-z0-9_.\-]+)"):
                m = re.search(pat, out)
                if m:
                    role = m.group(1)
                    break
            lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
            msg = next((ln for ln in lines if ln.startswith("ERROR")),
                       lines[-1] if lines else "(no output captured)")
            failures.append((str(f.relative_to(REPO_ROOT)), msg[:220], role))
    return failures


def declared_roles() -> set:
    """Role names this repo declares or vendors."""
    names = set()
    for req in requirement_files():
        try:
            data = yaml.safe_load(req.read_text()) or {}
        except yaml.YAMLError:
            continue
        for e in data.get("roles") or []:
            if isinstance(e, dict) and e.get("name"):
                names.add(e["name"])
    roles_dir = REPO_ROOT / "ansible/roles"
    if roles_dir.is_dir():
        names |= {d.name for d in roles_dir.iterdir() if d.is_dir()}
    return names


def split_parse_failures(failures: list) -> tuple[list, list]:
    """(version_breakage, external_role_gaps).

    A play that fails ONLY because a role we neither declare nor vendor is
    absent is not evidence about our pinned versions — those roles are supplied
    by the Ludus template build environment at image-build time. Failing the
    dependency gate on them would make it permanently red for a reason it cannot
    fix, which is how a gate stops being read.
    """
    declared = declared_roles()
    real, external = [], []
    for rel, err, role in failures:
        if role and role not in declared:
            external.append((rel, role))
        else:
            real.append((rel, err))
    return real, external


def _v(x: str):
    import re as _re
    return (tuple(int(p) for p in x.split("."))
            if _re.fullmatch(r"\d+\.\d+\.\d+", x or "") else None)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--skip-parse", action="store_true",
                    help="skip the parse sweep (diagnosis only)")
    args = ap.parse_args()

    if GATES.get("applicable") is False:
        print("NOT-APPLICABLE (scripts/gates.yml): "
              f"{GATES.get('reason', 'no reason recorded')}")
        return 0
    for tool in ("ansible-galaxy", "ansible-playbook"):
        if shutil.which(tool) is None:
            print(f"FAIL: {tool} is not on PATH — this gate installs the "
                  "pinned collections and syntax-checks every play, which "
                  "needs a working ansible install.")
            return 1

    # Ludus REJECTS a blueprint whose requirements.yml exceeds 5000 characters
    # ("requirements_yaml: Must be no more than 5000 character(s)"), and the
    # rejection happens at `ludus source add` — i.e. on the host, long after
    # review, and it fails the WHOLE blueprint, not just the file. Commentary
    # once took this to 5955 chars (5094 of them comments) and the blueprint
    # could not be installed at all. Cheap to check here, expensive to discover
    # there.
    LIMIT = 5000
    oversize = [(r, len(r.read_text()))
                for r in requirement_files() if len(r.read_text()) > LIMIT]
    if oversize:
        print("=== requirements.yml OVER THE LUDUS SERVER LIMIT ===\n")
        for r, n in oversize:
            print(f"  {r.relative_to(REPO_ROOT)}  {n} chars (limit {LIMIT})")
        print("\n  `ludus source add` will refuse the blueprint outright. Move prose")
        print("  to ansible/meta/ludus-stock-pins.yml and keep this file near payload.\n")
        return 1

    stock, stock_ref = stock_pins()
    print(f"stock ceiling from Ludus {stock_ref} "
          f"({len(stock)} collections Ludus itself ships)\n")

    root = Path(tempfile.mkdtemp(prefix="modavail-"))
    try:
        resolved = resolve_set(root, stock)
        if resolved is None:
            print("NOT CHECKED: the requirement set could not be installed "
                  "(no network?). This is NOT a pass.")
            return 0
        if not resolved:
            print("no blueprint requirements.yml found -- nothing to check.")
            return 0

        colls = root / "ansible_collections"

        # ---- STAGE 1: the ceiling. Stock pins bound ONLY what Ludus ships. ----
        print("=== ceiling: a collection Ludus ships may not resolve above its stock pin ===\n")
        over = []
        for coll in sorted(resolved):
            got, cap = resolved[coll], stock.get(coll)
            if cap is None:
                print(f"  {coll:<28} {got:<9} (not shipped by Ludus -- no ceiling)")
            elif _v(got) and _v(cap) and _v(got) > _v(cap):
                print(f"  {coll:<28} {got:<9} EXCEEDS stock {cap}")
                over.append((coll, got, cap))
            else:
                print(f"  {coll:<28} {got:<9} "
                      + ("at ceiling" if got == cap else f"under ceiling {cap}"))
        print()
        if over:
            print("  A blueprint pinning above stock does NOT sit alongside it:")
            print("  `ludus source add` overwrites the shared per-user tree, so every")
            print("  consumer gets the newer one. Lower the upper bound to the stock pin.\n")

        # ---- STAGE 2: every module we call exists at the RESOLVED version -----
        refs = collect_refs(set(resolved))
        fatal, redirects, deprecated, ok = [], [], [], 0
        for fqcn in sorted(refs):
            coll = ".".join(fqcn.split(".")[:2])
            ns, nm = coll.split(".", 1)
            verdict, detail = classify(colls / ns / nm, fqcn.split(".")[2])
            row = (fqcn, resolved[coll], detail, refs[fqcn])
            if verdict == "PRESENT":
                ok += 1
            elif verdict == "REDIRECT":
                redirects.append(row)
            elif verdict == "DEPRECATED":
                deprecated.append(row)
            else:
                fatal.append((verdict, *row))

        if fatal:
            print("=== REMOVED AT THE RESOLVED VERSION -- THESE PLAYS CANNOT RUN ===\n")
            for verdict, fqcn, version, detail, sites in fatal:
                print(f"  {fqcn}   [{verdict}]  resolved {version}")
                print(f"      {detail}")
                for rel, line in sites:
                    print(f"      called at {rel}:{line}")
                print()

        tomb = {f.split(".")[2] for v, f, *_ in fatal if v == "TOMBSTONE"}
        short = collect_short_refs(tomb) if tomb else {}
        if short:
            print("=== SAME REMOVED MODULES, CALLED UNQUALIFIED ===\n")
            for name, sites in sorted(short.items()):
                print(f"  {name}:")
                for rel, line in sites:
                    print(f"      called at {rel}:{line}")
            print()

        if redirects:
            print("--- deprecated but still resolving (not a failure) ---")
            for fqcn, version, detail, sites in redirects:
                print(f"  {fqcn} -> {detail}   ({len(sites)} call site(s))")
            print()

        if deprecated:
            print("--- deprecated IN PLACE — the next removal cliff (not a failure) ---")
            for fqcn, version, detail, sites in deprecated:
                print(f"  {fqcn}   [{detail}]   ({len(sites)} call site(s))")
            print()

        # ---- STAGE 3: it must still PARSE at those versions -------------------
        parse_fail = []
        if not args.skip_parse and not fatal:
            parse_fail, external = split_parse_failures(parse_sweep(colls))
            if external:
                print("--- plays needing a role supplied outside this repo "
                      "(not a version problem) ---")
                for rel, role in external:
                    print(f"  {rel}   needs role '{role}'")
                print()
            if parse_fail:
                print("=== PLAYS THAT DO NOT PARSE AT THE RESOLVED VERSIONS ===\n")
                for rel, err in parse_fail:
                    print(f"  {rel}\n      {err}")
                print()
            else:
                print("parse sweep: every playbook loads at the resolved versions.\n")

        print(f"{ok} present, {len(deprecated)} deprecated in place, "
              f"{len(redirects)} redirected, {len(fatal)} REMOVED, "
              f"{len(short)} unqualified, {len(over)} above ceiling, "
              f"{len(parse_fail)} parse failure(s).")
        return 1 if (fatal or short or over or parse_fail) else 0
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
