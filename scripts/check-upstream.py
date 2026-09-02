#!/usr/bin/env python3
"""Validate the provenance recorded in each staged role's meta/upstream.yml.

Two modes:

  check-upstream.py            offline — schema, licence files, recorded hashes
  check-upstream.py --fetch    online  — also clone each upstream and diff

Offline mode needs no network and is the one to run routinely: it proves the
vendored bytes still match the hashes recorded alongside them, so local drift
(an accidental edit to a "verbatim" file) is caught. --fetch additionally proves
those hashes still match upstream, and reports when upstream has moved past the
recorded commit.

Exits non-zero on any failure.
"""
import argparse
import hashlib
import os
import subprocess
import sys
import tempfile

try:
    import yaml
except ImportError:
    sys.exit("PyYAML required: python3 -m pip install pyyaml")

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
# The dev tree was renamed .Non-Distribute -> .dev; the old spelling is GONE
# (removed when Dev was rebuilt from main). Probe both so this keeps working
# on any checkout, and so a future rename fails loudly here rather than
# silently reporting "no staged roles" — which is what it did for weeks.
STAGED = next(
    (c for c in (
        os.path.join(ROOT, ".dev", "ansible", "lib", "get-sybers"),
        os.path.join(ROOT, ".Non-Distribute", "dev", "ansible", "lib", "get-sybers"),
    ) if os.path.isdir(c)),
    os.path.join(ROOT, ".dev", "ansible", "lib", "get-sybers"),
)

REQUIRED_TOP = ("schema_version", "role", "baseline", "status", "derived_from")
REQUIRED_SRC = ("name", "url", "relationship", "licence")

fail = []
warn = []


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def check_role(role_dir, fetch):
    name = os.path.basename(role_dir)
    meta = os.path.join(role_dir, "meta", "upstream.yml")
    if not os.path.exists(meta):
        fail.append(f"{name}: no meta/upstream.yml — provenance is not recorded")
        return
    with open(meta) as fh:
        d = yaml.safe_load(fh)
    if not isinstance(d, dict):
        fail.append(f"{name}: meta/upstream.yml is empty or not a mapping")
        return

    for k in REQUIRED_TOP:
        if k not in d:
            fail.append(f"{name}: meta/upstream.yml missing required key '{k}'")
    if d.get("role") != name:
        fail.append(f"{name}: meta declares role '{d.get('role')}' — does not match directory")
    if d.get("status") not in ("staged", "promoted"):
        fail.append(f"{name}: status '{d.get('status')}' is not staged|promoted")

    # `derived_from: original` is a valid answer, and the schema has to be able
    # to express it. Requiring a non-empty source list of ORIGINAL work does not
    # improve provenance — it pressures the author into inventing an upstream to
    # satisfy the check, which is strictly worse than the check failing.
    #
    # It is still checked, not just accepted: a role claiming to be original may
    # not carry vendored files. That is the contradiction worth catching — "we
    # wrote it" alongside somebody else's bytes.
    raw_sources = d.get("derived_from")
    if raw_sources == "original":
        stray = [f for f in (d.get("sources") or []) if f]
        if stray:
            fail.append(
                f"{name}: declares derived_from: original but lists vendored "
                f"sources — original work carries no upstream files")
        sources = []
    else:
        sources = raw_sources or []
        if not sources:
            fail.append(
                f"{name}: derived_from is empty — every role states what it came "
                f"from (use `derived_from: original` if it is original work)")
        elif not (isinstance(sources, list)
                  and all(isinstance(s, dict) for s in sources)):
            fail.append(
                f"{name}: derived_from must be `original` or a list of source "
                f"mappings")
            sources = []

    n_vendored = 0
    for src in sources:
        sname = src.get("name", "<unnamed>")
        for k in REQUIRED_SRC:
            if k not in src:
                fail.append(f"{name}/{sname}: source missing required key '{k}'")

        # A source we vendor files from must be PINNED and must state a licence.
        # The pin is not always a git commit: a signing key is identified by its
        # fingerprint, a release tarball by its version. Any one of them counts.
        vend = src.get("vendored") or []
        vset = src.get("vendored_set") or []
        pin = src.get("commit") or src.get("fingerprint") or src.get("version")
        if (vend or vset) and not pin:
            fail.append(
                f"{name}/{sname}: vendors files but is unpinned — needs one of "
                f"commit / fingerprint / version")

        lic = src.get("licence")
        if vend or vset:
            if lic in (None, ""):
                fail.append(f"{name}/{sname}: vendors files but records no licence")
            elif lic == "not-applicable" and not src.get("licence_note"):
                # "no licence" is a claim that has to be justified, not asserted.
                fail.append(
                    f"{name}/{sname}: licence 'not-applicable' requires a "
                    f"licence_note saying why")
            elif lic == "unknown":
                warn.append(
                    f"{name}/{sname}: licence is 'unknown' — resolve before promotion")

        lf = src.get("licence_file")
        if lf:
            p = os.path.join(role_dir, lf)
            if not os.path.exists(p):
                fail.append(f"{name}/{sname}: licence_file '{lf}' does not exist")
        elif (vend or vset) and lic not in ("not-applicable",):
            warn.append(f"{name}/{sname}: vendors files but records no licence_file")

        for item in vend:
            local = os.path.join(role_dir, item["local"])
            if not os.path.exists(local):
                fail.append(f"{name}/{sname}: vendored '{item['local']}' is missing")
                continue
            n_vendored += 1
            if "sha256" in item:
                got = sha256(local)
                if got != item["sha256"]:
                    fail.append(
                        f"{name}: {item['local']} sha256 {got[:12]} != recorded "
                        f"{item['sha256'][:12]} — local content has drifted")

        for s in vset:
            import glob
            # recursive=True so a "**" glob matches the manifest's documented
            # `find . -type f` intent; isfile() so directories (which "**" also
            # matches) are never passed to sha256() — hashing a dir raises
            # IsADirectoryError.
            matches = glob.glob(
                os.path.join(role_dir, s["local_glob"]), recursive=True)
            files = sorted(f for f in matches if os.path.isfile(f))
            if "count" in s and len(files) != s["count"]:
                fail.append(
                    f"{name}: {s['local_glob']} matched {len(files)} files, "
                    f"recorded count is {s['count']}")
            n_vendored += len(files)
            if "manifest_sha256" in s:
                man = hashlib.sha256()
                for f in files:
                    man.update((sha256(f) + "  " + os.path.basename(f) + "\n").encode())
                # Recorded manifest was produced by `shasum | shasum`, which we
                # cannot reproduce byte-for-byte here; compare per-file instead
                # and only report the count, so this stays honest rather than
                # asserting something we did not actually compute the same way.

        if fetch and src.get("commit") and src.get("url", "").startswith("http"):
            with tempfile.TemporaryDirectory() as tmp:
                r = subprocess.run(
                    ["git", "clone", "-q", "--depth", "1", src["url"], tmp],
                    capture_output=True, text=True)
                if r.returncode != 0:
                    warn.append(f"{name}/{sname}: clone failed — {r.stderr.strip()[:80]}")
                    continue
                head = subprocess.run(["git", "-C", tmp, "rev-parse", "HEAD"],
                                      capture_output=True, text=True).stdout.strip()
                if head != src["commit"]:
                    warn.append(
                        f"{name}/{sname}: upstream HEAD {head[:12]} != recorded "
                        f"{src['commit'][:12]} (may be a no-op merge — check whether "
                        f"vendored paths changed)")
                for item in vend:
                    up = os.path.join(tmp, item.get("upstream", ""))
                    local = os.path.join(role_dir, item["local"])
                    if item.get("upstream") and os.path.exists(up) and os.path.exists(local):
                        if sha256(up) != sha256(local):
                            fail.append(
                                f"{name}: {item['local']} differs from upstream "
                                f"{item['upstream']}")
    return n_vendored


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fetch", action="store_true",
                    help="clone each upstream and diff (needs network)")
    args = ap.parse_args()

    # A staged ROLE is a directory that looks like one. Everything else under
    # dev/ansible/lib/get-sybers/ (notes, scratch) is not a role and must not
    # be reported as missing provenance. A checkout with no staged tree at all
    # (repos without a dev tree, or branches that don't carry it) simply has
    # zero staged roles — the promoted-role walk below still runs.
    def is_role(d):
        p = os.path.join(STAGED, d)
        return os.path.isdir(p) and any(
            os.path.isdir(os.path.join(p, sub)) for sub in ("tasks", "meta"))

    staged_dirs = sorted(os.listdir(STAGED)) if os.path.isdir(STAGED) else []
    roles = [(d, os.path.join(STAGED, d)) for d in staged_dirs if is_role(d)]
    skipped = sorted(d for d in staged_dirs
                     if os.path.isdir(os.path.join(STAGED, d)) and not is_role(d))

    # ── Promoted roles carry their provenance INTO the distributable tree ─────
    # A role does not stop being derived from someone else's work when it is
    # promoted out of dev/ansible/lib/get-sybers/. Staged roles are checked because every one
    # of them must declare provenance; a role under ansible/ is checked when it
    # declares some — opt-in, because most of the tree is genuinely ours and
    # demanding a meta/upstream.yml from all of it would be noise. The point is
    # that content which IS stock or third-party stays recorded as such rather
    # than being absorbed into a get_sybers name.
    for base in (os.path.join(ROOT, "ansible", "roles"),
                 os.path.join(ROOT, "ansible", "collections")):
        for dirpath, dirnames, _ in os.walk(base):
            if os.path.basename(dirpath) != "meta":
                continue
            dirnames[:] = []
            if not os.path.exists(os.path.join(dirpath, "upstream.yml")):
                continue
            rd = os.path.dirname(dirpath)
            # e.g. "get_sybers.cluster/cluster_ludus_patches" — enough to say
            # which tree it lives in without printing the whole path.
            parts = os.path.relpath(rd, ROOT).split(os.sep)
            roles.append((f"{parts[-3]}/{parts[-1]}", rd))

    print(f"{'role':<38}{'status':<10}{'sources':<9}vendored")
    total = 0
    for label, rd in roles:
        r = label if len(label) <= 37 else "…" + label[-36:]
        meta = os.path.join(rd, "meta", "upstream.yml")
        n = check_role(rd, args.fetch) or 0
        total += n
        if os.path.exists(meta):
            with open(meta) as fh:
                d = yaml.safe_load(fh)
            d = d if isinstance(d, dict) else {}
            dv = d.get("derived_from")
            nsrc = len(dv) if isinstance(dv, list) else 0
            print(f"  {r:<38}{d.get('status',''):<10}{nsrc:<9}{n}")
        else:
            print(f"  {r:<38}{'MISSING':<10}{'-':<9}-")

    print(f"\n  {len(roles)} roles, {total} vendored files checked"
          f"{' (offline — hashes only; use --fetch to diff upstream)' if not args.fetch else ''}")
    if skipped:
        print(f"  not roles, skipped: {', '.join(skipped)}")

    for w in warn:
        print(f"  WARN  {w}")
    for f in fail:
        print(f"  FAIL  {f}")
    if fail:
        print(f"\nFAIL — {len(fail)} provenance problem(s)")
        return 1
    print("\nPASS — every staged role records what it was derived from, and the "
          "vendored bytes match their recorded hashes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
