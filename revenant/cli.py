"""Revenant CLI — entry point for the ingest → extract → resurrect → replay engine.

Current commands
----------------
extract     Extract Windows credentials from VM artefacts using VMkatz.

Usage::

    python -m revenant extract [OPTIONS] TARGET [TARGET ...]
    revenant extract [OPTIONS] TARGET [TARGET ...]
"""

import argparse
import json
import sys

from revenant.extract.vmkatz import VMkatz


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="revenant",
        description="Resurrect forensic disk images into live Proxmox VMs.",
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    # ── extract ────────────────────────────────────────────────────────────
    extract_p = sub.add_parser(
        "extract",
        help="Extract Windows credentials from VM artefacts (uses VMkatz).",
        description=(
            "Extract Windows credentials from one or more VM artefacts using "
            "VMkatz (https://github.com/nikaiw/VMkatz). Targets may be memory "
            "snapshots (.vmsn, .vmem, .sav, QEMU savevm), virtual disks "
            "(.vmdk, .qcow2, .vhd, .vhdx, .vdi), raw registry hives "
            "(SAM SYSTEM SECURITY), LSASS minidumps (.dmp), or a VM directory."
        ),
    )
    extract_p.add_argument(
        "targets",
        nargs="+",
        metavar="TARGET",
        help="Path(s) to VM artefact(s) to extract credentials from.",
    )
    extract_p.add_argument(
        "--disk",
        metavar="DISK",
        default=None,
        help=(
            "Companion virtual disk for paged-out credential resolution "
            "(passed as --disk to VMkatz)."
        ),
    )
    extract_p.add_argument(
        "--ntds",
        action="store_true",
        default=False,
        help="Enable NTDS.dit extraction (domain-controller disk required).",
    )
    extract_p.add_argument(
        "--no-download",
        action="store_true",
        default=False,
        help=(
            "Do not attempt to download VMkatz automatically. "
            "Use VMKATZ_BIN env var or --vmkatz-bin to supply the binary."
        ),
    )
    extract_p.add_argument(
        "--vmkatz-bin",
        metavar="PATH",
        default=None,
        help="Explicit path to the vmkatz binary (skips auto-download).",
    )
    extract_p.add_argument(
        "--timeout",
        type=int,
        default=300,
        metavar="SECONDS",
        help="Maximum seconds to wait for VMkatz (default: 300).",
    )
    extract_p.add_argument(
        "--format",
        choices=["json", "pwdump"],
        default="json",
        dest="output_format",
        help="Output format: json (default) or pwdump.",
    )

    return parser


def _cmd_extract(args: argparse.Namespace) -> int:
    vmk = VMkatz(binary_path=args.vmkatz_bin)

    if not args.no_download and args.vmkatz_bin is None:
        try:
            vmk.ensure_binary()
        except Exception as exc:
            print(f"revenant: failed to obtain VMkatz binary: {exc}", file=sys.stderr)
            return 1

    try:
        creds = vmk.extract(
            *args.targets,
            disk=args.disk,
            ntds=args.ntds,
            timeout=args.timeout,
        )
    except FileNotFoundError as exc:
        print(f"revenant: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"revenant: extraction failed: {exc}", file=sys.stderr)
        return 1

    if args.output_format == "pwdump":
        for c in creds:
            # pwdump: DOMAIN\user:RID:LM:NT:::
            domain = c.domain or ""
            user = c.username or ""
            lm = c.lm_hash or "aad3b435b51404eeaad3b435b51404ee"
            nt = c.nt_hash or "31d6cfe0d16ae931b73c59d7e0c089c0"
            print(f"{domain}\\{user}:0:{lm}:{nt}:::")
    else:
        print(json.dumps([c.as_dict() for c in creds], indent=2))

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "extract":
        return _cmd_extract(args)

    parser.print_help()
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
