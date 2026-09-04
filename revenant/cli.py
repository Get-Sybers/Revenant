"""Revenant CLI — entry point for the ingest → extract → resurrect → replay engine.

Current commands
----------------
extract disk        Extract credentials from a virtual disk (VMDK, qcow2, VHD/VHDX, VDI).
extract snapshot    Extract credentials from a memory snapshot, optionally with a disk.

Usage::

    # Tier 1: virtual disk only (SAM, LSA, DCC2, DPAPI, NTDS.dit)
    revenant extract disk disk.vmdk
    revenant extract disk --ntds dc.qcow2

    # Tier 2: snapshot + disk (everything above + live LSASS material)
    revenant extract snapshot snapshot.vmsn --disk disk.vmdk
    revenant extract snapshot snapshot.vmem --disk disk.vmdk

    python -m revenant extract disk disk.vmdk
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
            "Extract Windows credentials from virtual disks and/or memory "
            "snapshots using VMkatz (https://github.com/nikaiw/VMkatz)."
        ),
    )
    extract_sub = extract_p.add_subparsers(dest="extract_mode", metavar="MODE")

    # shared options injected into both sub-parsers
    def _add_shared(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--ntds",
            action="store_true",
            default=False,
            help="Enable NTDS.dit extraction (domain-controller disk required).",
        )
        p.add_argument(
            "--no-download",
            action="store_true",
            default=False,
            help=(
                "Do not attempt to download VMkatz automatically. "
                "Use VMKATZ_BIN env var or --vmkatz-bin to supply the binary."
            ),
        )
        p.add_argument(
            "--vmkatz-bin",
            metavar="PATH",
            default=None,
            help="Explicit path to the vmkatz binary (skips auto-download).",
        )
        p.add_argument(
            "--timeout",
            type=int,
            default=300,
            metavar="SECONDS",
            help="Maximum seconds to wait for VMkatz (default: 300).",
        )
        p.add_argument(
            "--format",
            choices=["json", "pwdump"],
            default="json",
            dest="output_format",
            help="Output format: json (default) or pwdump.",
        )

    # ── extract disk ───────────────────────────────────────────────────────
    disk_p = extract_sub.add_parser(
        "disk",
        help="Extract credentials from a virtual disk (.vmdk, .qcow2, .vhd/.vhdx, .vdi).",
        description=(
            "Extract on-disk credentials from a virtual disk image: SAM NT/LM "
            "hashes, LSA secrets, cached domain credentials (DCC2), and DPAPI "
            "master-key hashes.  Use --ntds for a domain-controller disk to "
            "extract the full NTDS.dit hash table instead.\n\n"
            "Supported formats: .vmdk (VMware), .qcow2 (QEMU/Proxmox), "
            ".vhd/.vhdx (Hyper-V), .vdi (VirtualBox)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    disk_p.add_argument(
        "disk",
        metavar="DISK",
        help="Path to the virtual disk image.",
    )
    _add_shared(disk_p)

    # ── extract snapshot ───────────────────────────────────────────────────
    snap_p = extract_sub.add_parser(
        "snapshot",
        help=(
            "Extract credentials from a VM memory snapshot "
            "(.vmsn/.vmss/.vmem, VirtualBox .sav, QEMU savevm, Hyper-V .vmrs)."
        ),
        description=(
            "Extract live LSASS credentials from a VM memory snapshot: NT/LM "
            "hashes, WDigest plaintext passwords, Kerberos tickets, DPAPI "
            "session keys, and LSA secrets held in memory.\n\n"
            "Pass --disk to also supply the companion virtual disk.  VMkatz "
            "uses it to resolve paged-out credentials from the snapshot AND to "
            "run the full on-disk extraction (SAM, LSA, DCC2, DPAPI) in the "
            "same pass.\n\n"
            "Supported snapshot formats: .vmsn/.vmss (VMware), .vmem (raw VMware "
            "memory), .sav (VirtualBox), QEMU/KVM savevm state, .vmrs (Hyper-V), "
            ".elf (virsh dump)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    snap_p.add_argument(
        "snapshot",
        metavar="SNAPSHOT",
        help="Path to the VM memory snapshot.",
    )
    snap_p.add_argument(
        "--disk",
        metavar="DISK",
        default=None,
        help=(
            "Companion virtual disk (.vmdk, .qcow2, .vhd/.vhdx, .vdi). "
            "Enables paged-out credential resolution and on-disk extraction "
            "in the same VMkatz pass."
        ),
    )
    _add_shared(snap_p)

    return parser


def _get_vmk(args: argparse.Namespace) -> VMkatz | None:
    """Return a ready VMkatz instance, handling binary acquisition."""
    vmk = VMkatz(binary_path=args.vmkatz_bin)
    if not args.no_download and args.vmkatz_bin is None:
        try:
            vmk.ensure_binary()
        except Exception as exc:
            print(f"revenant: failed to obtain VMkatz binary: {exc}", file=sys.stderr)
            return None
    return vmk


def _print_creds(creds, output_format: str) -> None:
    if output_format == "pwdump":
        for c in creds:
            domain = c.domain or ""
            user = c.username or ""
            lm = c.lm_hash or "aad3b435b51404eeaad3b435b51404ee"
            nt = c.nt_hash or "31d6cfe0d16ae931b73c59d7e0c089c0"
            print(f"{domain}\\{user}:0:{lm}:{nt}:::")
    else:
        print(json.dumps([c.as_dict() for c in creds], indent=2))


def _cmd_extract_disk(args: argparse.Namespace) -> int:
    vmk = _get_vmk(args)
    if vmk is None:
        return 1
    try:
        creds = vmk.extract_from_disk(
            args.disk,
            ntds=args.ntds,
            timeout=args.timeout,
        )
    except (ValueError, FileNotFoundError) as exc:
        print(f"revenant: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"revenant: extraction failed: {exc}", file=sys.stderr)
        return 1
    _print_creds(creds, args.output_format)
    return 0


def _cmd_extract_snapshot(args: argparse.Namespace) -> int:
    vmk = _get_vmk(args)
    if vmk is None:
        return 1
    try:
        creds = vmk.extract_from_snapshot(
            args.snapshot,
            disk=args.disk,
            ntds=args.ntds,
            timeout=args.timeout,
        )
    except (ValueError, FileNotFoundError) as exc:
        print(f"revenant: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"revenant: extraction failed: {exc}", file=sys.stderr)
        return 1
    _print_creds(creds, args.output_format)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "extract":
        if not hasattr(args, "extract_mode") or args.extract_mode is None:
            # Print extract sub-command help
            parser.parse_args(["extract", "--help"])
            return 0
        if args.extract_mode == "disk":
            return _cmd_extract_disk(args)
        if args.extract_mode == "snapshot":
            return _cmd_extract_snapshot(args)

    parser.print_help()
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

