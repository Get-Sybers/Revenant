"""VMkatz binary manager and credential-extraction wrapper.

VMkatz (https://github.com/nikaiw/VMkatz) is a static binary that extracts
Windows credentials — NTLM hashes, Kerberos tickets, cached domain creds,
LSA secrets, DPAPI master keys, NTDS.dit, BitLocker keys — directly from VM
virtual disks and memory snapshots, without pulling the full image.

Primary use-case for Revenant: extract credentials from a VMDK (or other
virtual disk format) that was imported alongside a forensic scenario.  When a
memory snapshot is also available — a ``.vmsn``/``.vmss`` VMware snapshot, a
``.vmem`` raw memory file, a QEMU savevm state, or similar — pass it together
with the disk so VMkatz can resolve paged-out credentials and extract
live-session material (Kerberos tickets, WDigest plaintext, DPAPI keys) in
addition to the on-disk SAM/LSA/DCC2 hashes.

Extraction tiers
----------------
1. **Disk only** (``extract_from_disk``) — SAM hashes, LSA secrets, cached
   domain credentials (DCC2), DPAPI master-key hashes, NTDS.dit (DC disks).
   Supported formats: ``.vmdk``, ``.qcow2``, ``.vhd``/``.vhdx``, ``.vdi``.

2. **Disk + snapshot** (``extract_from_snapshot``) — everything in tier 1, plus
   live LSASS material: NT/LM hashes, WDigest plaintext, Kerberos tickets,
   DPAPI session keys, LSA secrets held in memory.  Supply the snapshot as the
   first positional argument; pass the companion disk via ``disk=``.

This module:
  1. Downloads the pinned VMkatz release for the current platform on first use.
  2. Verifies the SHA-256 digest against the upstream SHA256SUMS release asset.
  3. Invokes the binary and returns credentials as typed :class:`Credential`
     dataclass instances.

Quick start::

    from revenant.extract.vmkatz import VMkatz

    vmk = VMkatz()
    vmk.ensure_binary()   # idempotent — no-op when binary is current

    # Tier 1: disk only
    creds = vmk.extract_from_disk("disk.vmdk")

    # Tier 2: disk + VMware snapshot
    creds = vmk.extract_from_snapshot("snapshot.vmsn", disk="disk.vmdk")

    # Tier 2: disk + raw memory file
    creds = vmk.extract_from_snapshot("snapshot.vmem", disk="disk.vmdk")

    # Domain-controller disk — full NTDS.dit extraction
    creds = vmk.extract_from_disk("dc-disk.vmdk", ntds=True)
"""

import csv
import hashlib
import io
import os
import platform
import stat
import subprocess
import tarfile
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Release pin
# ---------------------------------------------------------------------------

VMKATZ_VERSION = "1.4.1"
VMKATZ_RELEASE_BASE = (
    f"https://github.com/nikaiw/VMkatz/releases/download/v{VMKATZ_VERSION}"
)
VMKATZ_SHA256SUMS_URL = f"{VMKATZ_RELEASE_BASE}/SHA256SUMS.txt"

# Supported virtual-disk extensions (checked before handing a path to VMkatz).
DISK_EXTENSIONS: frozenset[str] = frozenset(
    {".vmdk", ".qcow2", ".vhd", ".vhdx", ".vdi"}
)

# Supported memory-snapshot extensions.
SNAPSHOT_EXTENSIONS: frozenset[str] = frozenset(
    {".vmsn", ".vmss", ".vmem", ".sav", ".vmrs", ".elf"}
)

# Default install location — respects XDG_DATA_HOME if set.
_XDG_DATA_HOME = Path(
    os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")
)
DEFAULT_BIN_DIR: Path = _XDG_DATA_HOME / "revenant" / "bin"


# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

def _asset_name() -> str:
    """Return the VMkatz release asset filename for the running platform."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    # Normalise architecture names
    arch_map = {
        "x86_64": "x86_64",
        "amd64": "x86_64",
        "aarch64": "aarch64",
        "arm64": "aarch64",
        "armv7l": "armv7",
        "armv6l": "arm",
    }
    arch = arch_map.get(machine)
    if arch is None:
        raise RuntimeError(
            f"Unsupported CPU architecture '{machine}' for VMkatz auto-download. "
            "Set VMKATZ_BIN to a pre-downloaded binary path."
        )

    if system == "linux":
        return f"vmkatz-v{VMKATZ_VERSION}-linux-{arch}.tar.gz"
    if system == "darwin":
        return f"vmkatz-v{VMKATZ_VERSION}-macos-{arch}.tar.gz"
    if system == "windows":
        return f"vmkatz-v{VMKATZ_VERSION}-windows-{arch}.zip"

    raise RuntimeError(
        f"Unsupported OS '{system}' for VMkatz auto-download. "
        "Set VMKATZ_BIN to a pre-downloaded binary path."
    )


# ---------------------------------------------------------------------------
# SHA-256 helpers
# ---------------------------------------------------------------------------

def _sha256_file(path: Path) -> str:
    """Return the lowercase hex SHA-256 digest of *path*."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _fetch_expected_sha256(asset_name: str) -> str:
    """Download SHA256SUMS.txt and return the digest for *asset_name*."""
    with urllib.request.urlopen(VMKATZ_SHA256SUMS_URL) as resp:  # noqa: S310
        text = resp.read().decode()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[1].strip() == asset_name:
            return parts[0].lower()
    raise ValueError(
        f"'{asset_name}' not found in SHA256SUMS.txt from VMkatz v{VMKATZ_VERSION}."
    )


# ---------------------------------------------------------------------------
# Download + install
# ---------------------------------------------------------------------------

def _extract_binary(archive_path: Path, dest_dir: Path) -> Path:
    """Extract the vmkatz binary from a release archive into *dest_dir*."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    archive_name = archive_path.name

    if archive_name.endswith(".tar.gz"):
        with tarfile.open(archive_path, "r:gz") as tf:
            members = tf.getmembers()
            # The binary is the sole executable in the archive.
            bin_member = next(
                (m for m in members if m.name.endswith("vmkatz") and m.isfile()),
                None,
            )
            if bin_member is None:
                raise RuntimeError(
                    f"Could not find 'vmkatz' binary inside {archive_name}."
                )
            extracted = tf.extractfile(bin_member)
            if extracted is None:
                raise RuntimeError(
                    f"Could not extract 'vmkatz' binary from {archive_name}."
                )
            out = dest_dir / "vmkatz"
            out.write_bytes(extracted.read())
    elif archive_name.endswith(".zip"):
        with zipfile.ZipFile(archive_path) as zf:
            names = zf.namelist()
            bin_entry = next(
                (n for n in names if n.endswith("vmkatz.exe")),
                None,
            )
            if bin_entry is None:
                raise RuntimeError(
                    f"Could not find 'vmkatz.exe' inside {archive_name}."
                )
            data = zf.read(bin_entry)
            out = dest_dir / "vmkatz.exe"
            out.write_bytes(data)
    else:
        raise RuntimeError(f"Unknown archive format: {archive_name}")

    bin_name = "vmkatz.exe" if platform.system().lower() == "windows" else "vmkatz"
    installed = dest_dir / bin_name
    # Ensure the binary is executable on POSIX systems.
    installed.chmod(installed.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)
    return installed


# ---------------------------------------------------------------------------
# Credential record
# ---------------------------------------------------------------------------

@dataclass
class Credential:
    """A single credential record emitted by VMkatz.

    Fields map directly to VMkatz's ``--format csv`` columns. Any column not
    present for a given credential type is left as ``None``.
    """

    cred_type: str
    domain: Optional[str] = None
    username: Optional[str] = None
    nt_hash: Optional[str] = None
    lm_hash: Optional[str] = None
    sha1: Optional[str] = None
    plaintext: Optional[str] = None
    extra: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        """Return a plain dict representation (suitable for JSON serialisation)."""
        d = {
            "type": self.cred_type,
            "domain": self.domain,
            "username": self.username,
            "nt_hash": self.nt_hash,
            "lm_hash": self.lm_hash,
            "sha1": self.sha1,
            "plaintext": self.plaintext,
        }
        d.update(self.extra)
        return {k: v for k, v in d.items() if v is not None}


def _parse_csv(csv_text: str) -> list[Credential]:
    """Parse VMkatz ``--format csv`` output into :class:`Credential` objects."""
    # VMkatz CSV columns (as of v1.4.x):
    #   type, domain, username, nt_hash, lm_hash, sha1, plaintext, ...
    known = {"type", "domain", "username", "nt_hash", "lm_hash", "sha1", "plaintext"}
    creds: list[Credential] = []
    reader = csv.DictReader(io.StringIO(csv_text))
    for row in reader:
        extra = {k: v for k, v in row.items() if k not in known and v}
        creds.append(
            Credential(
                cred_type=row.get("type", "unknown"),
                domain=row.get("domain") or None,
                username=row.get("username") or None,
                nt_hash=row.get("nt_hash") or None,
                lm_hash=row.get("lm_hash") or None,
                sha1=row.get("sha1") or None,
                plaintext=row.get("plaintext") or None,
                extra=extra,
            )
        )
    return creds


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

class VMkatz:
    """Manages the VMkatz binary and runs credential-extraction jobs.

    The primary extraction methods are:

    * :meth:`extract_from_disk` — SAM hashes, LSA secrets, cached domain
      credentials, DPAPI master-key hashes, and (optionally) NTDS.dit from a
      virtual disk (``.vmdk``, ``.qcow2``, ``.vhd``/``.vhdx``, ``.vdi``).

    * :meth:`extract_from_snapshot` — everything above **plus** live LSASS
      material (NT/LM, WDigest, Kerberos tickets, DPAPI session keys) extracted
      from a memory snapshot.  Accepts any snapshot format VMkatz supports
      (``.vmsn``, ``.vmss``, ``.vmem``, QEMU savevm, ``.vmrs``, ``.elf``).
      Pass the companion disk via ``disk=`` for paged-out credential resolution
      and to unlock on-disk secrets alongside memory extraction.

    Args:
        bin_dir: Directory where the vmkatz binary is stored.  Defaults to
            ``~/.local/share/revenant/bin`` (XDG_DATA_HOME honoured).
        binary_path: Explicit path to an already-installed vmkatz binary.
            When set, *bin_dir* is ignored and no download is attempted.
            The ``VMKATZ_BIN`` environment variable has the same effect.
    """

    def __init__(
        self,
        bin_dir: Optional[Path] = None,
        binary_path: Optional[Path] = None,
    ) -> None:
        # Allow the caller (or env var) to supply a pre-installed binary.
        env_bin = os.environ.get("VMKATZ_BIN")
        if binary_path is not None:
            self._binary: Optional[Path] = Path(binary_path)
        elif env_bin:
            self._binary = Path(env_bin)
        else:
            self._binary = None

        self._bin_dir = Path(bin_dir) if bin_dir else DEFAULT_BIN_DIR

    # ------------------------------------------------------------------
    # Binary management
    # ------------------------------------------------------------------

    def _bin_name(self) -> str:
        return "vmkatz.exe" if platform.system().lower() == "windows" else "vmkatz"

    def _installed_path(self) -> Path:
        return self._bin_dir / self._bin_name()

    def _installed_digest_path(self) -> Path:
        return self._bin_dir / f"{self._bin_name()}.sha256"

    def binary_path(self) -> Path:
        """Return the path to the vmkatz binary.

        Does *not* download the binary — call :meth:`ensure_binary` for that.
        """
        if self._binary is not None:
            if not self._binary.exists():
                raise FileNotFoundError(
                    f"Configured VMkatz binary not found: {self._binary}"
                )
            return self._binary
        return self._installed_path()

    def ensure_binary(self) -> Path:
        """Ensure the pinned VMkatz binary is present and verified.

        Downloads from the GitHub release if not already installed.  The
        SHA-256 digest is always checked against the upstream SHA256SUMS file.

        Returns:
            Path to the vmkatz binary.
        """
        # If the caller supplied an explicit binary, trust it as-is.
        if self._binary is not None:
            if not self._binary.exists():
                raise FileNotFoundError(
                    f"Configured VMkatz binary not found: {self._binary}"
                )
            return self._binary

        installed = self._installed_path()
        installed_digest_path = self._installed_digest_path()
        asset = _asset_name()
        expected_sha = _fetch_expected_sha256(asset)

        # Already installed and locally verified before — nothing to do.
        if installed.exists() and installed_digest_path.exists():
            recorded_sha = installed_digest_path.read_text(encoding="utf-8").strip().lower()
            if recorded_sha and _sha256_file(installed) == recorded_sha:
                return installed

        # Download the archive into a temp directory, verify, then install.
        url = f"{VMKATZ_RELEASE_BASE}/{asset}"
        with tempfile.TemporaryDirectory() as tmp:
            tmp_archive = Path(tmp) / asset
            with urllib.request.urlopen(url) as resp:  # noqa: S310
                tmp_archive.write_bytes(resp.read())

            actual_sha = _sha256_file(tmp_archive)
            if actual_sha != expected_sha:
                raise RuntimeError(
                    f"SHA-256 mismatch for {asset}: "
                    f"expected {expected_sha}, got {actual_sha}."
                )

            installed = _extract_binary(tmp_archive, self._bin_dir)
            installed_digest = _sha256_file(installed)
            installed_digest_path.write_text(f"{installed_digest}\n", encoding="utf-8")

        return installed

    # ------------------------------------------------------------------
    # Tier 1: disk extraction
    # ------------------------------------------------------------------

    def extract_from_disk(
        self,
        disk: str | Path,
        *,
        ntds: bool = False,
        timeout: int = 300,
    ) -> list[Credential]:
        """Extract credentials from a virtual disk image.

        Runs ``vmkatz <disk>`` (plus ``--ntds`` when requested) and returns
        on-disk credentials: SAM NT/LM hashes, LSA secrets, cached domain
        credentials (DCC2), and DPAPI master-key hashes.  When *ntds* is set
        and the disk belongs to a domain controller, the full NTDS.dit hash
        table is extracted instead.

        Supported disk formats:
            ``.vmdk`` (VMware, sparse or flat), ``.qcow2`` (QEMU/Proxmox),
            ``.vhd`` / ``.vhdx`` (Hyper-V), ``.vdi`` (VirtualBox).

        Args:
            disk: Path to the virtual disk.
            ntds: Enable NTDS.dit extraction (domain-controller disk required).
            timeout: Maximum seconds to wait for VMkatz.

        Returns:
            List of :class:`Credential` objects.

        Raises:
            ValueError: If *disk* has an unrecognised extension.
            FileNotFoundError: If the vmkatz binary does not exist.
            subprocess.CalledProcessError: If vmkatz exits non-zero.
            subprocess.TimeoutExpired: If extraction exceeds *timeout* seconds.
        """
        disk = Path(disk)
        _validate_disk_path(disk)

        cmd = [str(self.binary_path()), "--format", "csv"]
        if ntds:
            cmd.append("--ntds")
        cmd.append(str(disk))

        result = subprocess.run(  # noqa: S603
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True,
        )
        return _parse_csv(result.stdout)

    # ------------------------------------------------------------------
    # Tier 2: snapshot (+ optional disk) extraction
    # ------------------------------------------------------------------

    def extract_from_snapshot(
        self,
        snapshot: str | Path,
        *,
        disk: Optional[str | Path] = None,
        ntds: bool = False,
        timeout: int = 300,
    ) -> list[Credential]:
        """Extract credentials from a VM memory snapshot, optionally with a disk.

        Passes the snapshot to VMkatz for live LSASS extraction (NT/LM hashes,
        WDigest plaintext, Kerberos tickets, DPAPI session keys, LSA secrets
        held in memory).  When *disk* is also supplied it is passed as
        ``--disk``; VMkatz uses it to resolve paged-out credentials from the
        snapshot **and** to run the full on-disk extraction (SAM, LSA, DCC2,
        DPAPI, NTDS.dit) in the same pass.

        Supported snapshot formats:
            ``.vmsn`` / ``.vmss`` (VMware Workstation / ESXi),
            ``.vmem`` (raw VMware memory file),
            ``.sav`` (VirtualBox saved state),
            QEMU/KVM savevm state (auto-detected),
            ``.vmrs`` (Hyper-V saved state),
            ``.elf`` (``virsh dump`` ELF core).

        Args:
            snapshot: Path to the VM memory snapshot.
            disk: Optional companion virtual disk for paged-out resolution and
                on-disk extraction.  Supported formats same as
                :meth:`extract_from_disk`.
            ntds: Enable NTDS.dit extraction (requires a DC disk via *disk=*).
            timeout: Maximum seconds to wait for VMkatz.

        Returns:
            List of :class:`Credential` objects.

        Raises:
            ValueError: If *snapshot* has an unrecognised extension, or if
                *disk* is supplied with an unrecognised extension.
            FileNotFoundError: If a supplied path or the vmkatz binary does not
                exist.
            subprocess.CalledProcessError: If vmkatz exits non-zero.
            subprocess.TimeoutExpired: If extraction exceeds *timeout* seconds.
        """
        snapshot = Path(snapshot)
        _validate_snapshot_path(snapshot)

        cmd = [str(self.binary_path()), "--format", "csv"]
        if disk is not None:
            disk = Path(disk)
            _validate_disk_path(disk)
            cmd += ["--disk", str(disk)]
        if ntds:
            cmd.append("--ntds")
        cmd.append(str(snapshot))

        result = subprocess.run(  # noqa: S603
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True,
        )
        return _parse_csv(result.stdout)

    # ------------------------------------------------------------------
    # Low-level passthrough (for callers that need full control)
    # ------------------------------------------------------------------

    def extract(
        self,
        *targets: str | Path,
        disk: Optional[str | Path] = None,
        ntds: bool = False,
        timeout: int = 300,
    ) -> list[Credential]:
        """Low-level passthrough: run VMkatz against arbitrary target paths.

        Prefer :meth:`extract_from_disk` or :meth:`extract_from_snapshot` for
        the standard Revenant workflows.  Use this method only when you need to
        pass targets that do not fit those signatures (e.g. raw registry hives,
        LSASS minidumps, or a VM directory).

        Args:
            *targets: One or more paths passed verbatim to VMkatz.
            disk: Optional ``--disk`` argument for paged-out resolution.
            ntds: Pass ``--ntds`` to VMkatz.
            timeout: Maximum seconds to wait for VMkatz.

        Returns:
            List of :class:`Credential` objects.
        """
        cmd: list[str] = [str(self.binary_path()), "--format", "csv"]
        if disk is not None:
            cmd += ["--disk", str(disk)]
        if ntds:
            cmd.append("--ntds")
        cmd += [str(t) for t in targets]

        result = subprocess.run(  # noqa: S603
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True,
        )
        return _parse_csv(result.stdout)

    def extract_to_dicts(
        self,
        *targets: str | Path,
        disk: Optional[str | Path] = None,
        ntds: bool = False,
        timeout: int = 300,
    ) -> list[dict]:
        """Convenience wrapper around :meth:`extract` that returns plain dicts."""
        return [
            c.as_dict()
            for c in self.extract(
                *targets,
                disk=disk,
                ntds=ntds,
                timeout=timeout,
            )
        ]


# ---------------------------------------------------------------------------
# Path validation helpers
# ---------------------------------------------------------------------------

def _validate_disk_path(path: Path) -> None:
    """Raise :exc:`ValueError` if *path* is not a recognised virtual-disk format."""
    ext = path.suffix.lower()
    if ext not in DISK_EXTENSIONS:
        raise ValueError(
            f"'{path.name}' does not look like a virtual disk "
            f"(expected one of {sorted(DISK_EXTENSIONS)}, got '{ext}'). "
            "Use VMkatz.extract() to pass arbitrary targets."
        )


def _validate_snapshot_path(path: Path) -> None:
    """Raise :exc:`ValueError` if *path* is not a recognised snapshot format."""
    ext = path.suffix.lower()
    if ext not in SNAPSHOT_EXTENSIONS:
        raise ValueError(
            f"'{path.name}' does not look like a VM memory snapshot "
            f"(expected one of {sorted(SNAPSHOT_EXTENSIONS)}, got '{ext}'). "
            "Use VMkatz.extract() to pass arbitrary targets."
        )
