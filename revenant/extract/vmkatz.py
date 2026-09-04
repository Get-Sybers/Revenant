"""VMkatz binary manager and credential-extraction wrapper.

VMkatz (https://github.com/nikaiw/VMkatz) is a static binary that extracts
Windows credentials — NTLM hashes, Kerberos tickets, cached domain creds,
LSA secrets, DPAPI master keys, NTDS.dit, BitLocker keys — directly from VM
memory snapshots and virtual disks without pulling the full image.

This module:
  1. Downloads the pinned VMkatz release for the current platform on first use.
  2. Verifies the SHA-256 digest against the upstream SHA256SUMS release asset.
  3. Invokes the binary and returns credentials as a list of plain dicts.

Typical usage inside the Revenant CLI::

    from revenant.extract.vmkatz import VMkatz

    vmk = VMkatz()
    vmk.ensure_binary()          # idempotent: no-op if binary is current
    creds = vmk.extract("snapshot.vmsn")
    # creds → [{"type": "msv", "domain": "CORP", "user": "alice",
    #           "nt_hash": "...", ...}, ...]
"""

import csv
import hashlib
import io
import os
import platform
import shutil
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
        ext = "tar.gz"
        return f"vmkatz-v{VMKATZ_VERSION}-linux-{arch}.{ext}"
    if system == "darwin":
        ext = "tar.gz"
        return f"vmkatz-v{VMKATZ_VERSION}-macos-{arch}.{ext}"
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
            bin_member.name = "vmkatz"
            tf.extract(bin_member, path=dest_dir)
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

    Args:
        bin_dir: Directory where the vmkatz binary is stored.  Defaults to
            ``~/.local/share/revenant/bin`` (XDG_DATA_HOME honoured).
        binary_path: Explicit path to an already-installed vmkatz binary.
            When set, *bin_dir* is ignored and no download is attempted.
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

    def binary_path(self) -> Path:
        """Return the path to the vmkatz binary (download if necessary)."""
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
        asset = _asset_name()
        expected_sha = _fetch_expected_sha256(asset)

        # Already installed and digest still matches — nothing to do.
        if installed.exists() and _sha256_file(installed) == expected_sha:
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

        return installed

    # ------------------------------------------------------------------
    # Extraction
    # ------------------------------------------------------------------

    def extract(
        self,
        *targets: str | Path,
        disk: Optional[str | Path] = None,
        ntds: bool = False,
        timeout: int = 300,
    ) -> list[Credential]:
        """Run VMkatz against one or more VM artefacts and return credentials.

        Args:
            *targets: One or more paths to VM artefacts — memory snapshots
                (``.vmsn``, ``.vmem``, ``.sav``, QEMU savevm), virtual disks
                (``.vmdk``, ``.qcow2``, ``.vhd``, ``.vhdx``, ``.vdi``), raw
                registry hives (``SAM``, ``SYSTEM``, ``SECURITY``), LSASS
                minidumps (``.dmp``), or a VM directory.
            disk: Optional companion virtual-disk path; passed as
                ``--disk`` to resolve paged-out credentials from memory.
            ntds: Pass ``--ntds`` to enable NTDS.dit extraction from a domain
                controller disk (requires a DC disk as one of *targets*).
            timeout: Maximum seconds to wait for vmkatz to finish.

        Returns:
            List of :class:`Credential` objects, one per extracted entry.

        Raises:
            FileNotFoundError: If the vmkatz binary is absent.
            subprocess.CalledProcessError: If vmkatz exits with a non-zero
                status.
            subprocess.TimeoutExpired: If extraction exceeds *timeout* seconds.
        """
        binary = self.binary_path()

        cmd: list[str] = [str(binary), "--format", "csv"]
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
        """Convenience wrapper that returns plain dicts instead of dataclasses."""
        return [
            c.as_dict()
            for c in self.extract(
                *targets,
                disk=disk,
                ntds=ntds,
                timeout=timeout,
            )
        ]
