"""Tests for revenant.extract.vmkatz."""

import csv
import io
import os
import platform
import subprocess
import tarfile
import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from revenant.extract.vmkatz import (
    Credential,
    DISK_EXTENSIONS,
    SNAPSHOT_EXTENSIONS,
    VMkatz,
    _asset_name,
    _extract_binary,
    _parse_csv,
    _sha256_file,
    _validate_disk_path,
    _validate_snapshot_path,
    VMKATZ_VERSION,
)


# ---------------------------------------------------------------------------
# Helper CSV builder
# ---------------------------------------------------------------------------

def _make_csv(rows: list[dict]) -> str:
    """Render a list of dicts as a CSV string (with header)."""
    if not rows:
        return ""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue()


# CSV with the standard set of columns
_EMPTY_CSV_HEADER = "type,domain,username,nt_hash,lm_hash,sha1,plaintext\n"


# ---------------------------------------------------------------------------
# _asset_name
# ---------------------------------------------------------------------------

class TestAssetName:
    def test_linux_x86_64(self):
        with patch("platform.system", return_value="Linux"), \
             patch("platform.machine", return_value="x86_64"):
            name = _asset_name()
        assert name == f"vmkatz-v{VMKATZ_VERSION}-linux-x86_64.tar.gz"

    def test_linux_aarch64(self):
        with patch("platform.system", return_value="Linux"), \
             patch("platform.machine", return_value="aarch64"):
            name = _asset_name()
        assert name == f"vmkatz-v{VMKATZ_VERSION}-linux-aarch64.tar.gz"

    def test_macos_aarch64(self):
        with patch("platform.system", return_value="Darwin"), \
             patch("platform.machine", return_value="arm64"):
            name = _asset_name()
        assert name == f"vmkatz-v{VMKATZ_VERSION}-macos-aarch64.tar.gz"

    def test_windows_x86_64(self):
        with patch("platform.system", return_value="Windows"), \
             patch("platform.machine", return_value="AMD64"):
            name = _asset_name()
        assert name == f"vmkatz-v{VMKATZ_VERSION}-windows-x86_64.zip"

    def test_unsupported_arch_raises(self):
        with patch("platform.system", return_value="Linux"), \
             patch("platform.machine", return_value="mips64"):
            with pytest.raises(RuntimeError, match="Unsupported CPU architecture"):
                _asset_name()

    def test_unsupported_os_raises(self):
        with patch("platform.system", return_value="FreeBSD"), \
             patch("platform.machine", return_value="x86_64"):
            with pytest.raises(RuntimeError, match="Unsupported OS"):
                _asset_name()


# ---------------------------------------------------------------------------
# _sha256_file
# ---------------------------------------------------------------------------

class TestSha256File:
    def test_known_digest(self, tmp_path):
        import hashlib
        data = b"hello vmkatz"
        p = tmp_path / "data.bin"
        p.write_bytes(data)
        expected = hashlib.sha256(data).hexdigest()
        assert _sha256_file(p) == expected


class TestExtractBinary:
    def test_extracts_vmkatz_from_tar_without_unpacking_other_members(self, tmp_path):
        archive = tmp_path / "vmkatz.tar.gz"
        with tarfile.open(archive, "w:gz") as tf:
            nested = tmp_path / "nested_vmkatz"
            nested.write_bytes(b"vmkatz-bytes")
            tf.add(nested, arcname="nested/path/vmkatz")

            other = tmp_path / "other_file"
            other.write_bytes(b"ignored")
            tf.add(other, arcname="../../evil")

        dest = tmp_path / "bin"
        installed = _extract_binary(archive, dest)
        assert installed == dest / "vmkatz"
        assert installed.read_bytes() == b"vmkatz-bytes"
        assert not (tmp_path / "evil").exists()


# ---------------------------------------------------------------------------
# Path validation
# ---------------------------------------------------------------------------

class TestValidateDiskPath:
    @pytest.mark.parametrize("name", ["disk.vmdk", "image.qcow2", "win.vhd",
                                       "win.vhdx", "box.vdi"])
    def test_valid_extensions_accepted(self, name):
        _validate_disk_path(Path(name))  # must not raise

    def test_invalid_extension_raises(self):
        with pytest.raises(ValueError, match="virtual disk"):
            _validate_disk_path(Path("snapshot.vmsn"))

    def test_plain_filename_no_ext_raises(self):
        with pytest.raises(ValueError, match="virtual disk"):
            _validate_disk_path(Path("SAM"))


class TestValidateSnapshotPath:
    @pytest.mark.parametrize("name", ["snap.vmsn", "snap.vmss", "mem.vmem",
                                       "state.sav", "saved.vmrs", "dump.elf"])
    def test_valid_extensions_accepted(self, name):
        _validate_snapshot_path(Path(name))  # must not raise

    def test_invalid_extension_raises(self):
        with pytest.raises(ValueError, match="memory snapshot"):
            _validate_snapshot_path(Path("disk.vmdk"))


# ---------------------------------------------------------------------------
# _parse_csv
# ---------------------------------------------------------------------------

class TestParseCsv:
    def test_empty_input_returns_empty_list(self):
        assert _parse_csv("") == []

    def test_single_msv_row(self):
        csv_text = _make_csv([
            {
                "type": "msv",
                "domain": "CORP",
                "username": "alice",
                "nt_hash": "aad3b435b51404eeaad3b435b51404ee",
                "lm_hash": "",
                "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                "plaintext": "",
            }
        ])
        creds = _parse_csv(csv_text)
        assert len(creds) == 1
        c = creds[0]
        assert c.cred_type == "msv"
        assert c.domain == "CORP"
        assert c.username == "alice"
        assert c.nt_hash == "aad3b435b51404eeaad3b435b51404ee"
        assert c.lm_hash is None   # empty string → None
        assert c.plaintext is None

    def test_wdigest_plaintext(self):
        csv_text = _make_csv([
            {
                "type": "wdigest",
                "domain": "WORKGROUP",
                "username": "bob",
                "nt_hash": "",
                "lm_hash": "",
                "sha1": "",
                "plaintext": "P@ssw0rd!",
            }
        ])
        creds = _parse_csv(csv_text)
        assert creds[0].plaintext == "P@ssw0rd!"

    def test_multiple_rows(self):
        rows = [
            {
                "type": "msv", "domain": "D", "username": f"user{i}",
                "nt_hash": "aa" * 16, "lm_hash": "", "sha1": "", "plaintext": "",
            }
            for i in range(5)
        ]
        creds = _parse_csv(_make_csv(rows))
        assert len(creds) == 5

    def test_extra_columns_captured(self):
        rows = [
            {
                "type": "kerberos",
                "domain": "CORP",
                "username": "svc",
                "nt_hash": "",
                "lm_hash": "",
                "sha1": "",
                "plaintext": "",
                "ticket_file": "/tmp/svc.kirbi",
            }
        ]
        creds = _parse_csv(_make_csv(rows))
        assert creds[0].extra.get("ticket_file") == "/tmp/svc.kirbi"


# ---------------------------------------------------------------------------
# Credential.as_dict
# ---------------------------------------------------------------------------

class TestCredentialAsDict:
    def test_none_fields_omitted(self):
        c = Credential(cred_type="msv", username="alice", nt_hash="aabbccdd")
        d = c.as_dict()
        assert "domain" not in d
        assert d["username"] == "alice"
        assert d["nt_hash"] == "aabbccdd"

    def test_extra_merged(self):
        c = Credential(cred_type="dpapi", extra={"master_key": "deadbeef"})
        d = c.as_dict()
        assert d["master_key"] == "deadbeef"


# ---------------------------------------------------------------------------
# VMkatz — binary management
# ---------------------------------------------------------------------------

class TestVMkatzBinaryPath:
    def test_explicit_binary_path_used(self, tmp_path):
        fake_bin = tmp_path / "vmkatz"
        fake_bin.touch()
        vmk = VMkatz(binary_path=fake_bin)
        assert vmk.binary_path() == fake_bin

    def test_explicit_binary_missing_raises(self, tmp_path):
        missing = tmp_path / "vmkatz"
        vmk = VMkatz(binary_path=missing)
        with pytest.raises(FileNotFoundError):
            vmk.binary_path()

    def test_env_var_overrides(self, tmp_path, monkeypatch):
        fake_bin = tmp_path / "vmkatz"
        fake_bin.touch()
        monkeypatch.setenv("VMKATZ_BIN", str(fake_bin))
        vmk = VMkatz()
        assert vmk.binary_path() == fake_bin

    def test_env_var_missing_raises(self, tmp_path, monkeypatch):
        monkeypatch.setenv("VMKATZ_BIN", str(tmp_path / "no_such_file"))
        vmk = VMkatz()
        with pytest.raises(FileNotFoundError):
            vmk.binary_path()


# ---------------------------------------------------------------------------
# VMkatz.ensure_binary — no real network
# ---------------------------------------------------------------------------

class TestVMkatzEnsureBinary:
    def test_skips_download_when_binary_already_set(self, tmp_path):
        """When binary_path is set and exists, ensure_binary returns immediately."""
        fake_bin = tmp_path / "vmkatz"
        fake_bin.touch()
        vmk = VMkatz(binary_path=fake_bin)
        # ensure_binary must not make any network calls.
        with patch("urllib.request.urlopen") as mock_url:
            result = vmk.ensure_binary()
        mock_url.assert_not_called()
        assert result == fake_bin

    def test_already_installed_matching_digest_skips_download(self, tmp_path):
        """If the installed binary already has the expected digest, no download."""
        fake_bin = tmp_path / "vmkatz"
        fake_bin.write_bytes(b"fake-binary-content")
        import hashlib
        digest = hashlib.sha256(b"fake-binary-content").hexdigest()
        (tmp_path / "vmkatz.sha256").write_text(f"{digest}\n", encoding="utf-8")

        vmk = VMkatz(bin_dir=tmp_path)

        with patch("revenant.extract.vmkatz._fetch_expected_sha256", return_value=digest):
            result = vmk.ensure_binary()

        assert result == fake_bin

    def test_missing_binary_triggers_download(self, tmp_path):
        """A missing binary triggers download + extraction."""
        expected_digest = "abc123"
        archive_content = b"fake-archive"

        vmk = VMkatz(bin_dir=tmp_path)

        with patch("revenant.extract.vmkatz._fetch_expected_sha256", return_value=expected_digest), \
             patch("revenant.extract.vmkatz._sha256_file", return_value=expected_digest), \
             patch("urllib.request.urlopen") as mock_url, \
             patch("revenant.extract.vmkatz._extract_binary") as mock_extract:

            # Simulate urlopen context manager returning archive bytes
            mock_resp = MagicMock()
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_resp.read.return_value = archive_content
            mock_url.return_value = mock_resp

            fake_installed = tmp_path / "vmkatz"
            mock_extract.return_value = fake_installed

            vmk.ensure_binary()

        mock_extract.assert_called_once()


# ---------------------------------------------------------------------------
# VMkatz.extract_from_disk — primary disk workflow
# ---------------------------------------------------------------------------

class TestExtractFromDisk:
    """Tests for the primary virtual-disk extraction workflow."""

    def _vmk(self, tmp_path) -> tuple[VMkatz, Path]:
        fake_bin = tmp_path / "vmkatz"
        fake_bin.touch()
        return VMkatz(binary_path=fake_bin), fake_bin

    def test_vmdk_basic(self, tmp_path):
        vmk, fake_bin = self._vmk(tmp_path)
        csv_out = _make_csv([
            {"type": "sam", "domain": "WORKGROUP", "username": "Administrator",
             "nt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
             "lm_hash": "", "sha1": "", "plaintext": ""}
        ])
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=csv_out, returncode=0)
            creds = vmk.extract_from_disk("disk.vmdk")

        cmd = mock_run.call_args[0][0]
        assert str(fake_bin) in cmd
        assert "--format" in cmd
        assert "csv" in cmd
        assert "disk.vmdk" in cmd
        assert "--ntds" not in cmd
        assert "--disk" not in cmd
        assert len(creds) == 1
        assert creds[0].username == "Administrator"

    @pytest.mark.parametrize("disk_name", [
        "image.qcow2", "win.vhd", "win.vhdx", "box.vdi"
    ])
    def test_supported_disk_formats(self, tmp_path, disk_name):
        vmk, _ = self._vmk(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=_EMPTY_CSV_HEADER, returncode=0)
            vmk.extract_from_disk(disk_name)
        cmd = mock_run.call_args[0][0]
        assert disk_name in cmd

    def test_ntds_flag_passed(self, tmp_path):
        vmk, _ = self._vmk(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=_EMPTY_CSV_HEADER, returncode=0)
            vmk.extract_from_disk("dc.vmdk", ntds=True)
        cmd = mock_run.call_args[0][0]
        assert "--ntds" in cmd

    def test_invalid_extension_raises_before_subprocess(self, tmp_path):
        vmk, _ = self._vmk(tmp_path)
        with patch("subprocess.run") as mock_run:
            with pytest.raises(ValueError, match="virtual disk"):
                vmk.extract_from_disk("snapshot.vmsn")
        mock_run.assert_not_called()

    def test_lsa_and_dcc2_creds_returned(self, tmp_path):
        vmk, _ = self._vmk(tmp_path)
        csv_out = _make_csv([
            {"type": "sam",  "domain": "CORP", "username": "alice",
             "nt_hash": "aa" * 16, "lm_hash": "", "sha1": "", "plaintext": ""},
            {"type": "lsa",  "domain": "CORP", "username": "_svc",
             "nt_hash": "bb" * 16, "lm_hash": "", "sha1": "", "plaintext": ""},
            {"type": "dcc2", "domain": "CORP", "username": "bob",
             "nt_hash": "cc" * 16, "lm_hash": "", "sha1": "", "plaintext": ""},
        ])
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=csv_out, returncode=0)
            creds = vmk.extract_from_disk("disk.vmdk")
        assert len(creds) == 3
        types = {c.cred_type for c in creds}
        assert types == {"sam", "lsa", "dcc2"}

    def test_nonzero_exit_raises(self, tmp_path):
        vmk, _ = self._vmk(tmp_path)
        with patch("subprocess.run", side_effect=subprocess.CalledProcessError(1, "vmkatz")):
            with pytest.raises(subprocess.CalledProcessError):
                vmk.extract_from_disk("disk.vmdk")

    def test_timeout_raises(self, tmp_path):
        vmk, _ = self._vmk(tmp_path)
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("vmkatz", 1)):
            with pytest.raises(subprocess.TimeoutExpired):
                vmk.extract_from_disk("disk.vmdk", timeout=1)


# ---------------------------------------------------------------------------
# VMkatz.extract_from_snapshot — snapshot (+ disk) workflow
# ---------------------------------------------------------------------------

class TestExtractFromSnapshot:

    def _vmk(self, tmp_path) -> tuple[VMkatz, Path]:
        fake_bin = tmp_path / "vmkatz"
        fake_bin.touch()
        return VMkatz(binary_path=fake_bin), fake_bin

    def test_vmsn_without_disk(self, tmp_path):
        vmk, fake_bin = self._vmk(tmp_path)
        csv_out = _make_csv([
            {"type": "msv", "domain": "CORP", "username": "alice",
             "nt_hash": "aa" * 16, "lm_hash": "", "sha1": "", "plaintext": ""}
        ])
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=csv_out, returncode=0)
            creds = vmk.extract_from_snapshot("snap.vmsn")

        cmd = mock_run.call_args[0][0]
        assert "snap.vmsn" in cmd
        assert "--disk" not in cmd
        assert len(creds) == 1

    def test_vmsn_with_disk(self, tmp_path):
        vmk, _ = self._vmk(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=_EMPTY_CSV_HEADER, returncode=0)
            vmk.extract_from_snapshot("snap.vmsn", disk="disk.vmdk")

        cmd = mock_run.call_args[0][0]
        assert "--disk" in cmd
        idx = cmd.index("--disk")
        assert cmd[idx + 1] == "disk.vmdk"
        assert "snap.vmsn" in cmd

    def test_vmem_with_disk(self, tmp_path):
        """Raw VMware memory file + disk — paged-out resolution path."""
        vmk, _ = self._vmk(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=_EMPTY_CSV_HEADER, returncode=0)
            vmk.extract_from_snapshot("memory.vmem", disk="disk.vmdk")

        cmd = mock_run.call_args[0][0]
        assert "memory.vmem" in cmd
        assert "--disk" in cmd

    @pytest.mark.parametrize("snap_name", [
        "snap.vmsn", "snap.vmss", "mem.vmem", "state.sav", "saved.vmrs", "dump.elf"
    ])
    def test_supported_snapshot_formats(self, tmp_path, snap_name):
        vmk, _ = self._vmk(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=_EMPTY_CSV_HEADER, returncode=0)
            vmk.extract_from_snapshot(snap_name)
        cmd = mock_run.call_args[0][0]
        assert snap_name in cmd

    def test_invalid_snapshot_extension_raises(self, tmp_path):
        vmk, _ = self._vmk(tmp_path)
        with patch("subprocess.run") as mock_run:
            with pytest.raises(ValueError, match="memory snapshot"):
                vmk.extract_from_snapshot("disk.vmdk")
        mock_run.assert_not_called()

    def test_invalid_disk_extension_raises(self, tmp_path):
        vmk, _ = self._vmk(tmp_path)
        with patch("subprocess.run") as mock_run:
            with pytest.raises(ValueError, match="virtual disk"):
                vmk.extract_from_snapshot("snap.vmsn", disk="also_a_snap.vmsn")
        mock_run.assert_not_called()

    def test_ntds_flag_passed(self, tmp_path):
        vmk, _ = self._vmk(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=_EMPTY_CSV_HEADER, returncode=0)
            vmk.extract_from_snapshot("snap.vmsn", disk="dc.vmdk", ntds=True)
        cmd = mock_run.call_args[0][0]
        assert "--ntds" in cmd

    def test_wdigest_and_kerberos_from_snapshot(self, tmp_path):
        vmk, _ = self._vmk(tmp_path)
        csv_out = _make_csv([
            {"type": "wdigest", "domain": "CORP", "username": "alice",
             "nt_hash": "", "lm_hash": "", "sha1": "", "plaintext": "P@ss1"},
            {"type": "kerberos", "domain": "CORP", "username": "alice",
             "nt_hash": "", "lm_hash": "", "sha1": "", "plaintext": ""},
        ])
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=csv_out, returncode=0)
            creds = vmk.extract_from_snapshot("snap.vmsn", disk="disk.vmdk")
        types = {c.cred_type for c in creds}
        assert "wdigest" in types
        assert "kerberos" in types
        plaintext_creds = [c for c in creds if c.plaintext]
        assert plaintext_creds[0].plaintext == "P@ss1"


# ---------------------------------------------------------------------------
# VMkatz.extract — low-level passthrough
# ---------------------------------------------------------------------------

class TestVMkatzExtract:
    """Tests for the low-level extract() passthrough."""

    def _vmk_with_fake_bin(self, tmp_path) -> tuple[VMkatz, Path]:
        fake_bin = tmp_path / "vmkatz"
        fake_bin.touch()
        return VMkatz(binary_path=fake_bin), fake_bin

    def test_basic_invocation(self, tmp_path):
        vmk, fake_bin = self._vmk_with_fake_bin(tmp_path)
        csv_out = _make_csv([
            {"type": "msv", "domain": "CORP", "username": "alice",
             "nt_hash": "aa" * 16, "lm_hash": "", "sha1": "", "plaintext": ""}
        ])

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=csv_out, returncode=0)
            creds = vmk.extract("snapshot.vmsn")

        call_args = mock_run.call_args[0][0]
        assert str(fake_bin) in call_args
        assert "--format" in call_args
        assert "csv" in call_args
        assert "snapshot.vmsn" in call_args
        assert len(creds) == 1
        assert creds[0].username == "alice"

    def test_disk_flag_passed(self, tmp_path):
        vmk, _ = self._vmk_with_fake_bin(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=_EMPTY_CSV_HEADER, returncode=0)
            vmk.extract("snap.vmsn", disk="disk.vmdk")

        cmd = mock_run.call_args[0][0]
        assert "--disk" in cmd
        idx = cmd.index("--disk")
        assert cmd[idx + 1] == "disk.vmdk"

    def test_ntds_flag_passed(self, tmp_path):
        vmk, _ = self._vmk_with_fake_bin(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=_EMPTY_CSV_HEADER, returncode=0)
            vmk.extract("dc.qcow2", ntds=True)

        cmd = mock_run.call_args[0][0]
        assert "--ntds" in cmd

    def test_multiple_targets(self, tmp_path):
        vmk, _ = self._vmk_with_fake_bin(tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=_EMPTY_CSV_HEADER, returncode=0)
            vmk.extract("SAM", "SYSTEM", "SECURITY")

        cmd = mock_run.call_args[0][0]
        assert "SAM" in cmd
        assert "SYSTEM" in cmd
        assert "SECURITY" in cmd

    def test_nonzero_exit_raises(self, tmp_path):
        vmk, _ = self._vmk_with_fake_bin(tmp_path)

        with patch("subprocess.run", side_effect=subprocess.CalledProcessError(1, "vmkatz")):
            with pytest.raises(subprocess.CalledProcessError):
                vmk.extract("snapshot.vmsn")

    def test_timeout_raises(self, tmp_path):
        vmk, _ = self._vmk_with_fake_bin(tmp_path)

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("vmkatz", 1)):
            with pytest.raises(subprocess.TimeoutExpired):
                vmk.extract("snapshot.vmsn", timeout=1)

    def test_extract_to_dicts(self, tmp_path):
        vmk, _ = self._vmk_with_fake_bin(tmp_path)
        csv_out = _make_csv([
            {"type": "msv", "domain": "D", "username": "u",
             "nt_hash": "bb" * 16, "lm_hash": "", "sha1": "", "plaintext": ""}
        ])

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=csv_out, returncode=0)
            dicts = vmk.extract_to_dicts("snap.vmsn")

        assert isinstance(dicts, list)
        assert isinstance(dicts[0], dict)
        assert dicts[0]["username"] == "u"


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------

class TestCli:
    def test_no_args_prints_help(self, capsys):
        from revenant.cli import main
        rc = main([])
        assert rc == 0

    def test_extract_without_mode_prints_extract_help(self, capsys):
        from revenant.cli import main
        rc = main(["extract"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "Extract Windows credentials" in out

    def test_extract_disk_json(self, tmp_path, capsys):
        fake_bin = tmp_path / "vmkatz"
        fake_bin.touch()
        csv_out = _make_csv([
            {"type": "sam", "domain": "LAB", "username": "testuser",
             "nt_hash": "cc" * 16, "lm_hash": "", "sha1": "", "plaintext": ""}
        ])
        from revenant.cli import main
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=csv_out, returncode=0)
            rc = main([
                "extract", "disk",
                "--vmkatz-bin", str(fake_bin),
                "--no-download",
                "disk.vmdk",
            ])
        assert rc == 0
        out = capsys.readouterr().out
        data = __import__("json").loads(out)
        assert data[0]["username"] == "testuser"

    def test_extract_disk_pwdump(self, tmp_path, capsys):
        fake_bin = tmp_path / "vmkatz"
        fake_bin.touch()
        csv_out = _make_csv([
            {"type": "sam", "domain": "LAB", "username": "admin",
             "nt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
             "lm_hash": "", "sha1": "", "plaintext": ""},
            {"type": "wdigest", "domain": "LAB", "username": "admin",
             "nt_hash": "", "lm_hash": "", "sha1": "", "plaintext": "Password123!"},
            {"type": "sam", "domain": "LAB", "username": "",
             "nt_hash": "aa" * 16, "lm_hash": "", "sha1": "", "plaintext": ""},
        ])
        from revenant.cli import main
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=csv_out, returncode=0)
            rc = main([
                "extract", "disk",
                "--vmkatz-bin", str(fake_bin),
                "--no-download",
                "--format", "pwdump",
                "disk.vmdk",
            ])
        assert rc == 0
        out = capsys.readouterr().out
        assert "admin" in out
        assert "31d6cfe0d16ae931b73c59d7e0c089c0" in out
        assert out.count("\n") == 1

    def test_extract_snapshot_with_disk(self, tmp_path, capsys):
        fake_bin = tmp_path / "vmkatz"
        fake_bin.touch()
        csv_out = _make_csv([
            {"type": "msv", "domain": "CORP", "username": "alice",
             "nt_hash": "dd" * 16, "lm_hash": "", "sha1": "", "plaintext": ""}
        ])
        from revenant.cli import main
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=csv_out, returncode=0)
            rc = main([
                "extract", "snapshot",
                "--vmkatz-bin", str(fake_bin),
                "--no-download",
                "--disk", "disk.vmdk",
                "snap.vmsn",
            ])
        assert rc == 0
        cmd = mock_run.call_args[0][0]
        assert "--disk" in cmd
        assert "disk.vmdk" in cmd
        assert "snap.vmsn" in cmd

    def test_extract_snapshot_without_disk(self, tmp_path, capsys):
        fake_bin = tmp_path / "vmkatz"
        fake_bin.touch()
        from revenant.cli import main
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=_EMPTY_CSV_HEADER, returncode=0)
            rc = main([
                "extract", "snapshot",
                "--vmkatz-bin", str(fake_bin),
                "--no-download",
                "snap.vmem",
            ])
        assert rc == 0
        cmd = mock_run.call_args[0][0]
        assert "--disk" not in cmd

    def test_extract_disk_invalid_extension_returns_error(self, tmp_path, capsys):
        fake_bin = tmp_path / "vmkatz"
        fake_bin.touch()
        from revenant.cli import main
        rc = main([
            "extract", "disk",
            "--vmkatz-bin", str(fake_bin),
            "--no-download",
            "not_a_disk.txt",
        ])
        assert rc == 1
        err = capsys.readouterr().err
        assert "revenant:" in err

    def test_extract_missing_binary_returns_error(self, tmp_path, capsys):
        from revenant.cli import main
        rc = main([
            "extract", "disk",
            "--vmkatz-bin", str(tmp_path / "no_such_vmkatz"),
            "--no-download",
            "disk.vmdk",
        ])
        assert rc == 1
        err = capsys.readouterr().err
        assert "revenant:" in err
