"""Tests for the firmware analysis module."""

import tempfile
from pathlib import Path

from iotscan.models import Severity, Target
from iotscan.modules.firmware_analysis import FirmwareAnalyzer


def test_firmware_no_path():
    target = Target(host="192.168.1.1")
    scanner = FirmwareAnalyzer(target=target)
    result = scanner.run()
    assert any("No firmware path" in f.title for f in result.findings)


def test_firmware_file_not_found():
    target = Target(host="192.168.1.1", firmware_path="/nonexistent/firmware.bin")
    scanner = FirmwareAnalyzer(target=target)
    result = scanner.run()
    assert any("not found" in f.title for f in result.findings)


def test_firmware_hardcoded_password():
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(b"\x00" * 100)
        f.write(b'password = "SuperSecret123"\n')
        f.write(b"\x00" * 100)
        f.flush()

        target = Target(host="192.168.1.1", firmware_path=f.name)
        scanner = FirmwareAnalyzer(target=target)
        result = scanner.run()

        password_findings = [
            finding for finding in result.findings
            if "password" in finding.title.lower() or "Hardcoded" in finding.title
        ]
        assert len(password_findings) > 0

    Path(f.name).unlink(missing_ok=True)


def test_firmware_private_key():
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(b"\x00" * 50)
        f.write(b"-----BEGIN RSA PRIVATE KEY-----\n")
        f.write(b"MIIEpAIBAAKCAQEA...\n")
        f.write(b"-----END RSA PRIVATE KEY-----\n")
        f.write(b"\x00" * 50)
        f.flush()

        target = Target(host="192.168.1.1", firmware_path=f.name)
        scanner = FirmwareAnalyzer(target=target)
        result = scanner.run()

        key_findings = [
            f for f in result.findings if "private key" in f.title.lower()
        ]
        assert len(key_findings) > 0
        assert key_findings[0].severity == Severity.CRITICAL

    Path(f.name).unlink(missing_ok=True)


def test_firmware_unsafe_functions():
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(b"\x00" * 50)
        f.write(b"strcpy\x00sprintf\x00gets\x00")
        f.write(b"\x00" * 50)
        f.flush()

        target = Target(host="192.168.1.1", firmware_path=f.name)
        scanner = FirmwareAnalyzer(target=target)
        result = scanner.run()

        unsafe_findings = [
            f for f in result.findings if "unsafe" in f.title.lower()
        ]
        assert len(unsafe_findings) > 0

    Path(f.name).unlink(missing_ok=True)


def test_firmware_squashfs_header():
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        # SquashFS little-endian magic
        f.write(b"hsqs" + b"\x00" * 508)
        f.flush()

        target = Target(host="192.168.1.1", firmware_path=f.name)
        scanner = FirmwareAnalyzer(target=target)
        result = scanner.run()

        section_findings = [
            f for f in result.findings if "sections identified" in f.title.lower()
        ]
        assert len(section_findings) > 0

    Path(f.name).unlink(missing_ok=True)


def test_firmware_vulnerable_library():
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(b"\x00" * 50)
        f.write(b"BusyBox v1.30.0")
        f.write(b"\x00" * 50)
        f.flush()

        target = Target(host="192.168.1.1", firmware_path=f.name)
        scanner = FirmwareAnalyzer(target=target)
        result = scanner.run()

        vuln_findings = [
            f for f in result.findings if "busybox" in f.title.lower()
        ]
        assert len(vuln_findings) > 0

    Path(f.name).unlink(missing_ok=True)
