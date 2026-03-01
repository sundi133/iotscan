"""Tests for the credential checker module."""

from unittest.mock import patch

from iotscan.models import Target
from iotscan.modules.credential_checker import CredentialChecker, DEFAULT_CREDENTIALS


def test_credential_checker_no_open_ports():
    """When no ports are open, there should be no critical findings."""
    target = Target(host="192.168.1.1")
    scanner = CredentialChecker(target=target)

    with patch.object(scanner, "_is_port_open", return_value=False):
        result = scanner.run()

    critical_findings = [f for f in result.findings if f.severity.value == "critical"]
    assert len(critical_findings) == 0


def test_credential_database_populated():
    """Verify the default credential database has entries for major vendors."""
    vendors = {c["vendor"] for c in DEFAULT_CREDENTIALS}
    assert "Hikvision" in vendors
    assert "TP-Link" in vendors
    assert "Ubiquiti" in vendors
    assert "Generic" in vendors
    assert len(DEFAULT_CREDENTIALS) >= 30


def test_credential_checker_telnet_finding():
    """When telnet port 23 is open, it should generate a high finding."""
    target = Target(host="192.168.1.1")
    scanner = CredentialChecker(target=target)

    def fake_port_open(host, port):
        return port == 23

    with patch.object(scanner, "_is_port_open", side_effect=fake_port_open):
        with patch.object(scanner, "_check_telnet") as mock_telnet:
            result = scanner.run()
            mock_telnet.assert_called_once_with("192.168.1.1", 23)
