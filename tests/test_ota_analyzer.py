"""Tests for the OTA update mechanism analyzer."""

from iotscan.models import Severity, Target
from iotscan.modules.ota_analyzer import OTAAnalyzer


def test_ota_http_update_url():
    target = Target(host="192.168.1.1")
    config = {"ota": {"update_url": "http://updates.example.com/firmware.bin"}}
    scanner = OTAAnalyzer(target=target, config=config)
    result = scanner.run()

    http_findings = [
        f for f in result.findings if "unencrypted HTTP" in f.title
    ]
    assert len(http_findings) == 1
    assert http_findings[0].severity == Severity.CRITICAL


def test_ota_no_signing():
    target = Target(host="192.168.1.1")
    config = {"ota": {"signing_method": "none"}}
    scanner = OTAAnalyzer(target=target, config=config)
    result = scanner.run()

    signing_findings = [
        f for f in result.findings if "not cryptographically signed" in f.title
    ]
    assert len(signing_findings) == 1
    assert signing_findings[0].severity == Severity.CRITICAL


def test_ota_weak_signing():
    target = Target(host="192.168.1.1")
    config = {"ota": {"signing_method": "md5"}}
    scanner = OTAAnalyzer(target=target, config=config)
    result = scanner.run()

    weak_findings = [
        f for f in result.findings if "weak integrity" in f.title.lower()
    ]
    assert len(weak_findings) == 1


def test_ota_no_rollback():
    target = Target(host="192.168.1.1")
    config = {"ota": {"rollback_protection": False, "secure_boot": False}}
    scanner = OTAAnalyzer(target=target, config=config)
    result = scanner.run()

    rollback_findings = [f for f in result.findings if "rollback" in f.title.lower()]
    assert len(rollback_findings) == 1

    boot_findings = [f for f in result.findings if "secure boot" in f.title.lower()]
    assert len(boot_findings) == 1


def test_ota_strong_signing():
    target = Target(host="192.168.1.1")
    config = {"ota": {"signing_method": "ed25519"}}
    scanner = OTAAnalyzer(target=target, config=config)
    result = scanner.run()

    signing_findings = [
        f for f in result.findings if "signing verified" in f.title.lower()
    ]
    assert len(signing_findings) == 1
    assert signing_findings[0].severity == Severity.INFO
