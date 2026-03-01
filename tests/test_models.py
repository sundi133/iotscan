"""Tests for core data models."""

from iotscan.models import Finding, ScanResult, ScanStatus, Severity, Target


def test_finding_to_dict():
    f = Finding(
        title="Test finding",
        severity=Severity.HIGH,
        module="test",
        description="A test finding",
        evidence="some evidence",
        remediation="fix it",
        cve="CVE-2024-0001",
    )
    d = f.to_dict()
    assert d["title"] == "Test finding"
    assert d["severity"] == "high"
    assert d["module"] == "test"
    assert d["cve"] == "CVE-2024-0001"


def test_scan_result_add_finding():
    target = Target(host="192.168.1.1")
    result = ScanResult(target=target, module_name="test")
    assert len(result.findings) == 0

    result.add_finding(Finding(
        title="Critical bug",
        severity=Severity.CRITICAL,
        module="test",
        description="desc",
    ))
    result.add_finding(Finding(
        title="Info note",
        severity=Severity.INFO,
        module="test",
        description="desc",
    ))
    assert len(result.findings) == 2
    assert result.critical_count == 1
    assert result.high_count == 0


def test_scan_result_to_dict():
    target = Target(host="10.0.0.1", port=1883)
    result = ScanResult(target=target, module_name="mqtt_test", status=ScanStatus.COMPLETED)
    result.add_finding(Finding(
        title="Open broker",
        severity=Severity.CRITICAL,
        module="mqtt_test",
        description="Broker open",
    ))
    d = result.to_dict()
    assert d["target"] == "10.0.0.1"
    assert d["module"] == "mqtt_test"
    assert d["status"] == "completed"
    assert d["summary"]["total"] == 1
    assert d["summary"]["critical"] == 1


def test_target_defaults():
    t = Target(host="example.com")
    assert t.port == 0
    assert t.protocol == ""
    assert t.firmware_path == ""
    assert t.metadata == {}
