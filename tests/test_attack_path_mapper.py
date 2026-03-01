"""Tests for the attack path mapper module."""

from unittest.mock import patch

from iotscan.models import Severity, Target
from iotscan.modules.attack_path_mapper import AttackNode, AttackPath, AttackPathMapper


def test_attack_node_to_dict():
    node = AttackNode(
        name="device:192.168.1.1",
        node_type="device",
        risk_level="high",
        vulnerabilities=["telnet_exposed"],
        connections=["gateway:192.168.1.254"],
    )
    d = node.to_dict()
    assert d["name"] == "device:192.168.1.1"
    assert d["type"] == "device"
    assert "telnet_exposed" in d["vulnerabilities"]


def test_attack_path_to_dict():
    path = AttackPath(
        name="Test Path",
        description="A test attack path",
        nodes=["device", "gateway", "cloud"],
        severity="high",
        prerequisites=["Network access"],
    )
    d = path.to_dict()
    assert d["name"] == "Test Path"
    assert len(d["nodes"]) == 3
    assert d["severity"] == "high"


def test_attack_path_mapper_network_segmentation():
    target = Target(host="192.168.1.1")
    config = {
        "ecosystem": {
            "network": {
                "iot_vlan": False,
                "egress_filtering": False,
                "ids_monitoring": False,
            },
        },
    }
    scanner = AttackPathMapper(target=target, config=config)

    with patch.object(scanner, "_probe_device"):
        result = scanner.run()

    vlan_findings = [f for f in result.findings if "network segment" in f.title.lower()]
    assert len(vlan_findings) >= 1


def test_attack_path_mapper_shared_credentials():
    target = Target(host="192.168.1.1")
    config = {
        "ecosystem": {
            "cloud": {
                "shared_credentials": True,
                "device_identity": False,
            },
        },
    }
    scanner = AttackPathMapper(target=target, config=config)

    with patch.object(scanner, "_probe_device"):
        result = scanner.run()

    shared_findings = [f for f in result.findings if "shared" in f.title.lower() or "share" in f.description.lower()]
    assert len(shared_findings) >= 1


def test_attack_path_mapper_api_no_auth():
    target = Target(host="192.168.1.1")
    config = {
        "ecosystem": {
            "apis": [
                {"url": "https://api.example.com/v1", "auth_method": "none"},
            ],
        },
    }
    scanner = AttackPathMapper(target=target, config=config)

    with patch.object(scanner, "_probe_device"):
        result = scanner.run()

    api_findings = [f for f in result.findings if "no authentication" in f.title.lower()]
    assert len(api_findings) >= 1
