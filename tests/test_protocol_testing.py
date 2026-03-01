"""Tests for the protocol testing module."""

from iotscan.models import Severity, Target
from iotscan.modules.protocol_testing import ProtocolTester


def test_protocol_tester_zigbee_default_key():
    target = Target(host="192.168.1.1", protocol="zigbee")
    config = {
        "zigbee": {
            "network_key": "5a:69:67:42:65:65:41:6c:6c:69:61:6e:63:65:30:39",
            "security_mode": "standard",
            "permit_join": True,
            "touchlink_enabled": True,
        }
    }
    scanner = ProtocolTester(target=target, config=config)
    result = scanner.run()

    key_findings = [f for f in result.findings if "well-known" in f.title.lower()]
    assert len(key_findings) == 1
    assert key_findings[0].severity == Severity.CRITICAL

    join_findings = [f for f in result.findings if "permit join" in f.title.lower()]
    assert len(join_findings) == 1

    touchlink_findings = [f for f in result.findings if "touchlink" in f.title.lower()]
    assert len(touchlink_findings) == 1


def test_protocol_tester_ble_just_works():
    target = Target(host="192.168.1.1", protocol="ble")
    config = {
        "ble": {
            "pairing_mode": "just_works",
            "encryption_enabled": True,
            "version": "4.1",
        }
    }
    scanner = ProtocolTester(target=target, config=config)
    result = scanner.run()

    pairing_findings = [f for f in result.findings if "just works" in f.title.lower()]
    assert len(pairing_findings) == 1
    assert pairing_findings[0].severity == Severity.HIGH

    version_findings = [f for f in result.findings if "outdated" in f.title.lower()]
    assert len(version_findings) == 1


def test_protocol_tester_ble_no_pairing():
    target = Target(host="192.168.1.1", protocol="ble")
    config = {
        "ble": {
            "pairing_mode": "none",
            "encryption_enabled": False,
        }
    }
    scanner = ProtocolTester(target=target, config=config)
    result = scanner.run()

    no_pairing = [f for f in result.findings if "no pairing" in f.title.lower()]
    assert len(no_pairing) == 1
    assert no_pairing[0].severity == Severity.CRITICAL

    no_encryption = [f for f in result.findings if "encryption disabled" in f.title.lower()]
    assert len(no_encryption) == 1


def test_protocol_tester_zigbee_no_security():
    target = Target(host="192.168.1.1", protocol="zigbee")
    config = {
        "zigbee": {
            "security_mode": "no_security",
        }
    }
    scanner = ProtocolTester(target=target, config=config)
    result = scanner.run()

    disabled_findings = [f for f in result.findings if "security disabled" in f.title.lower()]
    assert len(disabled_findings) == 1
    assert disabled_findings[0].severity == Severity.CRITICAL


def test_mqtt_connect_packet_builder():
    """Test that the MQTT CONNECT packet builder produces valid packets."""
    packet = ProtocolTester._build_mqtt_connect(client_id="test", username="", password="")
    assert packet[0] == 0x10  # CONNECT packet type
    assert b"MQTT" in packet


def test_mqtt_subscribe_packet_builder():
    """Test that the MQTT SUBSCRIBE packet builder produces valid packets."""
    packet = ProtocolTester._build_mqtt_subscribe(topic="#", packet_id=1)
    assert packet[0] == 0x82  # SUBSCRIBE packet type
    assert b"#" in packet
