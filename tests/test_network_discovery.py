"""Tests for the network discovery module."""

from iotscan.models import Target
from iotscan.modules.network_discovery import NetworkDiscovery, DEFAULT_COMMUNITIES


def test_network_discovery_name():
    target = Target(host="192.168.1.1")
    scanner = NetworkDiscovery(target=target)
    assert scanner.name == "network_discovery"


def test_snmp_community_list():
    assert "public" in DEFAULT_COMMUNITIES
    assert "private" in DEFAULT_COMMUNITIES
    assert len(DEFAULT_COMMUNITIES) >= 5


def test_snmp_get_packet_builder():
    scanner = NetworkDiscovery(target=Target(host="x"))
    pkt = scanner._build_snmp_get("public", "1.3.6.1.2.1.1.1.0")
    # Should start with SEQUENCE tag (0x30)
    assert pkt[0] == 0x30
    # Should contain the community string
    assert b"public" in pkt


def test_mdns_query_builder():
    query = NetworkDiscovery._build_mdns_query("_http._tcp.local")
    # DNS header is 12 bytes
    assert len(query) > 12
    # Should contain the service name
    assert b"_http" in query
    assert b"_tcp" in query
    assert b"local" in query


def test_exposed_service_detection():
    target = Target(host="192.168.1.1")
    scanner = NetworkDiscovery(target=target)
    # Simulate finding dangerous services
    open_services = {23: "Telnet", 502: "Modbus", 80: "HTTP"}
    scanner._check_exposed_services(open_services)

    findings = scanner.result.findings
    titles = [f.title for f in findings]
    assert "Telnet exposed" in titles
    assert "Modbus exposed" in titles


def test_excessive_services_warning():
    target = Target(host="192.168.1.1")
    scanner = NetworkDiscovery(target=target)
    # Simulate many open services
    open_services = {p: "svc" for p in range(80, 90)}
    scanner._check_exposed_services(open_services)

    titles = [f.title for f in scanner.result.findings]
    assert "Excessive number of open services" in titles
