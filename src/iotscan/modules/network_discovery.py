"""Network discovery module - UPnP/SSDP, mDNS, SNMP, and service fingerprinting."""

from __future__ import annotations

import re
import socket
import struct
from contextlib import closing

from ..base import BaseScanner
from ..models import Severity

# SNMP default community strings commonly found on IoT devices
DEFAULT_COMMUNITIES = [
    "public",
    "private",
    "community",
    "admin",
    "default",
    "manager",
    "monitor",
    "snmp",
    "cable-docsis",
    "ILMI",
]

# Common IoT service banners and their associated risks
SERVICE_FINGERPRINTS = {
    21: ("FTP", "File Transfer Protocol"),
    22: ("SSH", "Secure Shell"),
    23: ("Telnet", "Unencrypted remote shell"),
    25: ("SMTP", "Mail server"),
    53: ("DNS", "Domain Name System"),
    80: ("HTTP", "Web server"),
    161: ("SNMP", "Simple Network Management Protocol"),
    443: ("HTTPS", "Encrypted web server"),
    502: ("Modbus", "Industrial control protocol"),
    554: ("RTSP", "Real-Time Streaming Protocol"),
    1883: ("MQTT", "Message Queue Telemetry Transport"),
    1900: ("SSDP", "UPnP/SSDP discovery"),
    3000: ("HTTP-Alt", "Alternative web server"),
    5353: ("mDNS", "Multicast DNS"),
    5683: ("CoAP", "Constrained Application Protocol"),
    8080: ("HTTP-Proxy", "Web server / proxy"),
    8443: ("HTTPS-Alt", "Alternative HTTPS"),
    8883: ("MQTTS", "MQTT over TLS"),
    9100: ("Printer", "Raw printing / JetDirect"),
    47808: ("BACnet", "Building automation"),
}


class NetworkDiscovery(BaseScanner):
    """Discover IoT services, protocols, and misconfigurations on the network."""

    name = "network_discovery"
    description = "Network service discovery, UPnP/SSDP, mDNS, SNMP testing, and banner grabbing"

    def scan(self) -> None:
        host = self.target.host

        open_services = self._port_scan(host)
        self.result.raw_data["open_services"] = open_services

        self._banner_grab(host, open_services)
        self._test_ssdp(host)
        self._test_mdns(host)
        self._test_snmp(host)
        self._test_upnp(host)
        self._check_exposed_services(open_services)

    # ── Port Scanning & Banner Grabbing ───────────────────────────

    def _port_scan(self, host: str) -> dict[int, str]:
        """Scan common IoT ports and identify open services."""
        open_services: dict[int, str] = {}

        for port, (service, _desc) in SERVICE_FINGERPRINTS.items():
            try:
                with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
                    sock.settimeout(2)
                    if sock.connect_ex((host, port)) == 0:
                        open_services[port] = service
            except OSError:
                continue

        if open_services:
            services_str = ", ".join(f"{port}/{name}" for port, name in sorted(open_services.items()))
            self.add_finding(
                title=f"Found {len(open_services)} open service(s)",
                severity=Severity.INFO,
                description=f"Open services: {services_str}",
            )

        return open_services

    def _banner_grab(self, host: str, open_services: dict[int, str]) -> None:
        """Grab service banners for fingerprinting."""
        banners: dict[int, str] = {}

        for port in open_services:
            try:
                with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
                    sock.settimeout(3)
                    sock.connect((host, port))

                    # Some services send banner on connect, others need a probe
                    if port in (80, 8080, 3000):
                        sock.send(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
                    elif port == 554:
                        sock.send(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")
                    elif port == 21:
                        pass  # FTP sends banner automatically
                    elif port == 22:
                        pass  # SSH sends banner automatically
                    elif port == 23:
                        pass  # Telnet sends banner automatically

                    banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                    if banner:
                        banners[port] = banner[:200]
            except OSError:
                continue

        self.result.raw_data["banners"] = {str(k): v for k, v in banners.items()}

        # Analyze banners for information leakage
        for port, banner in banners.items():
            # Check for version disclosure
            version_patterns = [
                (r"Server:\s*(.+)", "HTTP server version"),
                (r"SSH-\S+\s+(\S+)", "SSH server version"),
                (r"220[- ](.+)", "FTP/SMTP banner"),
                (r"RTSP/\d\.\d\s+\d+\s+(.+)", "RTSP server"),
            ]
            for pattern, label in version_patterns:
                match = re.search(pattern, banner, re.IGNORECASE)
                if match:
                    server_info = match.group(1).strip()
                    self.add_finding(
                        title=f"Service version disclosed on port {port}",
                        severity=Severity.LOW,
                        description=f"{label}: {server_info}. Version disclosure helps attackers identify specific vulnerabilities.",
                        evidence=f"Port {port} banner: {banner[:100]}",
                        remediation="Suppress or customize server version banners in production.",
                    )

    # ── SSDP / UPnP ──────────────────────────────────────────────

    def _test_ssdp(self, host: str) -> None:
        """Send SSDP M-SEARCH to discover UPnP devices."""
        msearch = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            'MAN: "ssdp:discover"\r\n'
            "MX: 2\r\n"
            "ST: ssdp:all\r\n"
            "\r\n"
        ).encode()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.settimeout(3)
            sock.sendto(msearch, (host, 1900))

            responses = []
            try:
                while True:
                    data, addr = sock.recvfrom(4096)
                    responses.append(data.decode("utf-8", errors="ignore"))
            except socket.timeout:
                pass
            finally:
                sock.close()

            if responses:
                self.result.raw_data["ssdp_responses"] = responses

                # Parse responses for device info
                locations = []
                servers = []
                for resp in responses:
                    loc_match = re.search(r"LOCATION:\s*(http\S+)", resp, re.IGNORECASE)
                    if loc_match:
                        locations.append(loc_match.group(1))
                    srv_match = re.search(r"SERVER:\s*(.+)", resp, re.IGNORECASE)
                    if srv_match:
                        servers.append(srv_match.group(1).strip())

                self.add_finding(
                    title="UPnP/SSDP service discovered",
                    severity=Severity.MEDIUM,
                    description=(
                        f"Device responds to SSDP discovery ({len(responses)} response(s)). "
                        "UPnP exposes device details and can allow unauthenticated port forwarding or configuration changes."
                    ),
                    evidence=f"Locations: {locations[:3]}, Servers: {servers[:3]}",
                    remediation="Disable UPnP if not required. If needed, restrict to trusted networks only.",
                )
        except OSError as e:
            self.logger.debug("SSDP probe error: %s", e)

    def _test_upnp(self, host: str) -> None:
        """Check for UPnP IGD (Internet Gateway Device) which allows port mapping."""
        igd_paths = [
            "/rootDesc.xml",
            "/upnp/control/WANIPConn1",
            "/ctl/IPConn",
            "/DeviceDescription.xml",
        ]

        for path in igd_paths:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((host, 49152))  # common UPnP port
                request = f"GET {path} HTTP/1.1\r\nHost: {host}:49152\r\n\r\n".encode()
                sock.send(request)
                response = sock.recv(4096).decode("utf-8", errors="ignore")
                sock.close()

                if "200 OK" in response and ("InternetGatewayDevice" in response or "WANIPConnection" in response):
                    self.add_finding(
                        title="UPnP Internet Gateway Device exposed",
                        severity=Severity.HIGH,
                        description=(
                            "UPnP IGD is accessible, allowing unauthenticated port forwarding. "
                            "An attacker can open ports on the gateway and expose internal services."
                        ),
                        evidence=f"Accessible endpoint: {path}",
                        remediation="Disable UPnP IGD. Use manual port forwarding with explicit firewall rules.",
                    )
                    break
            except OSError:
                continue

    # ── mDNS ──────────────────────────────────────────────────────

    def _test_mdns(self, host: str) -> None:
        """Test for mDNS service exposure on the target."""
        # Build mDNS query for _services._dns-sd._udp.local
        query = self._build_mdns_query("_services._dns-sd._udp.local")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(query, (host, 5353))

            responses = []
            try:
                while True:
                    data, addr = sock.recvfrom(4096)
                    responses.append(data)
            except socket.timeout:
                pass
            finally:
                sock.close()

            if responses:
                self.add_finding(
                    title="mDNS service responds to queries",
                    severity=Severity.MEDIUM,
                    description=(
                        "The device responds to mDNS queries, exposing service information. "
                        "Attackers can enumerate available services and device details on the local network."
                    ),
                    evidence=f"Received {len(responses)} mDNS response(s) totaling {sum(len(r) for r in responses)} bytes",
                    remediation="Disable mDNS if not needed. Restrict mDNS to the local network segment only.",
                )

                # Also try device-specific service queries
                for service_type in ["_http._tcp.local", "_ssh._tcp.local", "_mqtt._tcp.local"]:
                    self._query_mdns_service(host, service_type)

        except OSError as e:
            self.logger.debug("mDNS probe error: %s", e)

    def _query_mdns_service(self, host: str, service_type: str) -> None:
        """Query a specific mDNS service type."""
        query = self._build_mdns_query(service_type)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.sendto(query, (host, 5353))
            data, _ = sock.recvfrom(4096)
            sock.close()

            if data and len(data) > 12:
                self.result.raw_data.setdefault("mdns_services", []).append(service_type)
        except (socket.timeout, OSError):
            pass

    @staticmethod
    def _build_mdns_query(name: str) -> bytes:
        """Build a minimal DNS query packet for mDNS."""
        # DNS header: ID=0, flags=0, 1 question, 0 answers
        header = struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)
        # Encode domain name
        qname = b""
        for label in name.split("."):
            qname += bytes([len(label)]) + label.encode()
        qname += b"\x00"
        # QTYPE=PTR(12), QCLASS=IN(1)
        question = qname + struct.pack("!HH", 12, 1)
        return header + question

    # ── SNMP ──────────────────────────────────────────────────────

    def _test_snmp(self, host: str) -> None:
        """Test for SNMP with default community strings."""
        successful_communities = []

        for community in DEFAULT_COMMUNITIES:
            snmp_get = self._build_snmp_get(community, "1.3.6.1.2.1.1.1.0")  # sysDescr
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2)
                sock.sendto(snmp_get, (host, 161))
                data, _ = sock.recvfrom(4096)
                sock.close()

                # A valid SNMP response starts with 0x30 (SEQUENCE)
                if data and data[0] == 0x30:
                    successful_communities.append(community)
                    # Try to extract sysDescr from response
                    text = data.decode("latin-1", errors="ignore")
                    self.result.raw_data.setdefault("snmp_sysDescr", []).append(
                        {"community": community, "response_size": len(data)}
                    )
            except (socket.timeout, OSError):
                continue

        if successful_communities:
            self.add_finding(
                title="SNMP accessible with default community strings",
                severity=Severity.CRITICAL,
                description=(
                    f"SNMP responds to {len(successful_communities)} default community string(s). "
                    "An attacker can read device configuration, routing tables, ARP caches, "
                    "and potentially write configuration changes."
                ),
                evidence=f"Working communities: {successful_communities}",
                remediation=(
                    "Change SNMP community strings to strong unique values. "
                    "Upgrade to SNMPv3 with authentication and encryption. "
                    "Restrict SNMP access via firewall rules."
                ),
            )

            # Check if SNMP write access is available
            if "private" in successful_communities:
                self.add_finding(
                    title="SNMP write access with default 'private' community",
                    severity=Severity.CRITICAL,
                    description=(
                        "The SNMP 'private' community string grants write access. "
                        "An attacker can modify device configuration, change routing, or disable services."
                    ),
                    remediation="Remove the 'private' community string immediately. Use SNMPv3 with write authentication.",
                )

    @staticmethod
    def _build_snmp_get(community: str, oid: str) -> bytes:
        """Build a minimal SNMPv1 GET request packet."""
        # Encode OID
        oid_parts = [int(p) for p in oid.split(".")]
        oid_bytes = bytes([oid_parts[0] * 40 + oid_parts[1]])
        for part in oid_parts[2:]:
            if part < 128:
                oid_bytes += bytes([part])
            else:
                # Multi-byte encoding for large OID components
                encoded = []
                while part > 0:
                    encoded.append(part & 0x7F)
                    part >>= 7
                encoded.reverse()
                for i in range(len(encoded) - 1):
                    encoded[i] |= 0x80
                oid_bytes += bytes(encoded)

        # Build from inside out (TLV encoding)
        # OID TLV
        oid_tlv = bytes([0x06, len(oid_bytes)]) + oid_bytes
        # NULL value
        null_val = bytes([0x05, 0x00])
        # VarBind SEQUENCE
        varbind = bytes([0x30, len(oid_tlv) + len(null_val)]) + oid_tlv + null_val
        # VarBindList SEQUENCE
        varbind_list = bytes([0x30, len(varbind)]) + varbind
        # Request ID (integer 1)
        req_id = bytes([0x02, 0x01, 0x01])
        # Error status (integer 0)
        error_status = bytes([0x02, 0x01, 0x00])
        # Error index (integer 0)
        error_index = bytes([0x02, 0x01, 0x00])
        # GetRequest PDU
        pdu_content = req_id + error_status + error_index + varbind_list
        get_pdu = bytes([0xA0, len(pdu_content)]) + pdu_content
        # Community string
        comm_bytes = community.encode()
        comm_tlv = bytes([0x04, len(comm_bytes)]) + comm_bytes
        # SNMP version (integer 0 = SNMPv1)
        version = bytes([0x02, 0x01, 0x00])
        # Top-level SEQUENCE
        message_content = version + comm_tlv + get_pdu
        return bytes([0x30, len(message_content)]) + message_content

    # ── Exposure Analysis ─────────────────────────────────────────

    def _check_exposed_services(self, open_services: dict[int, str]) -> None:
        """Flag dangerous service exposures common in IoT."""
        dangerous_services = {
            23: ("Telnet exposed", Severity.HIGH, "Telnet transmits all data in plaintext, including credentials. Primary vector for IoT botnets like Mirai."),
            502: ("Modbus exposed", Severity.CRITICAL, "Modbus has no authentication. An attacker can read/write industrial control registers."),
            554: ("RTSP exposed", Severity.MEDIUM, "RTSP may allow unauthenticated access to camera video streams."),
            9100: ("Raw printing port exposed", Severity.MEDIUM, "JetDirect/raw printing port allows sending arbitrary print jobs and may expose device status."),
            47808: ("BACnet exposed", Severity.HIGH, "BACnet building automation protocol often lacks authentication, allowing HVAC/lighting manipulation."),
        }

        for port, service in open_services.items():
            if port in dangerous_services:
                title, severity, description = dangerous_services[port]
                self.add_finding(
                    title=title,
                    severity=severity,
                    description=description,
                    evidence=f"Port {port} ({service}) is open",
                    remediation=f"Restrict access to port {port} via firewall. Use authenticated/encrypted alternatives where available.",
                )

        # Check for too many open services
        if len(open_services) > 8:
            self.add_finding(
                title="Excessive number of open services",
                severity=Severity.MEDIUM,
                description=f"Device has {len(open_services)} open services. IoT devices should minimize attack surface.",
                remediation="Disable unnecessary services. Apply principle of least privilege for network exposure.",
            )
