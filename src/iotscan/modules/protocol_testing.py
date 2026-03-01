"""IoT protocol testing module - MQTT, CoAP, Zigbee, and BLE security testing."""

from __future__ import annotations

import logging
import socket
import ssl
import struct
from contextlib import closing

from ..base import BaseScanner
from ..models import Severity

logger = logging.getLogger(__name__)


class ProtocolTester(BaseScanner):
    """Test IoT communication protocols for security vulnerabilities."""

    name = "protocol_testing"
    description = "Security testing for MQTT, CoAP, Zigbee, and BLE protocols"

    def scan(self) -> None:
        protocol = self.target.protocol.lower() if self.target.protocol else "auto"
        host = self.target.host
        port = self.target.port

        if protocol in ("auto", "mqtt"):
            self._test_mqtt(host, port or 1883)
        if protocol in ("auto", "coap"):
            self._test_coap(host, port or 5683)
        if protocol in ("auto", "zigbee"):
            self._test_zigbee(host)
        if protocol in ("auto", "ble"):
            self._test_ble(host)

    # ── MQTT Testing ──────────────────────────────────────────────

    def _test_mqtt(self, host: str, port: int) -> None:
        """Test MQTT broker for common security misconfigurations."""
        self.logger.info("Testing MQTT on %s:%d", host, port)

        self._test_mqtt_anonymous_access(host, port)
        self._test_mqtt_tls(host, port)
        self._test_mqtt_topic_enumeration(host, port)
        self._test_mqtt_version(host, port)

    def _test_mqtt_anonymous_access(self, host: str, port: int) -> None:
        """Check if MQTT broker allows unauthenticated connections."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))

            # MQTT CONNECT packet with no username/password
            connect_packet = self._build_mqtt_connect(client_id="iotscan_probe", username="", password="")
            sock.send(connect_packet)
            response = sock.recv(4)
            sock.close()

            if len(response) >= 4:
                return_code = response[3] if len(response) > 3 else 0xFF
                if return_code == 0x00:
                    self.add_finding(
                        title="MQTT broker allows anonymous access",
                        severity=Severity.CRITICAL,
                        description=(
                            "The MQTT broker accepts connections without authentication. "
                            "Any client can subscribe to topics and publish messages."
                        ),
                        evidence=f"CONNACK return code: 0x00 (Connection Accepted) on {host}:{port}",
                        remediation="Enable authentication on the MQTT broker. Use username/password or client certificates.",
                        owasp_iot="I9",
                        cvss_score=9.1,
                    )
                elif return_code == 0x05:
                    self.add_finding(
                        title="MQTT broker requires authentication",
                        severity=Severity.INFO,
                        description="The MQTT broker correctly rejects unauthenticated connections.",
                        evidence=f"CONNACK return code: 0x05 (Not Authorized) on {host}:{port}",
                    )
        except socket.timeout:
            self.add_finding(
                title="MQTT broker unreachable",
                severity=Severity.INFO,
                description=f"Could not connect to MQTT broker at {host}:{port} (timeout).",
            )
        except OSError as e:
            self.logger.debug("MQTT connection error: %s", e)

    def _test_mqtt_tls(self, host: str, port: int) -> None:
        """Check if MQTT supports TLS and validate certificate configuration."""
        tls_port = self.config.get("mqtt_tls_port", 8883)
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with closing(socket.create_connection((host, tls_port), timeout=5)) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                    cert = tls_sock.getpeercert(binary_form=True)
                    protocol_version = tls_sock.version()

                    if protocol_version in ("TLSv1", "TLSv1.1"):
                        self.add_finding(
                            title="MQTT uses deprecated TLS version",
                            severity=Severity.HIGH,
                            description=f"MQTT TLS endpoint uses {protocol_version}, which is deprecated and insecure.",
                            evidence=f"Negotiated protocol: {protocol_version}",
                            remediation="Configure the broker to use TLS 1.2 or TLS 1.3 minimum.",
                        )

                    self.add_finding(
                        title="MQTT TLS endpoint detected",
                        severity=Severity.INFO,
                        description=f"MQTT TLS is available on port {tls_port} using {protocol_version}.",
                    )
        except (socket.timeout, OSError):
            self.add_finding(
                title="No MQTT TLS endpoint found",
                severity=Severity.MEDIUM,
                description=f"No TLS-enabled MQTT endpoint found on port {tls_port}. Traffic may be unencrypted.",
                remediation="Enable TLS on the MQTT broker to encrypt data in transit.",
            )

    def _test_mqtt_topic_enumeration(self, host: str, port: int) -> None:
        """Attempt to subscribe to wildcard topics to enumerate available data."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))

            connect_packet = self._build_mqtt_connect(client_id="iotscan_enum")
            sock.send(connect_packet)
            response = sock.recv(4)

            if len(response) >= 4 and response[3] == 0x00:
                # Subscribe to wildcard '#'
                subscribe_packet = self._build_mqtt_subscribe(topic="#", packet_id=1)
                sock.send(subscribe_packet)
                sub_response = sock.recv(5)

                if len(sub_response) >= 5 and sub_response[4] != 0x80:
                    self.add_finding(
                        title="MQTT wildcard subscription allowed",
                        severity=Severity.HIGH,
                        description=(
                            "The broker allows subscribing to the '#' wildcard topic. "
                            "An attacker can monitor all MQTT traffic."
                        ),
                        evidence="Successfully subscribed to '#' topic",
                        remediation="Implement topic-level ACLs to restrict wildcard subscriptions.",
                    )

                    # Attempt to read messages for a short time
                    sock.settimeout(3)
                    try:
                        data = sock.recv(4096)
                        if data:
                            self.result.raw_data["mqtt_sample_traffic_size"] = len(data)
                    except socket.timeout:
                        pass

            sock.close()
        except (socket.timeout, OSError) as e:
            self.logger.debug("MQTT topic enumeration error: %s", e)

    def _test_mqtt_version(self, host: str, port: int) -> None:
        """Check which MQTT protocol versions are supported."""
        for version_name, version_byte in [("3.1", 3), ("3.1.1", 4), ("5.0", 5)]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((host, port))
                connect = self._build_mqtt_connect(
                    client_id="iotscan_ver", protocol_level=version_byte
                )
                sock.send(connect)
                resp = sock.recv(4)
                sock.close()
                if len(resp) >= 4 and resp[3] == 0x00:
                    self.result.raw_data.setdefault("mqtt_versions", []).append(version_name)
            except (socket.timeout, OSError):
                pass

    @staticmethod
    def _build_mqtt_connect(
        client_id: str = "iotscan",
        username: str = "",
        password: str = "",
        protocol_level: int = 4,
    ) -> bytes:
        """Build an MQTT CONNECT packet."""
        protocol_name = b"\x00\x04MQTT"
        connect_flags = 0x02  # Clean session
        if username:
            connect_flags |= 0x80
        if password:
            connect_flags |= 0x40
        keep_alive = struct.pack("!H", 60)
        client_id_bytes = struct.pack("!H", len(client_id)) + client_id.encode()

        variable_header = protocol_name + bytes([protocol_level, connect_flags]) + keep_alive
        payload = client_id_bytes

        if username:
            payload += struct.pack("!H", len(username)) + username.encode()
        if password:
            payload += struct.pack("!H", len(password)) + password.encode()

        remaining = variable_header + payload
        fixed_header = bytes([0x10]) + bytes([len(remaining)])
        return fixed_header + remaining

    @staticmethod
    def _build_mqtt_subscribe(topic: str, packet_id: int = 1) -> bytes:
        """Build an MQTT SUBSCRIBE packet."""
        packet_id_bytes = struct.pack("!H", packet_id)
        topic_bytes = struct.pack("!H", len(topic)) + topic.encode() + b"\x00"
        remaining = packet_id_bytes + topic_bytes
        fixed_header = bytes([0x82]) + bytes([len(remaining)])
        return fixed_header + remaining

    # ── CoAP Testing ──────────────────────────────────────────────

    def _test_coap(self, host: str, port: int) -> None:
        """Test CoAP endpoint for security issues."""
        self.logger.info("Testing CoAP on %s:%d", host, port)
        self._test_coap_discovery(host, port)
        self._test_coap_security(host, port)

    def _test_coap_discovery(self, host: str, port: int) -> None:
        """Attempt CoAP resource discovery via .well-known/core."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)

            # CoAP GET request for /.well-known/core
            # Ver=1, Type=CON, TKL=1, Code=GET(0.01), MsgId=0x0001
            coap_header = bytes([0x41, 0x01, 0x00, 0x01])
            token = b"\xAB"
            # Uri-Path option: .well-known
            opt1 = bytes([0xBD, 0x0B]) + b".well-known"
            # Uri-Path option: core
            opt2 = bytes([0x04]) + b"core"

            packet = coap_header + token + opt1 + opt2
            sock.sendto(packet, (host, port))
            data, _ = sock.recvfrom(4096)
            sock.close()

            if data and len(data) > 4:
                code_class = (data[1] >> 5) & 0x07
                code_detail = data[1] & 0x1F
                if code_class == 2:  # 2.xx success
                    self.add_finding(
                        title="CoAP resource discovery exposed",
                        severity=Severity.MEDIUM,
                        description=(
                            "The CoAP endpoint exposes resource discovery at /.well-known/core. "
                            "This reveals available resources and endpoints to attackers."
                        ),
                        evidence=f"CoAP response code: {code_class}.{code_detail:02d}, payload size: {len(data)} bytes",
                        remediation="Restrict CoAP resource discovery or require DTLS authentication.",
                    )
                    self.result.raw_data["coap_discovery_response_size"] = len(data)
        except socket.timeout:
            self.add_finding(
                title="CoAP endpoint unreachable",
                severity=Severity.INFO,
                description=f"No CoAP response from {host}:{port}.",
            )
        except OSError as e:
            self.logger.debug("CoAP discovery error: %s", e)

    def _test_coap_security(self, host: str, port: int) -> None:
        """Check if CoAP uses DTLS for transport security."""
        dtls_port = self.config.get("coap_dtls_port", 5684)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            # Send a DTLS ClientHello-like probe
            dtls_probe = bytes([0x16, 0xFE, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01])
            sock.sendto(dtls_probe, (host, dtls_port))
            data, _ = sock.recvfrom(4096)
            sock.close()

            if data and data[0] == 0x16:
                self.add_finding(
                    title="CoAP DTLS endpoint detected",
                    severity=Severity.INFO,
                    description=f"DTLS-secured CoAP (CoAPS) detected on port {dtls_port}.",
                )
            else:
                self.add_finding(
                    title="CoAP lacks DTLS transport security",
                    severity=Severity.HIGH,
                    description="CoAP communication is not protected by DTLS. Data is transmitted in plaintext.",
                    remediation="Enable DTLS (CoAPS) on port 5684 to encrypt CoAP communications.",
                )
        except (socket.timeout, OSError):
            self.add_finding(
                title="No CoAP DTLS endpoint found",
                severity=Severity.MEDIUM,
                description=f"No DTLS endpoint found on port {dtls_port}. CoAP traffic may be unencrypted.",
                remediation="Deploy DTLS to secure CoAP communications.",
            )

    # ── Zigbee Testing ────────────────────────────────────────────

    def _test_zigbee(self, host: str) -> None:
        """Test Zigbee network security configuration."""
        self.logger.info("Testing Zigbee security for %s", host)

        zigbee_config = self.config.get("zigbee", {})

        # Check network key configuration
        network_key = zigbee_config.get("network_key", "")
        if network_key:
            well_known_keys = [
                "5a:69:67:42:65:65:41:6c:6c:69:61:6e:63:65:30:39",  # ZigBeeAlliance09
                "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
                "ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff",
            ]
            if network_key.lower() in well_known_keys:
                self.add_finding(
                    title="Zigbee uses well-known network key",
                    severity=Severity.CRITICAL,
                    description=(
                        "The Zigbee network uses a well-known default key (e.g., ZigBeeAlliance09). "
                        "An attacker can decrypt all network traffic."
                    ),
                    evidence=f"Network key matches known default: {network_key[:8]}...",
                    remediation="Generate and distribute a unique random network key. Use Install Code-based key exchange.",
                )

        # Check security mode
        security_mode = zigbee_config.get("security_mode", "unknown")
        if security_mode == "no_security":
            self.add_finding(
                title="Zigbee network security disabled",
                severity=Severity.CRITICAL,
                description="Zigbee network is operating without encryption. All traffic is in plaintext.",
                remediation="Enable Zigbee security with AES-128-CCM encryption.",
            )
        elif security_mode in ("standard", "unknown"):
            self.add_finding(
                title="Zigbee standard security mode",
                severity=Severity.MEDIUM,
                description=(
                    "Zigbee is using standard security mode which transmits the network key in the clear "
                    "during device joining. An attacker can capture the key during the join process."
                ),
                remediation="Use high-security mode with a Trust Center Link Key or Install Codes for key exchange.",
            )

        # Check for permit join
        if zigbee_config.get("permit_join", False):
            self.add_finding(
                title="Zigbee network permit join enabled",
                severity=Severity.HIGH,
                description="The Zigbee coordinator has permit-join enabled, allowing new devices to join the network.",
                remediation="Disable permit-join when not actively pairing devices. Use Install Codes for secure joining.",
            )

        # Check touchlink vulnerability
        if zigbee_config.get("touchlink_enabled", True):
            self.add_finding(
                title="Zigbee Touchlink commissioning enabled",
                severity=Severity.HIGH,
                description=(
                    "Touchlink commissioning is enabled, which is vulnerable to factory reset attacks. "
                    "An attacker can force devices to leave the network and join a rogue network."
                ),
                remediation="Disable Touchlink commissioning if not required.",
            )

    # ── BLE Testing ───────────────────────────────────────────────

    def _test_ble(self, host: str) -> None:
        """Test Bluetooth Low Energy security configuration."""
        self.logger.info("Testing BLE security for %s", host)

        ble_config = self.config.get("ble", {})

        # Check pairing mode
        pairing_mode = ble_config.get("pairing_mode", "unknown")
        if pairing_mode == "just_works":
            self.add_finding(
                title="BLE uses 'Just Works' pairing (no MITM protection)",
                severity=Severity.HIGH,
                description=(
                    "The BLE device uses 'Just Works' pairing which provides no man-in-the-middle protection. "
                    "An attacker within radio range can intercept the pairing process."
                ),
                remediation="Use Passkey Entry or Numeric Comparison pairing methods for MITM protection.",
            )
        elif pairing_mode == "none":
            self.add_finding(
                title="BLE device has no pairing requirement",
                severity=Severity.CRITICAL,
                description="The BLE device does not require pairing. Any device can connect and interact with it.",
                remediation="Implement BLE pairing with at minimum Passkey Entry or Out of Band pairing.",
            )

        # Check encryption
        if not ble_config.get("encryption_enabled", True):
            self.add_finding(
                title="BLE link encryption disabled",
                severity=Severity.CRITICAL,
                description="BLE communication is unencrypted. All data transmitted over BLE can be captured.",
                remediation="Enable BLE link-layer encryption (AES-CCM).",
            )

        # Check BLE version for known vulnerabilities
        ble_version = ble_config.get("version", "")
        if ble_version and ble_version < "4.2":
            self.add_finding(
                title="Outdated BLE version with known vulnerabilities",
                severity=Severity.HIGH,
                description=(
                    f"BLE version {ble_version} lacks Secure Connections (LE Secure Connections introduced in 4.2). "
                    "Legacy pairing is vulnerable to passive eavesdropping."
                ),
                evidence=f"BLE version: {ble_version}",
                remediation="Update to BLE 4.2+ and enable LE Secure Connections.",
                cve="CVE-2019-9506",
            )

        # Check for writable GATT characteristics
        writable_chars = ble_config.get("writable_characteristics", [])
        if writable_chars:
            self.add_finding(
                title="BLE GATT characteristics are writable without authentication",
                severity=Severity.HIGH,
                description=(
                    f"Found {len(writable_chars)} GATT characteristic(s) that are writable without authentication. "
                    "An attacker could modify device behavior or configuration."
                ),
                evidence=f"Writable characteristics: {writable_chars[:5]}",
                remediation="Require authentication and authorization for writable GATT characteristics.",
            )

        # Check advertising data exposure
        if ble_config.get("exposes_device_name", False) or ble_config.get("exposes_mac", False):
            self.add_finding(
                title="BLE advertising exposes device information",
                severity=Severity.LOW,
                description="BLE advertising packets expose device name or MAC address, enabling device tracking.",
                remediation="Use random/rotating BLE addresses and minimize data in advertising packets.",
            )
