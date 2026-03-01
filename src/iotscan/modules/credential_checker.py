"""Default credential checker for IoT devices."""

from __future__ import annotations

import base64
import hashlib
import logging
import socket
import ssl
import struct
from contextlib import closing

from ..base import BaseScanner
from ..models import Severity

logger = logging.getLogger(__name__)

# Comprehensive default credential database for common IoT devices
DEFAULT_CREDENTIALS = [
    # Generic defaults
    {"vendor": "Generic", "username": "admin", "password": "admin"},
    {"vendor": "Generic", "username": "admin", "password": "password"},
    {"vendor": "Generic", "username": "admin", "password": "1234"},
    {"vendor": "Generic", "username": "admin", "password": "12345"},
    {"vendor": "Generic", "username": "admin", "password": ""},
    {"vendor": "Generic", "username": "root", "password": "root"},
    {"vendor": "Generic", "username": "root", "password": ""},
    {"vendor": "Generic", "username": "root", "password": "toor"},
    {"vendor": "Generic", "username": "user", "password": "user"},
    {"vendor": "Generic", "username": "guest", "password": "guest"},
    # IP Cameras
    {"vendor": "Hikvision", "username": "admin", "password": "12345"},
    {"vendor": "Dahua", "username": "admin", "password": "admin"},
    {"vendor": "Axis", "username": "root", "password": "pass"},
    {"vendor": "Foscam", "username": "admin", "password": ""},
    {"vendor": "Amcrest", "username": "admin", "password": "admin"},
    {"vendor": "Reolink", "username": "admin", "password": ""},
    # Routers / Gateways
    {"vendor": "TP-Link", "username": "admin", "password": "admin"},
    {"vendor": "D-Link", "username": "admin", "password": ""},
    {"vendor": "Netgear", "username": "admin", "password": "password"},
    {"vendor": "Linksys", "username": "admin", "password": "admin"},
    {"vendor": "Ubiquiti", "username": "ubnt", "password": "ubnt"},
    {"vendor": "MikroTik", "username": "admin", "password": ""},
    {"vendor": "ZTE", "username": "admin", "password": "admin"},
    {"vendor": "Huawei", "username": "admin", "password": "admin"},
    # Industrial / SCADA
    {"vendor": "Siemens", "username": "admin", "password": "admin"},
    {"vendor": "Schneider", "username": "USER", "password": "USER"},
    {"vendor": "Moxa", "username": "admin", "password": ""},
    {"vendor": "Rockwell", "username": "admin", "password": "1234"},
    # Smart Home
    {"vendor": "Samsung SmartThings", "username": "admin", "password": "admin"},
    {"vendor": "Philips Hue", "username": "", "password": ""},
    {"vendor": "Ring", "username": "admin", "password": "admin"},
    # MQTT brokers
    {"vendor": "Mosquitto", "username": "admin", "password": "admin"},
    {"vendor": "EMQ X", "username": "admin", "password": "public"},
    {"vendor": "HiveMQ", "username": "admin", "password": "hivemq"},
    # Printers / IoT misc
    {"vendor": "HP Printer", "username": "admin", "password": "admin"},
    {"vendor": "Brother", "username": "admin", "password": "access"},
    {"vendor": "Xerox", "username": "admin", "password": "1111"},
]

# Common IoT service ports to check
SERVICE_PORTS = {
    "http": [80, 8080, 8443, 443],
    "ssh": [22],
    "telnet": [23],
    "ftp": [21],
    "mqtt": [1883],
}


class CredentialChecker(BaseScanner):
    """Check IoT devices for default and weak credentials across multiple services."""

    name = "credential_checker"
    description = "Default and weak credential testing for IoT devices"

    def scan(self) -> None:
        host = self.target.host
        target_port = self.target.port

        # Discover open services
        open_ports = self._discover_services(host, target_port)
        self.result.raw_data["open_ports"] = open_ports

        for service, ports in open_ports.items():
            for port in ports:
                if service == "http":
                    self._check_http_credentials(host, port)
                elif service == "ssh":
                    self._check_ssh_banner(host, port)
                elif service == "telnet":
                    self._check_telnet(host, port)
                elif service == "ftp":
                    self._check_ftp(host, port)
                elif service == "mqtt":
                    self._check_mqtt_credentials(host, port)

        self._report_weak_password_policy()

    def _discover_services(self, host: str, target_port: int) -> dict[str, list[int]]:
        """Scan for open IoT service ports."""
        open_services: dict[str, list[int]] = {}

        if target_port:
            # If a specific port was given, probe it
            for service, ports in SERVICE_PORTS.items():
                if target_port in ports:
                    if self._is_port_open(host, target_port):
                        open_services[service] = [target_port]
                    return open_services
            # Unknown port - try it as HTTP
            if self._is_port_open(host, target_port):
                open_services["http"] = [target_port]
            return open_services

        # Auto-discover services
        for service, ports in SERVICE_PORTS.items():
            for port in ports:
                if self._is_port_open(host, port):
                    open_services.setdefault(service, []).append(port)

        return open_services

    def _is_port_open(self, host: str, port: int) -> bool:
        """Check if a TCP port is open."""
        try:
            with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
                sock.settimeout(3)
                return sock.connect_ex((host, port)) == 0
        except OSError:
            return False

    def _check_http_credentials(self, host: str, port: int) -> None:
        """Test HTTP/HTTPS basic auth with default credentials."""
        use_ssl = port in (443, 8443)
        tested = 0
        successful = []

        for cred in DEFAULT_CREDENTIALS:
            auth_string = base64.b64encode(
                f"{cred['username']}:{cred['password']}".encode()
            ).decode()

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((host, port))

                if use_ssl:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock, server_hostname=host)

                request = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {host}:{port}\r\n"
                    f"Authorization: Basic {auth_string}\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                ).encode()

                sock.send(request)
                response = sock.recv(1024).decode("utf-8", errors="ignore")
                sock.close()
                tested += 1

                if "200 OK" in response or "302 Found" in response or "301 Moved" in response:
                    if "401" not in response and "403" not in response:
                        successful.append(
                            f"{cred['vendor']}: {cred['username']}:{cred['password']}"
                        )
            except (OSError, ssl.SSLError):
                continue

        if successful:
            self.add_finding(
                title=f"Default HTTP credentials accepted on port {port}",
                severity=Severity.CRITICAL,
                description=(
                    f"The device's web interface accepts default credentials. "
                    f"Tested {tested} credential pairs, {len(successful)} succeeded."
                ),
                evidence=f"Successful logins: {successful}",
                remediation="Change default credentials immediately. Enforce strong password policy. Implement account lockout.",
            )

    def _check_ssh_banner(self, host: str, port: int) -> None:
        """Grab SSH banner to identify service and check for known weaknesses."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            banner = sock.recv(256).decode("utf-8", errors="ignore").strip()
            sock.close()

            self.result.raw_data["ssh_banner"] = banner

            if "dropbear" in banner.lower():
                self.add_finding(
                    title="Dropbear SSH detected",
                    severity=Severity.INFO,
                    description=f"Embedded SSH server detected: {banner}",
                )
            if "libssh" in banner.lower():
                self.add_finding(
                    title="libssh-based SSH detected",
                    severity=Severity.MEDIUM,
                    description=f"libssh detected ({banner}). Check for CVE-2018-10933 authentication bypass.",
                    cve="CVE-2018-10933",
                    remediation="Ensure libssh is updated to a patched version (>=0.8.4 or >=0.7.6).",
                )

            self.add_finding(
                title=f"SSH service on port {port}",
                severity=Severity.INFO,
                description=f"SSH is accessible. Banner: {banner}",
                remediation="Ensure SSH uses key-based authentication. Disable password auth if possible.",
            )
        except (OSError, UnicodeDecodeError):
            pass

    def _check_telnet(self, host: str, port: int) -> None:
        """Check for open telnet service (always a finding for IoT)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            banner = sock.recv(512).decode("utf-8", errors="ignore")
            sock.close()

            self.add_finding(
                title="Telnet service is accessible",
                severity=Severity.HIGH,
                description=(
                    "Telnet transmits credentials and data in plaintext. "
                    "This is a common attack vector for IoT botnets (e.g., Mirai)."
                ),
                evidence=f"Telnet banner: {banner[:100]}",
                remediation="Disable telnet entirely. Use SSH for remote management.",
            )
        except OSError:
            pass

    def _check_ftp(self, host: str, port: int) -> None:
        """Check FTP for anonymous access and default credentials."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            banner = sock.recv(512).decode("utf-8", errors="ignore")

            # Test anonymous login
            sock.send(b"USER anonymous\r\n")
            user_resp = sock.recv(512).decode("utf-8", errors="ignore")
            if "331" in user_resp:
                sock.send(b"PASS anonymous@\r\n")
                pass_resp = sock.recv(512).decode("utf-8", errors="ignore")
                if "230" in pass_resp:
                    self.add_finding(
                        title="FTP allows anonymous access",
                        severity=Severity.HIGH,
                        description="The FTP server allows anonymous login, potentially exposing firmware or config files.",
                        evidence=f"FTP banner: {banner[:100]}",
                        remediation="Disable anonymous FTP access. Use SFTP instead of FTP.",
                    )

            sock.send(b"QUIT\r\n")
            sock.close()
        except OSError:
            pass

    def _check_mqtt_credentials(self, host: str, port: int) -> None:
        """Test MQTT broker with default credentials."""
        successful = []

        for cred in DEFAULT_CREDENTIALS:
            if cred["vendor"] not in ("Mosquitto", "EMQ X", "HiveMQ", "Generic"):
                continue
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((host, port))

                # Build MQTT CONNECT with credentials
                client_id = "iotscan_cred"
                protocol_name = b"\x00\x04MQTT"
                connect_flags = 0xC2  # Clean session + username + password
                keep_alive = struct.pack("!H", 60)

                payload = struct.pack("!H", len(client_id)) + client_id.encode()
                payload += struct.pack("!H", len(cred["username"])) + cred["username"].encode()
                payload += struct.pack("!H", len(cred["password"])) + cred["password"].encode()

                variable_header = protocol_name + bytes([4, connect_flags]) + keep_alive
                remaining = variable_header + payload
                packet = bytes([0x10, len(remaining)]) + remaining

                sock.send(packet)
                resp = sock.recv(4)
                sock.close()

                if len(resp) >= 4 and resp[3] == 0x00:
                    successful.append(f"{cred['vendor']}: {cred['username']}:{cred['password']}")
            except (OSError, struct.error):
                continue

        if successful:
            self.add_finding(
                title="MQTT broker accepts default credentials",
                severity=Severity.CRITICAL,
                description=f"The MQTT broker accepts {len(successful)} default credential pair(s).",
                evidence=f"Successful: {successful}",
                remediation="Change MQTT broker credentials. Use strong passwords and client certificates.",
            )

    def _report_weak_password_policy(self) -> None:
        """Check for indicators of weak password policies."""
        crit_findings = [f for f in self.result.findings if f.severity == Severity.CRITICAL]
        if len(crit_findings) >= 2:
            self.add_finding(
                title="Multiple services use default credentials",
                severity=Severity.CRITICAL,
                description=(
                    f"Found {len(crit_findings)} services accepting default credentials. "
                    "This indicates a systemic lack of credential management."
                ),
                remediation=(
                    "Implement a device provisioning process that forces credential changes. "
                    "Use unique per-device credentials. Consider certificate-based authentication."
                ),
            )
