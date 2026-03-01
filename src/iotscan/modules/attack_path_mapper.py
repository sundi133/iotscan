"""Device-to-cloud attack path mapping for IoT ecosystems."""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field

from ..base import BaseScanner
from ..models import Severity


@dataclass
class AttackNode:
    """A node in the attack path graph."""
    name: str
    node_type: str  # device, gateway, cloud, network, api
    risk_level: str = "unknown"
    vulnerabilities: list[str] = field(default_factory=list)
    connections: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "type": self.node_type,
            "risk_level": self.risk_level,
            "vulnerabilities": self.vulnerabilities,
            "connections": self.connections,
        }


@dataclass
class AttackPath:
    """A path an attacker could take through the IoT ecosystem."""
    name: str
    description: str
    nodes: list[str]
    severity: str
    prerequisites: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "nodes": self.nodes,
            "severity": self.severity,
            "prerequisites": self.prerequisites,
        }


class AttackPathMapper(BaseScanner):
    """Map device-to-cloud attack paths in IoT ecosystems."""

    name = "attack_path_mapper"
    description = "Device-to-cloud attack path mapping and risk analysis"

    def scan(self) -> None:
        host = self.target.host
        ecosystem = self.config.get("ecosystem", {})

        # Build the ecosystem graph
        nodes = self._discover_ecosystem(host, ecosystem)
        self.result.raw_data["ecosystem_nodes"] = [n.to_dict() for n in nodes]

        # Identify attack paths
        attack_paths = self._identify_attack_paths(nodes, ecosystem)
        self.result.raw_data["attack_paths"] = [p.to_dict() for p in attack_paths]

        # Assess each path
        for path in attack_paths:
            self.add_finding(
                title=f"Attack path: {path.name}",
                severity=Severity[path.severity.upper()],
                description=path.description,
                evidence=f"Path: {' -> '.join(path.nodes)}",
                remediation=self._get_remediation(path),
            )

        # Check network segmentation
        self._check_network_segmentation(ecosystem)

        # Check API security
        self._check_api_security(ecosystem)

        # Check cloud backend
        self._check_cloud_security(ecosystem)

        # Lateral movement assessment
        self._check_lateral_movement(nodes, ecosystem)

    def _discover_ecosystem(self, host: str, ecosystem: dict) -> list[AttackNode]:
        """Discover and map the IoT ecosystem components."""
        nodes = []

        # Device node
        device = AttackNode(
            name=f"device:{host}",
            node_type="device",
            risk_level="unknown",
        )
        self._probe_device(host, device)
        nodes.append(device)

        # Gateway node (if configured)
        gateway_host = ecosystem.get("gateway", {}).get("host", "")
        if gateway_host:
            gw = AttackNode(
                name=f"gateway:{gateway_host}",
                node_type="gateway",
                connections=[device.name],
            )
            device.connections.append(gw.name)
            self._probe_device(gateway_host, gw)
            nodes.append(gw)

        # Cloud endpoints
        for endpoint in ecosystem.get("cloud_endpoints", []):
            cloud = AttackNode(
                name=f"cloud:{endpoint.get('url', 'unknown')}",
                node_type="cloud",
                connections=[gateway_host and f"gateway:{gateway_host}" or device.name],
            )
            nodes.append(cloud)

        # API endpoints
        for api in ecosystem.get("apis", []):
            api_node = AttackNode(
                name=f"api:{api.get('url', 'unknown')}",
                node_type="api",
                connections=[],
            )
            nodes.append(api_node)

        # Mobile app (if exists)
        if ecosystem.get("mobile_app"):
            app_node = AttackNode(
                name="mobile_app",
                node_type="mobile",
                connections=[device.name],
            )
            device.connections.append(app_node.name)
            nodes.append(app_node)

        return nodes

    def _probe_device(self, host: str, node: AttackNode) -> None:
        """Probe a device to identify exposed services."""
        common_ports = [22, 23, 80, 443, 1883, 5683, 8080, 8443, 8883]
        open_ports = []

        for port in common_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(2)
                    if sock.connect_ex((host, port)) == 0:
                        open_ports.append(port)
            except OSError:
                continue

        if 23 in open_ports:
            node.vulnerabilities.append("telnet_exposed")
            node.risk_level = "high"
        if 80 in open_ports or 8080 in open_ports:
            node.vulnerabilities.append("http_unencrypted")
        if not any(p in open_ports for p in [443, 8443, 8883]):
            node.vulnerabilities.append("no_tls_services")
            if node.risk_level != "high":
                node.risk_level = "medium"

        if not node.vulnerabilities:
            node.risk_level = "low"

    def _identify_attack_paths(self, nodes: list[AttackNode], ecosystem: dict) -> list[AttackPath]:
        """Identify potential attack paths through the ecosystem."""
        paths = []

        device_nodes = [n for n in nodes if n.node_type == "device"]
        cloud_nodes = [n for n in nodes if n.node_type == "cloud"]
        gateway_nodes = [n for n in nodes if n.node_type == "gateway"]
        api_nodes = [n for n in nodes if n.node_type == "api"]

        # Path 1: Direct device compromise -> cloud
        for device in device_nodes:
            if device.vulnerabilities:
                for cloud in cloud_nodes:
                    paths.append(AttackPath(
                        name="Device-to-Cloud via direct compromise",
                        description=(
                            f"An attacker exploits vulnerabilities on {device.name} "
                            f"({', '.join(device.vulnerabilities)}) to gain device access, "
                            "then pivots to cloud services using stolen credentials or tokens."
                        ),
                        nodes=[device.name, cloud.name],
                        severity="critical" if "telnet_exposed" in device.vulnerabilities else "high",
                        prerequisites=["Network access to device"],
                    ))

        # Path 2: Device -> Gateway -> Cloud
        for device in device_nodes:
            for gw in gateway_nodes:
                for cloud in cloud_nodes:
                    paths.append(AttackPath(
                        name="Device-to-Gateway-to-Cloud lateral movement",
                        description=(
                            f"An attacker compromises {device.name}, moves laterally to "
                            f"the gateway ({gw.name}), and uses the gateway's elevated "
                            "cloud permissions to access backend services."
                        ),
                        nodes=[device.name, gw.name, cloud.name],
                        severity="critical",
                        prerequisites=["Device compromise", "Weak network segmentation"],
                    ))

        # Path 3: Network sniffing -> credential theft -> cloud access
        for device in device_nodes:
            if "http_unencrypted" in device.vulnerabilities or "no_tls_services" in device.vulnerabilities:
                for cloud in cloud_nodes:
                    paths.append(AttackPath(
                        name="Network eavesdropping to cloud credential theft",
                        description=(
                            f"Unencrypted traffic from {device.name} exposes credentials "
                            "or API tokens that can be used to access cloud services."
                        ),
                        nodes=["network_sniffer", device.name, cloud.name],
                        severity="high",
                        prerequisites=["Same network segment access"],
                    ))

        # Path 4: API exploitation
        for api in api_nodes:
            for cloud in cloud_nodes:
                paths.append(AttackPath(
                    name="API exploitation to cloud backend",
                    description=(
                        f"An attacker exploits weak API authentication or authorization "
                        f"at {api.name} to access or manipulate cloud resources."
                    ),
                    nodes=[api.name, cloud.name],
                    severity="high",
                    prerequisites=["API endpoint discovery"],
                ))

        # Path 5: Firmware -> extract secrets -> cloud access
        if ecosystem.get("firmware_accessible", False):
            for cloud in cloud_nodes:
                paths.append(AttackPath(
                    name="Firmware secret extraction to cloud access",
                    description=(
                        "An attacker extracts the firmware (via UART/JTAG/download), "
                        "finds embedded credentials, API keys, or certificates, and uses "
                        "them to authenticate to cloud services."
                    ),
                    nodes=["physical_access", "firmware", cloud.name],
                    severity="critical",
                    prerequisites=["Physical device access or firmware download"],
                ))

        # Path 6: Mobile app -> device/cloud
        mobile_nodes = [n for n in nodes if n.node_type == "mobile"]
        for app in mobile_nodes:
            for cloud in cloud_nodes:
                paths.append(AttackPath(
                    name="Mobile app reverse engineering to cloud access",
                    description=(
                        "An attacker reverse-engineers the companion mobile app to extract "
                        "API keys, endpoints, and authentication mechanisms for cloud access."
                    ),
                    nodes=[app.name, cloud.name],
                    severity="high",
                    prerequisites=["Access to mobile application binary"],
                ))

        return paths

    def _check_network_segmentation(self, ecosystem: dict) -> None:
        """Check if IoT devices are properly segmented from other networks."""
        network = ecosystem.get("network", {})

        if not network.get("iot_vlan", False):
            self.add_finding(
                title="IoT devices not on dedicated network segment",
                severity=Severity.HIGH,
                description=(
                    "IoT devices share the same network segment as other systems. "
                    "A compromised IoT device can be used to attack other network resources."
                ),
                remediation="Place IoT devices on a dedicated VLAN with strict firewall rules.",
            )

        if not network.get("egress_filtering", False):
            self.add_finding(
                title="No egress filtering for IoT network",
                severity=Severity.MEDIUM,
                description=(
                    "IoT devices can make arbitrary outbound connections. "
                    "A compromised device can exfiltrate data or participate in botnets."
                ),
                remediation="Implement egress filtering to allow only necessary outbound connections.",
            )

        if not network.get("ids_monitoring", False):
            self.add_finding(
                title="No intrusion detection on IoT network",
                severity=Severity.MEDIUM,
                description="No IDS/IPS monitoring detected on the IoT network segment.",
                remediation="Deploy network-level IDS/IPS to monitor IoT traffic for anomalies.",
            )

    def _check_api_security(self, ecosystem: dict) -> None:
        """Check API security between device and cloud."""
        for api in ecosystem.get("apis", []):
            url = api.get("url", "")
            auth_method = api.get("auth_method", "")

            if not auth_method or auth_method == "none":
                self.add_finding(
                    title=f"API has no authentication: {url}",
                    severity=Severity.CRITICAL,
                    description=f"The API at {url} does not require authentication.",
                    remediation="Implement API authentication (OAuth 2.0, mTLS, or API keys with rate limiting).",
                )
            elif auth_method == "api_key" and not api.get("rate_limiting", False):
                self.add_finding(
                    title=f"API key without rate limiting: {url}",
                    severity=Severity.MEDIUM,
                    description=f"The API at {url} uses API keys but has no rate limiting.",
                    remediation="Implement rate limiting and API key rotation policies.",
                )

            if not api.get("input_validation", True):
                self.add_finding(
                    title=f"API lacks input validation: {url}",
                    severity=Severity.HIGH,
                    description=f"The API at {url} does not properly validate inputs, risking injection attacks.",
                    remediation="Implement strict input validation and parameterized queries.",
                )

    def _check_cloud_security(self, ecosystem: dict) -> None:
        """Check cloud backend security configuration."""
        cloud = ecosystem.get("cloud", {})

        if not cloud.get("encryption_at_rest", True):
            self.add_finding(
                title="Cloud storage not encrypted at rest",
                severity=Severity.HIGH,
                description="IoT device data stored in the cloud is not encrypted at rest.",
                remediation="Enable encryption at rest for all stored IoT data.",
            )

        if not cloud.get("device_identity", False):
            self.add_finding(
                title="No unique device identity management",
                severity=Severity.HIGH,
                description=(
                    "Devices do not have unique cryptographic identities. "
                    "This makes it impossible to distinguish legitimate devices from clones."
                ),
                remediation="Provision unique X.509 certificates or use TPM-based device attestation.",
            )

        if cloud.get("shared_credentials", False):
            self.add_finding(
                title="Devices share cloud credentials",
                severity=Severity.CRITICAL,
                description=(
                    "Multiple devices use the same credentials to authenticate to cloud services. "
                    "Compromising one device exposes credentials for all devices."
                ),
                remediation="Provision unique per-device credentials. Use AWS IoT Core, Azure IoT Hub, or similar services.",
            )

    def _check_lateral_movement(self, nodes: list[AttackNode], ecosystem: dict) -> None:
        """Assess lateral movement opportunities in the ecosystem."""
        high_risk_nodes = [n for n in nodes if n.risk_level == "high"]

        if len(high_risk_nodes) >= 2:
            self.add_finding(
                title="Multiple high-risk nodes enable lateral movement",
                severity=Severity.CRITICAL,
                description=(
                    f"Found {len(high_risk_nodes)} high-risk nodes in the ecosystem: "
                    f"{', '.join(n.name for n in high_risk_nodes)}. "
                    "An attacker can chain these to move laterally through the infrastructure."
                ),
                remediation=(
                    "Address vulnerabilities on each node. Implement zero-trust networking. "
                    "Use micro-segmentation between IoT components."
                ),
            )

    @staticmethod
    def _get_remediation(path: AttackPath) -> str:
        """Generate remediation advice for an attack path."""
        remediations = []
        if "telnet" in path.description.lower():
            remediations.append("Disable telnet, use SSH with key authentication")
        if "unencrypted" in path.description.lower() or "eavesdrop" in path.description.lower():
            remediations.append("Encrypt all communications using TLS/DTLS")
        if "credential" in path.description.lower():
            remediations.append("Implement unique per-device credentials and rotate regularly")
        if "firmware" in path.description.lower():
            remediations.append("Remove secrets from firmware, use secure provisioning")
        if "gateway" in path.description.lower():
            remediations.append("Segment gateway with strict firewall rules")
        if "api" in path.description.lower():
            remediations.append("Implement API authentication, authorization, and rate limiting")
        if "mobile" in path.description.lower():
            remediations.append("Obfuscate mobile app, use certificate pinning, avoid embedded secrets")
        return ". ".join(remediations) + "." if remediations else "Implement defense-in-depth across the ecosystem."
