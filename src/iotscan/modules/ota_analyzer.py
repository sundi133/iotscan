"""OTA (Over-The-Air) update mechanism analyzer for IoT devices."""

from __future__ import annotations

import hashlib
import re
import socket
import ssl
from pathlib import Path
from urllib.parse import urlparse

from ..base import BaseScanner
from ..models import Severity


class OTAAnalyzer(BaseScanner):
    """Analyze OTA update mechanisms for security vulnerabilities."""

    name = "ota_analyzer"
    description = "OTA update mechanism security analysis"

    def scan(self) -> None:
        host = self.target.host

        self._check_update_transport(host)
        self._check_firmware_signing()
        self._check_rollback_protection()
        self._check_update_server_security(host)
        self._check_differential_updates()

        if self.target.firmware_path:
            self._analyze_update_binary(self.target.firmware_path)

    def _check_update_transport(self, host: str) -> None:
        """Check if firmware updates are delivered over secure transport."""
        ota_config = self.config.get("ota", {})
        update_url = ota_config.get("update_url", "")

        if update_url:
            parsed = urlparse(update_url)

            if parsed.scheme == "http":
                self.add_finding(
                    title="OTA updates delivered over unencrypted HTTP",
                    severity=Severity.CRITICAL,
                    description=(
                        "Firmware updates are fetched over plain HTTP. An attacker can perform "
                        "a man-in-the-middle attack to inject malicious firmware."
                    ),
                    evidence=f"Update URL: {update_url}",
                    remediation="Use HTTPS with certificate pinning for firmware downloads.",
                )
            elif parsed.scheme == "https":
                self._verify_tls_config(parsed.hostname, parsed.port or 443)
            elif parsed.scheme in ("ftp", "tftp"):
                self.add_finding(
                    title="OTA updates use insecure FTP/TFTP protocol",
                    severity=Severity.CRITICAL,
                    description=f"Firmware updates use {parsed.scheme.upper()} which provides no encryption or authentication.",
                    evidence=f"Update URL: {update_url}",
                    remediation="Switch to HTTPS with certificate pinning for firmware distribution.",
                )

        # Check if device accepts firmware from any source
        if ota_config.get("allow_custom_server", False):
            self.add_finding(
                title="Device accepts updates from custom servers",
                severity=Severity.HIGH,
                description=(
                    "The device can be configured to fetch updates from arbitrary servers. "
                    "An attacker with device access could redirect updates to a malicious server."
                ),
                remediation="Restrict update sources to manufacturer's servers. Use certificate pinning.",
            )

    def _verify_tls_config(self, hostname: str, port: int) -> None:
        """Verify TLS configuration of the update server."""
        if not hostname:
            return
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                    cert = tls_sock.getpeercert()
                    protocol = tls_sock.version()
                    cipher = tls_sock.cipher()

                    if protocol in ("TLSv1", "TLSv1.1"):
                        self.add_finding(
                            title="OTA server uses deprecated TLS version",
                            severity=Severity.HIGH,
                            description=f"Update server uses {protocol} which is deprecated.",
                            remediation="Configure server for TLS 1.2+ only.",
                        )

                    if cipher and "RC4" in cipher[0]:
                        self.add_finding(
                            title="OTA server uses weak cipher",
                            severity=Severity.HIGH,
                            description=f"Update server negotiated weak cipher: {cipher[0]}",
                            remediation="Disable RC4 and other weak ciphers on the update server.",
                        )

                    self.add_finding(
                        title="OTA update server TLS verified",
                        severity=Severity.INFO,
                        description=f"Update server uses {protocol} with cipher {cipher[0] if cipher else 'unknown'}.",
                    )
        except ssl.SSLCertVerificationError as e:
            self.add_finding(
                title="OTA server has invalid TLS certificate",
                severity=Severity.HIGH,
                description=f"The update server's TLS certificate failed verification: {e}",
                remediation="Fix the server certificate. Ensure the device validates certificates properly.",
            )
        except (socket.timeout, OSError) as e:
            self.logger.debug("TLS verification error for %s:%d: %s", hostname, port, e)

    def _check_firmware_signing(self) -> None:
        """Check if firmware updates are cryptographically signed."""
        ota_config = self.config.get("ota", {})

        signing_method = ota_config.get("signing_method", "")
        if not signing_method or signing_method == "none":
            self.add_finding(
                title="Firmware updates are not cryptographically signed",
                severity=Severity.CRITICAL,
                description=(
                    "The device does not verify firmware signatures before installation. "
                    "An attacker can flash arbitrary firmware onto the device."
                ),
                remediation=(
                    "Implement firmware signing using Ed25519 or RSA-2048+ signatures. "
                    "Verify signatures in a secure bootloader before installation."
                ),
            )
        else:
            if signing_method.lower() in ("md5", "crc32", "sha1"):
                self.add_finding(
                    title="Firmware uses weak integrity check instead of signing",
                    severity=Severity.HIGH,
                    description=(
                        f"Firmware uses {signing_method.upper()} for integrity verification. "
                        "This is a hash/checksum, not a cryptographic signature - it can be forged."
                    ),
                    evidence=f"Signing method: {signing_method}",
                    remediation="Use asymmetric cryptographic signatures (Ed25519, ECDSA, RSA) instead of checksums.",
                )
            elif signing_method.lower() in ("rsa", "ecdsa", "ed25519"):
                key_size = ota_config.get("key_size", 0)
                if signing_method.lower() == "rsa" and key_size and key_size < 2048:
                    self.add_finding(
                        title="Firmware signing uses weak RSA key",
                        severity=Severity.HIGH,
                        description=f"Firmware is signed with RSA-{key_size}, which is below recommended minimum.",
                        remediation="Use RSA-2048 or stronger. Consider Ed25519 for better performance on constrained devices.",
                    )
                else:
                    self.add_finding(
                        title="Firmware signing verified",
                        severity=Severity.INFO,
                        description=f"Firmware uses {signing_method} signing.",
                    )

    def _check_rollback_protection(self) -> None:
        """Check if the device has anti-rollback protection for firmware."""
        ota_config = self.config.get("ota", {})

        if not ota_config.get("rollback_protection", False):
            self.add_finding(
                title="No firmware rollback protection",
                severity=Severity.HIGH,
                description=(
                    "The device does not prevent installation of older firmware versions. "
                    "An attacker can downgrade to a version with known vulnerabilities."
                ),
                remediation=(
                    "Implement anti-rollback using monotonic version counters stored in "
                    "one-time programmable (OTP) fuses or secure storage."
                ),
            )

        if not ota_config.get("secure_boot", False):
            self.add_finding(
                title="Secure boot not enabled",
                severity=Severity.HIGH,
                description=(
                    "The device does not use secure boot, so it cannot guarantee firmware integrity "
                    "from boot time. Persistent rootkits can survive firmware updates."
                ),
                remediation="Enable secure boot chain from ROM bootloader through application firmware.",
            )

    def _check_update_server_security(self, host: str) -> None:
        """Check the update server configuration for security issues."""
        ota_config = self.config.get("ota", {})
        update_url = ota_config.get("update_url", "")

        if not update_url:
            return

        parsed = urlparse(update_url)
        server = parsed.hostname

        if not server:
            return

        # Check if update URL uses IP instead of hostname
        ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        if ip_pattern.match(server):
            self.add_finding(
                title="OTA update URL uses IP address instead of hostname",
                severity=Severity.MEDIUM,
                description=(
                    "The update URL uses a hardcoded IP address rather than a hostname. "
                    "This makes certificate validation harder and complicates server migration."
                ),
                remediation="Use a fully qualified domain name for the update server.",
            )

        # Check for certificate pinning configuration
        if not ota_config.get("certificate_pinning", False):
            self.add_finding(
                title="No certificate pinning for OTA updates",
                severity=Severity.MEDIUM,
                description=(
                    "The device does not pin the update server's certificate. "
                    "A compromised CA could issue a rogue certificate for MITM attacks."
                ),
                remediation="Implement certificate pinning (pin the leaf or intermediate CA certificate).",
            )

    def _check_differential_updates(self) -> None:
        """Check differential/delta update security."""
        ota_config = self.config.get("ota", {})

        if ota_config.get("delta_updates", False):
            if not ota_config.get("delta_signing", False):
                self.add_finding(
                    title="Delta updates not individually signed",
                    severity=Severity.HIGH,
                    description=(
                        "Delta/differential firmware updates are not signed independently. "
                        "A malicious delta patch could be injected."
                    ),
                    remediation="Sign delta update packages independently from full firmware images.",
                )

    def _analyze_update_binary(self, firmware_path: str) -> None:
        """Analyze a firmware update binary for security properties."""
        path = Path(firmware_path)
        if not path.exists():
            return

        data = path.read_bytes()

        # Check for plaintext URLs in firmware that indicate update endpoints
        text = data.decode("latin-1", errors="ignore")
        http_urls = re.findall(r"http://[^\s\x00\"'<>]+", text)
        https_urls = re.findall(r"https://[^\s\x00\"'<>]+", text)

        if http_urls:
            unique_http = list(set(http_urls))[:5]
            self.add_finding(
                title="Plaintext HTTP URLs found in firmware",
                severity=Severity.MEDIUM,
                description=f"Found {len(http_urls)} HTTP URL(s) in firmware binary that may be update endpoints.",
                evidence=f"Sample URLs: {unique_http}",
                remediation="Replace all HTTP URLs with HTTPS equivalents.",
            )

        # Check for update-related strings
        update_keywords = ["firmware_update", "ota_update", "fwupdate", "upgrade", "download_fw"]
        found_keywords = [kw for kw in update_keywords if kw in text.lower()]
        if found_keywords:
            self.result.raw_data["ota_keywords_found"] = found_keywords
