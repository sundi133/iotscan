"""Web interface security testing module for IoT device admin panels."""

from __future__ import annotations

import re
import socket
import ssl
from contextlib import closing
from urllib.parse import quote

from ..base import BaseScanner
from ..models import Severity

# Paths commonly exposing sensitive data on IoT web interfaces
SENSITIVE_PATHS = [
    ("/cgi-bin/", "CGI scripts directory"),
    ("/debug", "Debug endpoint"),
    ("/debug/pprof", "Go profiling endpoint"),
    ("/server-status", "Apache server status"),
    ("/server-info", "Apache server info"),
    ("/.env", "Environment file"),
    ("/config.json", "Configuration file"),
    ("/config.yaml", "Configuration file"),
    ("/config.xml", "Configuration file"),
    ("/backup.tar.gz", "Backup archive"),
    ("/firmware.bin", "Firmware download"),
    ("/api/v1/system", "System API"),
    ("/api/config", "Configuration API"),
    ("/phpinfo.php", "PHP info page"),
    ("/console", "Management console"),
    ("/admin", "Admin panel"),
    ("/setup", "Setup wizard"),
    ("/diag.html", "Diagnostics page"),
    ("/syslog", "System log"),
    ("/log", "Log endpoint"),
    ("/goform/", "GoAhead web server forms"),
    ("/HNAP1/", "Home Network Administration Protocol"),
]

# Command injection test payloads (safe - detection only, no execution)
CMD_INJECTION_PROBES = [
    (";echo iotscan_test", "semicolon"),
    ("|echo iotscan_test", "pipe"),
    ("$(echo iotscan_test)", "subshell"),
    ("`echo iotscan_test`", "backtick"),
]

# Path traversal probes (read-only detection)
PATH_TRAVERSAL_PROBES = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

# Security headers every web interface should have
REQUIRED_HEADERS = {
    "X-Frame-Options": ("Clickjacking protection", Severity.MEDIUM),
    "X-Content-Type-Options": ("MIME sniffing protection", Severity.LOW),
    "Content-Security-Policy": ("Content Security Policy", Severity.MEDIUM),
    "Strict-Transport-Security": ("HSTS for HTTPS enforcement", Severity.HIGH),
    "X-XSS-Protection": ("XSS filter header", Severity.LOW),
}


class WebSecurityTester(BaseScanner):
    """Test IoT device web interfaces for common security vulnerabilities."""

    name = "web_security"
    description = "Web interface testing: exposed endpoints, injection, path traversal, headers, TLS"

    def scan(self) -> None:
        host = self.target.host
        port = self.target.port or 80

        # Detect if HTTPS is available
        https_port = self._detect_https(host, port)

        self._check_security_headers(host, port)
        self._probe_sensitive_paths(host, port)
        self._test_path_traversal(host, port)
        self._test_command_injection(host, port)
        self._check_cors(host, port)
        self._check_http_methods(host, port)

        if https_port:
            self._check_tls_security(host, https_port)
        elif port not in (443, 8443):
            self.add_finding(
                title="Web interface served over HTTP only",
                severity=Severity.HIGH,
                description="The device web interface has no HTTPS endpoint. All traffic including credentials is unencrypted.",
                remediation="Enable HTTPS on the device. Use a self-signed certificate at minimum.",
            )

    def _detect_https(self, host: str, http_port: int) -> int:
        """Check if HTTPS is available."""
        for port in [443, 8443, http_port]:
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with closing(socket.create_connection((host, port), timeout=3)) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host):
                        return port
            except (OSError, ssl.SSLError):
                continue
        return 0

    def _http_request(self, host: str, port: int, method: str, path: str) -> tuple[str, str]:
        """Make a raw HTTP request and return (status_line, full_response)."""
        use_ssl = port in (443, 8443)
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
                f"{method} {path} HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                f"User-Agent: iotscan/0.1\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode()
            sock.send(request)

            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) > 32768:
                    break

            sock.close()
            decoded = response.decode("utf-8", errors="ignore")
            status_line = decoded.split("\r\n", 1)[0] if decoded else ""
            return status_line, decoded

        except (OSError, ssl.SSLError):
            return "", ""

    # ── Security Headers ──────────────────────────────────────────

    def _check_security_headers(self, host: str, port: int) -> None:
        """Check for missing security headers on the web interface."""
        _status, response = self._http_request(host, port, "GET", "/")
        if not response:
            return

        # Extract headers section
        header_section = response.split("\r\n\r\n", 1)[0] if "\r\n\r\n" in response else response
        headers_lower = header_section.lower()

        missing = []
        for header, (desc, severity) in REQUIRED_HEADERS.items():
            if header.lower() not in headers_lower:
                missing.append((header, desc, severity))

        if missing:
            worst_severity = max(missing, key=lambda x: list(Severity).index(x[2]))[2]
            header_list = ", ".join(f"{h} ({d})" for h, d, _ in missing)
            self.add_finding(
                title=f"{len(missing)} security header(s) missing",
                severity=worst_severity,
                description=f"Missing headers: {header_list}",
                remediation="Configure the web server to include all recommended security headers.",
            )

        # Check for information disclosure headers
        for dangerous_header in ["X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]:
            if dangerous_header.lower() in headers_lower:
                match = re.search(rf"{dangerous_header}:\s*(.+)", header_section, re.IGNORECASE)
                value = match.group(1).strip() if match else "present"
                self.add_finding(
                    title=f"Information disclosure via {dangerous_header}",
                    severity=Severity.LOW,
                    description=f"Header '{dangerous_header}: {value}' reveals server technology stack.",
                    remediation=f"Remove the {dangerous_header} header from responses.",
                )

    # ── Sensitive Endpoint Discovery ──────────────────────────────

    def _probe_sensitive_paths(self, host: str, port: int) -> None:
        """Check for exposed sensitive endpoints on the web interface."""
        exposed = []

        for path, description in SENSITIVE_PATHS:
            status, response = self._http_request(host, port, "GET", path)
            if not status:
                continue

            # Consider it found if we get 200 OK (not 401/403/404)
            if "200" in status and "404" not in response[:500].lower():
                exposed.append((path, description))

        if exposed:
            paths_str = ", ".join(f"{p} ({d})" for p, d in exposed[:10])
            severity = Severity.CRITICAL if any(
                p in (".env", "config.json", "config.yaml", "backup.tar.gz", "firmware.bin")
                for p, _ in exposed
            ) else Severity.HIGH

            self.add_finding(
                title=f"{len(exposed)} sensitive endpoint(s) exposed",
                severity=severity,
                description=f"Accessible endpoints: {paths_str}",
                evidence=f"Found {len(exposed)} unprotected paths",
                remediation="Restrict access to administrative and sensitive endpoints. Require authentication. Remove unnecessary files.",
            )

        # Special check for HNAP (common in consumer routers, often vulnerable)
        for path, desc in exposed:
            if "HNAP" in path.upper():
                self.add_finding(
                    title="HNAP protocol exposed",
                    severity=Severity.HIGH,
                    description="Home Network Administration Protocol (HNAP) is exposed. HNAP has a history of authentication bypass and command injection vulnerabilities.",
                    remediation="Disable HNAP if not needed. Apply latest firmware patches.",
                )

    # ── Path Traversal ────────────────────────────────────────────

    def _test_path_traversal(self, host: str, port: int) -> None:
        """Test for directory traversal vulnerabilities."""
        for payload in PATH_TRAVERSAL_PROBES:
            # Test in common parameter positions
            test_paths = [
                f"/cgi-bin/viewfile?path={quote(payload)}",
                f"/download?file={quote(payload)}",
                f"/..%2f..%2f..%2fetc/passwd",
            ]

            for path in test_paths:
                _status, response = self._http_request(host, port, "GET", path)
                if not response:
                    continue

                # Check for /etc/passwd indicators in response
                if "root:" in response and "/bin/" in response:
                    self.add_finding(
                        title="Path traversal vulnerability confirmed",
                        severity=Severity.CRITICAL,
                        description="The web interface is vulnerable to directory traversal. An attacker can read arbitrary files from the device filesystem.",
                        evidence=f"Payload: {path} returned /etc/passwd content",
                        remediation="Sanitize file path inputs. Use a whitelist of allowed files. Never pass user input directly to filesystem APIs.",
                    )
                    return  # One finding is enough

    # ── Command Injection ─────────────────────────────────────────

    def _test_command_injection(self, host: str, port: int) -> None:
        """Test for command injection via common IoT diagnostic endpoints."""
        # Common endpoints that accept user input for diagnostics
        diagnostic_endpoints = [
            ("/ping", "ping_addr", "GET"),
            ("/diag", "host", "GET"),
            ("/tools/ping", "ip", "GET"),
            ("/cgi-bin/ping.cgi", "target", "GET"),
            ("/goform/formPing", "target_addr", "GET"),
        ]

        for endpoint, param, _method in diagnostic_endpoints:
            for payload, technique in CMD_INJECTION_PROBES:
                test_path = f"{endpoint}?{param}=127.0.0.1{quote(payload)}"
                _status, response = self._http_request(host, port, "GET", test_path)

                if response and "iotscan_test" in response:
                    self.add_finding(
                        title=f"Command injection via {endpoint}",
                        severity=Severity.CRITICAL,
                        description=(
                            f"The diagnostic endpoint {endpoint} is vulnerable to OS command injection "
                            f"via {technique} technique. An attacker can execute arbitrary system commands."
                        ),
                        evidence=f"Payload: {test_path} reflected injected output",
                        remediation=(
                            "Never pass user input to shell commands. Use parameterized system calls. "
                            "Validate input against strict allowlists (IP address regex)."
                        ),
                    )
                    return  # One finding is enough

    # ── CORS ──────────────────────────────────────────────────────

    def _check_cors(self, host: str, port: int) -> None:
        """Check for overly permissive CORS configuration."""
        use_ssl = port in (443, 8443)
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
                f"OPTIONS / HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                f"Origin: https://evil.example.com\r\n"
                f"Access-Control-Request-Method: GET\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode()
            sock.send(request)
            response = sock.recv(4096).decode("utf-8", errors="ignore")
            sock.close()

            if "Access-Control-Allow-Origin: *" in response:
                self.add_finding(
                    title="CORS allows all origins (wildcard *)",
                    severity=Severity.MEDIUM,
                    description="The web interface sets Access-Control-Allow-Origin: *. Any website can make authenticated requests to the device.",
                    remediation="Restrict CORS to specific trusted origins instead of using wildcard.",
                )
            elif "evil.example.com" in response:
                self.add_finding(
                    title="CORS reflects arbitrary Origin header",
                    severity=Severity.HIGH,
                    description="The web interface reflects the Origin header in CORS responses, allowing any website to make cross-origin requests.",
                    remediation="Validate Origin against a whitelist of allowed domains.",
                )
        except (OSError, ssl.SSLError):
            pass

    # ── HTTP Methods ──────────────────────────────────────────────

    def _check_http_methods(self, host: str, port: int) -> None:
        """Check for dangerous HTTP methods enabled."""
        status, response = self._http_request(host, port, "OPTIONS", "/")
        if not response:
            return

        allow_match = re.search(r"Allow:\s*(.+)", response, re.IGNORECASE)
        if allow_match:
            methods = [m.strip().upper() for m in allow_match.group(1).split(",")]
            dangerous = {"PUT", "DELETE", "TRACE", "CONNECT"}
            found_dangerous = dangerous & set(methods)

            if found_dangerous:
                self.add_finding(
                    title=f"Dangerous HTTP method(s) enabled: {', '.join(found_dangerous)}",
                    severity=Severity.MEDIUM,
                    description=f"The web server allows {', '.join(found_dangerous)} methods which can be used for file upload, deletion, or XST attacks.",
                    evidence=f"Allow header: {allow_match.group(1)}",
                    remediation="Disable PUT, DELETE, TRACE, and CONNECT methods on the web server.",
                )

    # ── TLS ───────────────────────────────────────────────────────

    def _check_tls_security(self, host: str, port: int) -> None:
        """Check TLS configuration of the web interface."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with closing(socket.create_connection((host, port), timeout=5)) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                    cert = tls_sock.getpeercert(binary_form=False)
                    protocol = tls_sock.version()
                    cipher = tls_sock.cipher()

                    if protocol in ("TLSv1", "TLSv1.1"):
                        self.add_finding(
                            title=f"Web interface uses deprecated {protocol}",
                            severity=Severity.HIGH,
                            description=f"The HTTPS endpoint negotiated {protocol} which is deprecated and has known vulnerabilities.",
                            remediation="Configure TLS 1.2 as the minimum supported version.",
                        )

                    if cipher:
                        cipher_name = cipher[0]
                        weak_ciphers = ["RC4", "DES", "3DES", "NULL", "EXPORT", "anon"]
                        if any(weak in cipher_name for weak in weak_ciphers):
                            self.add_finding(
                                title=f"Weak TLS cipher: {cipher_name}",
                                severity=Severity.HIGH,
                                description=f"The HTTPS endpoint uses weak cipher {cipher_name}.",
                                remediation="Disable weak ciphers. Use AES-GCM or ChaCha20-Poly1305.",
                            )

            # Also check with strict verification
            try:
                strict_ctx = ssl.create_default_context()
                with closing(socket.create_connection((host, port), timeout=5)) as sock:
                    strict_ctx.wrap_socket(sock, server_hostname=host)
            except ssl.SSLCertVerificationError:
                self.add_finding(
                    title="Self-signed or invalid TLS certificate",
                    severity=Severity.MEDIUM,
                    description="The HTTPS certificate fails validation (self-signed, expired, or hostname mismatch).",
                    remediation="Use a valid TLS certificate. For internal devices, deploy a private CA.",
                )
        except (OSError, ssl.SSLError) as e:
            self.logger.debug("TLS check error: %s", e)
