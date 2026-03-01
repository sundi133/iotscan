"""Tests for the web security testing module."""

from iotscan.models import Target
from iotscan.modules.web_security import WebSecurityTester, SENSITIVE_PATHS, REQUIRED_HEADERS


def test_web_security_name():
    target = Target(host="192.168.1.1")
    scanner = WebSecurityTester(target=target)
    assert scanner.name == "web_security"


def test_sensitive_paths_populated():
    assert len(SENSITIVE_PATHS) >= 10
    paths = [p for p, _ in SENSITIVE_PATHS]
    assert "/.env" in paths
    assert "/admin" in paths
    assert "/debug" in paths


def test_required_headers_defined():
    assert "X-Frame-Options" in REQUIRED_HEADERS
    assert "Content-Security-Policy" in REQUIRED_HEADERS
    assert "Strict-Transport-Security" in REQUIRED_HEADERS


def test_path_traversal_probes():
    from iotscan.modules.web_security import PATH_TRAVERSAL_PROBES
    assert any("etc/passwd" in p for p in PATH_TRAVERSAL_PROBES)
    assert len(PATH_TRAVERSAL_PROBES) >= 3


def test_cmd_injection_probes():
    from iotscan.modules.web_security import CMD_INJECTION_PROBES
    assert len(CMD_INJECTION_PROBES) >= 3
    techniques = [t for _, t in CMD_INJECTION_PROBES]
    assert "semicolon" in techniques
    assert "pipe" in techniques
