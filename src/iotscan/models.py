"""Core data models for iotscan findings and targets."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime


class Severity(enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# OWASP IoT Top 10 (2018) mapping
OWASP_IOT_TOP10 = {
    "I1": "Weak, Guessable, or Hardcoded Passwords",
    "I2": "Insecure Network Services",
    "I3": "Insecure Ecosystem Interfaces",
    "I4": "Lack of Secure Update Mechanism",
    "I5": "Use of Insecure or Outdated Components",
    "I6": "Insufficient Privacy Protection",
    "I7": "Insecure Data Transfer and Storage",
    "I8": "Lack of Device Management",
    "I9": "Insecure Default Settings",
    "I10": "Lack of Physical Hardening",
}


class ScanStatus(enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class Finding:
    title: str
    severity: Severity
    module: str
    description: str
    evidence: str = ""
    remediation: str = ""
    cve: str = ""
    owasp_iot: str = ""  # e.g. "I1", "I5"
    cvss_score: float = 0.0  # 0.0 - 10.0
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict:
        d = {
            "title": self.title,
            "severity": self.severity.value,
            "module": self.module,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cve": self.cve,
            "timestamp": self.timestamp,
        }
        if self.owasp_iot:
            d["owasp_iot"] = self.owasp_iot
            d["owasp_iot_title"] = OWASP_IOT_TOP10.get(self.owasp_iot, "")
        if self.cvss_score > 0:
            d["cvss_score"] = self.cvss_score
        return d


@dataclass
class Target:
    host: str
    port: int = 0
    protocol: str = ""
    device_type: str = ""
    firmware_path: str = ""
    metadata: dict = field(default_factory=dict)


@dataclass
class ScanResult:
    target: Target
    module_name: str
    status: ScanStatus = ScanStatus.PENDING
    findings: list[Finding] = field(default_factory=list)
    start_time: str = ""
    end_time: str = ""
    raw_data: dict = field(default_factory=dict)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    def to_dict(self) -> dict:
        return {
            "target": self.target.host,
            "module": self.module_name,
            "status": self.status.value,
            "findings": [f.to_dict() for f in self.findings],
            "start_time": self.start_time,
            "end_time": self.end_time,
            "summary": {
                "total": len(self.findings),
                "critical": self.critical_count,
                "high": self.high_count,
            },
        }
