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
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity.value,
            "module": self.module,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cve": self.cve,
            "timestamp": self.timestamp,
        }


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
