"""Base scanner class that all IoT pentesting modules extend."""

from __future__ import annotations

import abc
import logging
from datetime import datetime

from .models import Finding, ScanResult, ScanStatus, Severity, Target

logger = logging.getLogger(__name__)


class BaseScanner(abc.ABC):
    """Abstract base class for all IoT scanning modules."""

    name: str = "base"
    description: str = ""

    def __init__(self, target: Target, config: dict | None = None):
        self.target = target
        self.config = config or {}
        self.result = ScanResult(target=target, module_name=self.name)
        self.logger = logging.getLogger(f"iotscan.{self.name}")

    def run(self) -> ScanResult:
        self.result.status = ScanStatus.RUNNING
        self.result.start_time = datetime.utcnow().isoformat()
        try:
            self.scan()
            self.result.status = ScanStatus.COMPLETED
        except Exception as e:
            self.logger.error("Scan failed for %s: %s", self.name, e)
            self.result.status = ScanStatus.FAILED
            self.add_finding(
                title=f"Scan error in {self.name}",
                severity=Severity.INFO,
                description=f"Module encountered an error: {e}",
            )
        finally:
            self.result.end_time = datetime.utcnow().isoformat()
        return self.result

    @abc.abstractmethod
    def scan(self) -> None:
        """Execute the scan logic. Subclasses must implement this."""

    def add_finding(
        self,
        title: str,
        severity: Severity,
        description: str,
        evidence: str = "",
        remediation: str = "",
        cve: str = "",
    ) -> None:
        finding = Finding(
            title=title,
            severity=severity,
            module=self.name,
            description=description,
            evidence=evidence,
            remediation=remediation,
            cve=cve,
        )
        self.result.add_finding(finding)
        self.logger.info("Finding: [%s] %s", severity.value, title)
