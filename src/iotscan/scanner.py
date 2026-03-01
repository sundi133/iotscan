"""Main scanner orchestrator that coordinates all IoT pentesting modules."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path

import yaml

from .base import BaseScanner
from .models import ScanResult, Severity, Target
from .modules import (
    AttackPathMapper,
    CredentialChecker,
    FirmwareAnalyzer,
    OTAAnalyzer,
    ProtocolTester,
)

logger = logging.getLogger(__name__)

ALL_MODULES: dict[str, type[BaseScanner]] = {
    "firmware": FirmwareAnalyzer,
    "protocols": ProtocolTester,
    "credentials": CredentialChecker,
    "ota": OTAAnalyzer,
    "attack_paths": AttackPathMapper,
}


class IoTScanner:
    """Orchestrate IoT security scanning across all modules."""

    def __init__(
        self,
        target: Target,
        modules: list[str] | None = None,
        config: dict | None = None,
    ):
        self.target = target
        self.config = config or {}
        self.module_names = modules or list(ALL_MODULES.keys())
        self.results: list[ScanResult] = []
        self.start_time = ""
        self.end_time = ""

    @classmethod
    def from_config_file(cls, config_path: str) -> IoTScanner:
        """Create a scanner instance from a YAML config file."""
        path = Path(config_path)
        with open(path) as f:
            config = yaml.safe_load(f)

        target_cfg = config.get("target", {})
        target = Target(
            host=target_cfg.get("host", ""),
            port=target_cfg.get("port", 0),
            protocol=target_cfg.get("protocol", ""),
            device_type=target_cfg.get("device_type", ""),
            firmware_path=target_cfg.get("firmware_path", ""),
            metadata=target_cfg.get("metadata", {}),
        )

        return cls(
            target=target,
            modules=config.get("modules"),
            config=config.get("config", {}),
        )

    def run(self) -> list[ScanResult]:
        """Execute all configured scanning modules."""
        self.start_time = datetime.utcnow().isoformat()
        logger.info("Starting IoT security scan of %s", self.target.host)

        for module_name in self.module_names:
            if module_name not in ALL_MODULES:
                logger.warning("Unknown module: %s (skipping)", module_name)
                continue

            logger.info("Running module: %s", module_name)
            scanner_cls = ALL_MODULES[module_name]
            scanner = scanner_cls(target=self.target, config=self.config)
            result = scanner.run()
            self.results.append(result)

            finding_count = len(result.findings)
            critical = result.critical_count
            logger.info(
                "Module %s completed: %d findings (%d critical)",
                module_name, finding_count, critical,
            )

        self.end_time = datetime.utcnow().isoformat()
        logger.info("Scan complete. Total findings: %d", self.total_findings)
        return self.results

    @property
    def total_findings(self) -> int:
        return sum(len(r.findings) for r in self.results)

    @property
    def total_critical(self) -> int:
        return sum(r.critical_count for r in self.results)

    @property
    def total_high(self) -> int:
        return sum(r.high_count for r in self.results)

    def get_summary(self) -> dict:
        """Generate a scan summary."""
        severity_counts = {s.value: 0 for s in Severity}
        for result in self.results:
            for finding in result.findings:
                severity_counts[finding.severity.value] += 1

        return {
            "target": self.target.host,
            "scan_start": self.start_time,
            "scan_end": self.end_time,
            "modules_run": [r.module_name for r in self.results],
            "total_findings": self.total_findings,
            "severity_breakdown": severity_counts,
            "module_results": [r.to_dict() for r in self.results],
        }

    def export_json(self, output_path: str) -> str:
        """Export scan results to JSON."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        summary = self.get_summary()
        with open(path, "w") as f:
            json.dump(summary, f, indent=2)
        return str(path)
