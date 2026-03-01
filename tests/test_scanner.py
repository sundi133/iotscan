"""Tests for the main scanner orchestrator."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import yaml

from iotscan.models import Target
from iotscan.scanner import ALL_MODULES, IoTScanner


def test_scanner_all_modules_registered():
    assert "firmware" in ALL_MODULES
    assert "protocols" in ALL_MODULES
    assert "credentials" in ALL_MODULES
    assert "ota" in ALL_MODULES
    assert "attack_paths" in ALL_MODULES


def test_scanner_run_specific_module():
    target = Target(host="192.168.1.1", firmware_path="/nonexistent")
    scanner = IoTScanner(target=target, modules=["firmware"])
    results = scanner.run()
    assert len(results) == 1
    assert results[0].module_name == "firmware_analysis"


def test_scanner_skip_unknown_module():
    target = Target(host="192.168.1.1")
    scanner = IoTScanner(target=target, modules=["nonexistent_module"])
    results = scanner.run()
    assert len(results) == 0


def test_scanner_summary():
    target = Target(host="192.168.1.1", firmware_path="/nonexistent")
    scanner = IoTScanner(target=target, modules=["firmware"])
    scanner.run()
    summary = scanner.get_summary()

    assert summary["target"] == "192.168.1.1"
    assert "firmware_analysis" in summary["modules_run"]
    assert "severity_breakdown" in summary
    assert "total_findings" in summary


def test_scanner_export_json():
    target = Target(host="192.168.1.1", firmware_path="/nonexistent")
    scanner = IoTScanner(target=target, modules=["firmware"])
    scanner.run()

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        output_path = scanner.export_json(f.name)
        assert Path(output_path).exists()

        with open(output_path) as rf:
            data = json.load(rf)
            assert data["target"] == "192.168.1.1"

    Path(output_path).unlink(missing_ok=True)


def test_scanner_from_config_file():
    config = {
        "target": {
            "host": "10.0.0.1",
            "port": 1883,
            "protocol": "mqtt",
        },
        "modules": ["firmware"],
        "config": {},
    }

    with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
        yaml.dump(config, f)
        f.flush()

        scanner = IoTScanner.from_config_file(f.name)
        assert scanner.target.host == "10.0.0.1"
        assert scanner.target.port == 1883
        assert scanner.module_names == ["firmware"]

    Path(f.name).unlink(missing_ok=True)
