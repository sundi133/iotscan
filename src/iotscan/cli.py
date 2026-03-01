"""Command-line interface for iotscan IoT security pentesting toolkit."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .models import Target
from .reports.generator import generate_html_report, generate_json_report, generate_text_report
from .scanner import ALL_MODULES, IoTScanner

console = Console()

BANNER = r"""
  _       _
 (_) ___ | |_ ___  ___ __ _ _ __
 | |/ _ \| __/ __|/ __/ _` | '_ \
 | | (_) | |_\__ \ (_| (_| | | | |
 |_|\___/ \__|___/\___\__,_|_| |_|

 IoT Security Pentesting Toolkit v0.1.0
"""


@click.group()
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose output")
@click.option("-q", "--quiet", is_flag=True, help="Suppress non-essential output")
def main(verbose: bool, quiet: bool) -> None:
    """iotscan - IoT Security Pentesting Toolkit.

    Firmware analysis, protocol testing, credential checks,
    OTA update analysis, and device-to-cloud attack path mapping.
    """
    level = logging.DEBUG if verbose else (logging.WARNING if quiet else logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    if not quiet:
        console.print(BANNER, style="bold cyan")


@main.command()
@click.argument("host")
@click.option("-p", "--port", type=int, default=0, help="Target port")
@click.option("--protocol", type=click.Choice(["auto", "mqtt", "coap", "zigbee", "ble"]), default="auto")
@click.option("--firmware", type=click.Path(exists=True), help="Path to firmware binary")
@click.option("--device-type", default="", help="Device type (camera, router, sensor, etc.)")
@click.option("-m", "--modules", multiple=True, help="Modules to run (default: all)")
@click.option("-c", "--config", type=click.Path(exists=True), help="YAML config file")
@click.option("-o", "--output", type=click.Path(), help="Output file path")
@click.option("--format", "output_format", type=click.Choice(["text", "json", "html"]), default="text")
def scan(
    host: str,
    port: int,
    protocol: str,
    firmware: str | None,
    device_type: str,
    modules: tuple[str, ...],
    config: str | None,
    output: str | None,
    output_format: str,
) -> None:
    """Run IoT security scan against a target.

    Examples:

        iotscan scan 192.168.1.100

        iotscan scan 192.168.1.100 -p 1883 --protocol mqtt

        iotscan scan 192.168.1.100 --firmware ./firmware.bin -m firmware -m credentials

        iotscan scan 192.168.1.100 -c config.yaml -o report.html --format html
    """
    if config:
        scanner = IoTScanner.from_config_file(config)
    else:
        target = Target(
            host=host,
            port=port,
            protocol=protocol,
            device_type=device_type,
            firmware_path=firmware or "",
        )
        module_list = list(modules) if modules else None
        scanner = IoTScanner(target=target, modules=module_list)

    with console.status("[bold green]Scanning...", spinner="dots"):
        results = scanner.run()

    summary = scanner.get_summary()
    _display_results(summary)

    if output:
        if output_format == "json":
            generate_json_report(summary, output)
        elif output_format == "html":
            path = Path(output)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(generate_html_report(summary))
        else:
            path = Path(output)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(generate_text_report(summary))
        console.print(f"\nReport saved to: [bold]{output}[/bold]")

    # Exit with non-zero if critical findings
    if scanner.total_critical > 0:
        sys.exit(2)
    elif scanner.total_high > 0:
        sys.exit(1)


@main.command("list-modules")
def list_modules() -> None:
    """List available scanning modules."""
    table = Table(title="Available Modules")
    table.add_column("Module", style="cyan")
    table.add_column("Description")

    for name, cls in ALL_MODULES.items():
        table.add_row(name, cls.description)

    console.print(table)


@main.command()
@click.argument("config_path", type=click.Path())
def init_config(config_path: str) -> None:
    """Generate a sample configuration file.

    Example: iotscan init-config config.yaml
    """
    sample = {
        "target": {
            "host": "192.168.1.100",
            "port": 0,
            "protocol": "auto",
            "device_type": "smart_camera",
            "firmware_path": "",
        },
        "modules": ["firmware", "protocols", "credentials", "ota", "attack_paths"],
        "config": {
            "mqtt_tls_port": 8883,
            "coap_dtls_port": 5684,
            "zigbee": {
                "network_key": "",
                "security_mode": "standard",
                "permit_join": False,
                "touchlink_enabled": True,
            },
            "ble": {
                "pairing_mode": "just_works",
                "encryption_enabled": True,
                "version": "4.2",
                "writable_characteristics": [],
                "exposes_device_name": False,
                "exposes_mac": False,
            },
            "ota": {
                "update_url": "",
                "signing_method": "none",
                "key_size": 0,
                "rollback_protection": False,
                "secure_boot": False,
                "certificate_pinning": False,
                "allow_custom_server": False,
                "delta_updates": False,
                "delta_signing": False,
            },
            "ecosystem": {
                "gateway": {"host": ""},
                "cloud_endpoints": [],
                "apis": [],
                "mobile_app": False,
                "firmware_accessible": False,
                "network": {
                    "iot_vlan": False,
                    "egress_filtering": False,
                    "ids_monitoring": False,
                },
                "cloud": {
                    "encryption_at_rest": True,
                    "device_identity": False,
                    "shared_credentials": False,
                },
            },
        },
    }

    import yaml

    path = Path(config_path)
    with open(path, "w") as f:
        yaml.dump(sample, f, default_flow_style=False, sort_keys=False)

    console.print(f"Sample config written to: [bold]{config_path}[/bold]")
    console.print("Edit the file and run: [cyan]iotscan scan <host> -c {config_path}[/cyan]")


def _display_results(summary: dict) -> None:
    """Display scan results in the terminal with rich formatting."""
    breakdown = summary.get("severity_breakdown", {})

    # Summary panel
    summary_text = (
        f"[bold]Target:[/bold] {summary.get('target', 'N/A')}\n"
        f"[bold]Modules:[/bold] {', '.join(summary.get('modules_run', []))}\n"
        f"[bold]Total Findings:[/bold] {summary.get('total_findings', 0)}\n\n"
        f"[bold red]Critical: {breakdown.get('critical', 0)}[/bold red]  "
        f"[bold yellow]High: {breakdown.get('high', 0)}[/bold yellow]  "
        f"Medium: {breakdown.get('medium', 0)}  "
        f"Low: {breakdown.get('low', 0)}  "
        f"Info: {breakdown.get('info', 0)}"
    )
    console.print(Panel(summary_text, title="Scan Summary", border_style="green"))

    # Findings table
    table = Table(title="Findings")
    table.add_column("#", style="dim", width=4)
    table.add_column("Severity", width=10)
    table.add_column("Module", width=20)
    table.add_column("Title")

    severity_styles = {
        "critical": "bold red",
        "high": "bold yellow",
        "medium": "yellow",
        "low": "cyan",
        "info": "dim",
    }

    idx = 0
    for module_result in summary.get("module_results", []):
        for finding in module_result.get("findings", []):
            idx += 1
            sev = finding.get("severity", "info")
            style = severity_styles.get(sev, "")
            table.add_row(
                str(idx),
                f"[{style}]{sev.upper()}[/{style}]",
                finding.get("module", ""),
                finding.get("title", ""),
            )

    console.print(table)


if __name__ == "__main__":
    main()
