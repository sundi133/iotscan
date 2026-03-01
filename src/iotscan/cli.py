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
        "modules": ["firmware", "protocols", "credentials", "ota", "attack_paths", "network", "web"],
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


@main.command("agent-scan")
@click.argument("host")
@click.option("-p", "--port", type=int, default=0, help="Target port")
@click.option("--firmware", type=click.Path(exists=True), help="Path to firmware binary")
@click.option("--device-type", default="IoT device", help="Device type for contextual analysis")
@click.option("-c", "--config", type=click.Path(exists=True), help="YAML config file")
@click.option("-o", "--output", type=click.Path(), help="Output file path")
@click.option("--format", "output_format", type=click.Choice(["text", "json", "html"]), default="text")
@click.option("--ai-provider", type=click.Choice(["anthropic", "openai", "offline"]), default="offline")
@click.option("--ai-model", default="", help="AI model override")
def agent_scan(
    host: str,
    port: int,
    firmware: str | None,
    device_type: str,
    config: str | None,
    output: str | None,
    output_format: str,
    ai_provider: str,
    ai_model: str,
) -> None:
    """AI-powered adaptive scan that reasons about results and adjusts strategy.

    The agent scan runs in phases:
    1. Discovery - initial network and service scan
    2. Analysis - AI analyzes initial findings to determine next steps
    3. Deep scan - runs targeted modules based on AI recommendations
    4. Report - generates AI-powered analysis with attack chains and remediation

    Examples:

        iotscan agent-scan 192.168.1.100

        iotscan agent-scan 192.168.1.100 --firmware fw.bin --device-type smart_camera

        ANTHROPIC_API_KEY=sk-... iotscan agent-scan 192.168.1.100 --ai-provider anthropic
    """
    from .ai.agent import SecurityAnalysisAgent

    agent = SecurityAnalysisAgent(provider=ai_provider, model=ai_model)

    if config:
        scanner = IoTScanner.from_config_file(config)
    else:
        target = Target(
            host=host,
            port=port,
            device_type=device_type,
            firmware_path=firmware or "",
        )
        # Phase 1: Start with discovery modules
        scanner = IoTScanner(target=target, modules=["network", "credentials"])

    # ── Phase 1: Discovery ─────────────────────────────────────
    console.print(Panel("[bold]Phase 1: Discovery & Reconnaissance[/bold]", border_style="blue"))
    with console.status("[bold blue]Running discovery scan...", spinner="dots"):
        scanner.run()

    summary = scanner.get_summary()
    summary["device_type"] = device_type
    _display_results(summary)

    # ── Phase 2: AI Analysis & Adaptive Recommendations ────────
    console.print(Panel("[bold]Phase 2: AI Analysis & Adaptive Planning[/bold]", border_style="magenta"))

    modules_run = set(summary.get("modules_run", []))
    available = [m for m in ALL_MODULES if m not in _module_name_to_key(modules_run)]

    with console.status("[bold magenta]AI agent analyzing findings...", spinner="dots"):
        recommendations = agent.get_adaptive_recommendations(summary, available)

    if recommendations:
        rec_table = Table(title="AI Recommended Next Steps")
        rec_table.add_column("Priority", width=10)
        rec_table.add_column("Module", width=15)
        rec_table.add_column("Reason")
        for rec in recommendations:
            priority = rec.get("priority", "medium")
            style = "bold red" if priority == "high" else ("yellow" if priority == "medium" else "dim")
            rec_table.add_row(
                f"[{style}]{priority.upper()}[/{style}]",
                rec.get("module", ""),
                rec.get("reason", ""),
            )
        console.print(rec_table)
    else:
        console.print("[dim]No additional modules recommended.[/dim]")

    # ── Phase 3: Deep Scan ─────────────────────────────────────
    adaptive_modules = [r["module"] for r in recommendations if r.get("priority") in ("high", "medium")]

    # Also add firmware if a firmware path was provided
    if firmware and "firmware" not in modules_run and "firmware" not in adaptive_modules:
        adaptive_modules.insert(0, "firmware")

    # Add OTA and web if not already scheduled
    for extra in ("web", "ota"):
        if extra not in modules_run and extra not in adaptive_modules and extra in ALL_MODULES:
            adaptive_modules.append(extra)

    if adaptive_modules:
        console.print(Panel(
            f"[bold]Phase 3: Deep Scan ({', '.join(adaptive_modules)})[/bold]",
            border_style="green",
        ))

        target2 = scanner.target
        deep_scanner = IoTScanner(
            target=target2,
            modules=adaptive_modules,
            config=scanner.config,
        )

        with console.status("[bold green]Running deep scan...", spinner="dots"):
            deep_scanner.run()

        deep_summary = deep_scanner.get_summary()
        _display_results(deep_summary)

        # Merge results for final analysis
        merged_summary = _merge_summaries(summary, deep_summary)
    else:
        merged_summary = summary

    # ── Phase 4: AI-Powered Report ─────────────────────────────
    console.print(Panel("[bold]Phase 4: AI Security Analysis[/bold]", border_style="cyan"))

    with console.status("[bold cyan]AI agent generating security analysis...", spinner="dots"):
        analysis = agent.analyze_scan(merged_summary)

    # Display executive summary
    console.print(Panel(
        f"[bold]Risk Rating: [{_risk_color(analysis.risk_rating)}]"
        f"{analysis.risk_rating}[/{_risk_color(analysis.risk_rating)}][/bold]\n\n"
        f"{analysis.executive_summary}",
        title="Executive Summary",
        border_style="cyan",
    ))

    # Display priority remediations
    if analysis.priority_remediations:
        rem_table = Table(title="Priority Remediations")
        rem_table.add_column("#", width=3)
        rem_table.add_column("Severity", width=10)
        rem_table.add_column("Finding")
        rem_table.add_column("Effort", width=25)
        rem_table.add_column("OWASP", width=6)
        for i, rem in enumerate(analysis.priority_remediations, 1):
            sev = rem.get("severity", "")
            style = "bold red" if sev == "critical" else ("bold yellow" if sev == "high" else "")
            rem_table.add_row(
                str(i),
                f"[{style}]{sev.upper()}[/{style}]",
                rem.get("title", ""),
                rem.get("effort", ""),
                rem.get("owasp_iot", ""),
            )
        console.print(rem_table)

    # Display attack chains
    if analysis.attack_chains:
        for chain in analysis.attack_chains:
            chain_text = f"[bold]{chain.get('name', '')}[/bold] (Risk: {chain.get('risk', '').upper()})\n\n"
            for j, step in enumerate(chain.get("steps", []), 1):
                chain_text += f"  {j}. {step}\n"
            console.print(Panel(chain_text, title="Attack Chain", border_style="red"))

    # Display compliance gaps
    if analysis.compliance_gaps:
        comp_table = Table(title="Compliance Gaps")
        comp_table.add_column("Standard")
        comp_table.add_column("Category")
        comp_table.add_column("Finding")
        for gap in analysis.compliance_gaps:
            comp_table.add_row(gap.get("standard", ""), gap.get("category", ""), gap.get("finding", ""))
        console.print(comp_table)

    # Save report
    if output:
        merged_summary["ai_analysis"] = analysis.to_dict()
        if output_format == "json":
            generate_json_report(merged_summary, output)
        elif output_format == "html":
            path = Path(output)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(generate_html_report(merged_summary))
        else:
            path = Path(output)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(generate_text_report(merged_summary))
        console.print(f"\nReport saved to: [bold]{output}[/bold]")

    total_findings = merged_summary.get("total_findings", 0)
    breakdown = merged_summary.get("severity_breakdown", {})
    console.print(
        f"\n[bold]Scan complete.[/bold] "
        f"{total_findings} findings "
        f"({breakdown.get('critical', 0)} critical, {breakdown.get('high', 0)} high)"
    )


@main.command("analyze")
@click.argument("report_file", type=click.Path(exists=True))
@click.option("--ai-provider", type=click.Choice(["anthropic", "openai", "offline"]), default="offline")
@click.option("--ai-model", default="", help="AI model override")
@click.option("--finding", type=int, default=0, help="Deep dive into a specific finding by number")
def analyze(report_file: str, ai_provider: str, ai_model: str, finding: int) -> None:
    """Run AI analysis on a previously generated JSON report.

    Examples:

        iotscan analyze report.json

        iotscan analyze report.json --finding 3

        ANTHROPIC_API_KEY=sk-... iotscan analyze report.json --ai-provider anthropic
    """
    from .ai.agent import SecurityAnalysisAgent

    with open(report_file) as f:
        summary = json.load(f)

    agent = SecurityAnalysisAgent(provider=ai_provider, model=ai_model)

    if finding > 0:
        # Deep dive into a specific finding
        all_findings = []
        for module_result in summary.get("module_results", []):
            for f_item in module_result.get("findings", []):
                all_findings.append(f_item)

        if finding > len(all_findings):
            console.print(f"[red]Finding #{finding} not found. Total findings: {len(all_findings)}[/red]")
            return

        target_finding = all_findings[finding - 1]
        console.print(Panel(
            f"[bold]Deep Dive: {target_finding.get('title', '')}[/bold]",
            border_style="cyan",
        ))

        with console.status("[bold cyan]AI analyzing finding...", spinner="dots"):
            deep = agent.deep_dive_finding(target_finding, summary.get("device_type", ""))

        from rich.markdown import Markdown
        console.print(Markdown(deep))
    else:
        # Full analysis
        with console.status("[bold cyan]AI analyzing scan results...", spinner="dots"):
            analysis = agent.analyze_scan(summary)

        console.print(Panel(
            f"[bold]Risk Rating: [{_risk_color(analysis.risk_rating)}]"
            f"{analysis.risk_rating}[/{_risk_color(analysis.risk_rating)}][/bold]\n\n"
            f"{analysis.executive_summary}",
            title="AI Security Analysis",
            border_style="cyan",
        ))

        if analysis.priority_remediations:
            rem_table = Table(title="Priority Remediations")
            rem_table.add_column("#", width=3)
            rem_table.add_column("Finding")
            rem_table.add_column("Effort")
            for i, rem in enumerate(analysis.priority_remediations, 1):
                rem_table.add_row(str(i), rem.get("title", ""), rem.get("effort", ""))
            console.print(rem_table)

        if analysis.attack_chains:
            for chain in analysis.attack_chains:
                steps = "\n".join(f"  {j}. {s}" for j, s in enumerate(chain.get("steps", []), 1))
                console.print(Panel(
                    f"[bold]{chain.get('name', '')}[/bold]\n\n{steps}",
                    title="Attack Chain",
                    border_style="red",
                ))


def _module_name_to_key(module_names: set[str]) -> set[str]:
    """Map scanner module_name values back to ALL_MODULES keys."""
    name_to_key = {cls.name: key for key, cls in ALL_MODULES.items()}
    return {name_to_key.get(name, name) for name in module_names}


def _merge_summaries(s1: dict, s2: dict) -> dict:
    """Merge two scan summaries."""
    b1 = s1.get("severity_breakdown", {})
    b2 = s2.get("severity_breakdown", {})
    merged_breakdown = {}
    for sev in ("critical", "high", "medium", "low", "info"):
        merged_breakdown[sev] = b1.get(sev, 0) + b2.get(sev, 0)

    return {
        "target": s1.get("target", s2.get("target", "")),
        "device_type": s1.get("device_type", s2.get("device_type", "")),
        "scan_start": s1.get("scan_start", ""),
        "scan_end": s2.get("scan_end", s1.get("scan_end", "")),
        "modules_run": list(set(s1.get("modules_run", []) + s2.get("modules_run", []))),
        "total_findings": s1.get("total_findings", 0) + s2.get("total_findings", 0),
        "severity_breakdown": merged_breakdown,
        "module_results": s1.get("module_results", []) + s2.get("module_results", []),
    }


def _risk_color(risk: str) -> str:
    """Return rich color for risk rating."""
    risk_lower = risk.lower()
    if risk_lower == "critical":
        return "bold red"
    if risk_lower == "high":
        return "bold yellow"
    if risk_lower == "medium":
        return "yellow"
    return "green"


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
