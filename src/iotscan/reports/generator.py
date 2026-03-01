"""Report generation for IoT security scan results."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from ..models import Severity


def generate_text_report(summary: dict) -> str:
    """Generate a human-readable text report from scan summary."""
    lines = []
    lines.append("=" * 72)
    lines.append("  IoT Security Scan Report")
    lines.append("=" * 72)
    lines.append("")
    lines.append(f"  Target:     {summary['target']}")
    lines.append(f"  Scan Start: {summary.get('scan_start', 'N/A')}")
    lines.append(f"  Scan End:   {summary.get('scan_end', 'N/A')}")
    lines.append(f"  Modules:    {', '.join(summary.get('modules_run', []))}")
    lines.append("")

    # Severity breakdown
    breakdown = summary.get("severity_breakdown", {})
    lines.append("-" * 72)
    lines.append("  FINDINGS SUMMARY")
    lines.append("-" * 72)
    lines.append(f"  Total Findings: {summary.get('total_findings', 0)}")
    lines.append("")
    severity_order = ["critical", "high", "medium", "low", "info"]
    severity_icons = {
        "critical": "[!!!]",
        "high": "[!! ]",
        "medium": "[!  ]",
        "low": "[.  ]",
        "info": "[i  ]",
    }
    for sev in severity_order:
        count = breakdown.get(sev, 0)
        icon = severity_icons.get(sev, "     ")
        lines.append(f"  {icon} {sev.upper():10s}: {count}")
    lines.append("")

    # Per-module findings
    for module_result in summary.get("module_results", []):
        module_name = module_result.get("module", "unknown")
        findings = module_result.get("findings", [])
        lines.append("-" * 72)
        lines.append(f"  MODULE: {module_name}")
        lines.append(f"  Status: {module_result.get('status', 'unknown')}")
        lines.append(f"  Findings: {len(findings)}")
        lines.append("-" * 72)

        for i, finding in enumerate(findings, 1):
            sev = finding.get("severity", "info")
            icon = severity_icons.get(sev, "     ")
            lines.append("")
            lines.append(f"  {icon} #{i}: {finding.get('title', 'Untitled')}")
            lines.append(f"       Severity: {sev.upper()}")
            lines.append(f"       {finding.get('description', '')}")
            if finding.get("evidence"):
                lines.append(f"       Evidence: {finding['evidence']}")
            if finding.get("cve"):
                lines.append(f"       CVE: {finding['cve']}")
            if finding.get("owasp_iot"):
                owasp_title = finding.get("owasp_iot_title", "")
                lines.append(f"       OWASP IoT: {finding['owasp_iot']} - {owasp_title}")
            if finding.get("cvss_score"):
                lines.append(f"       CVSS: {finding['cvss_score']}/10.0")
            if finding.get("remediation"):
                lines.append(f"       Fix: {finding['remediation']}")

        lines.append("")

    lines.append("=" * 72)
    lines.append(f"  Report generated: {datetime.utcnow().isoformat()}")
    lines.append("=" * 72)
    return "\n".join(lines)


def generate_json_report(summary: dict, output_path: str) -> str:
    """Write the scan summary as formatted JSON."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(summary, f, indent=2)
    return str(path)


def generate_html_report(summary: dict) -> str:
    """Generate an HTML report from scan summary."""
    severity_colors = {
        "critical": "#dc3545",
        "high": "#fd7e14",
        "medium": "#ffc107",
        "low": "#17a2b8",
        "info": "#6c757d",
    }

    findings_html = ""
    for module_result in summary.get("module_results", []):
        module_name = module_result.get("module", "unknown")
        findings = module_result.get("findings", [])

        findings_html += f'<h2>{_escape(module_name)}</h2>\n'
        findings_html += f'<p>Status: {_escape(module_result.get("status", "unknown"))}</p>\n'

        for finding in findings:
            sev = finding.get("severity", "info")
            color = severity_colors.get(sev, "#6c757d")
            findings_html += f"""
            <div style="border-left: 4px solid {color}; padding: 10px; margin: 10px 0; background: #f8f9fa;">
                <strong style="color: {color};">[{_escape(sev.upper())}]</strong>
                <strong>{_escape(finding.get('title', ''))}</strong>
                <p>{_escape(finding.get('description', ''))}</p>
                {"<p><em>Evidence:</em> " + _escape(finding.get('evidence', '')) + "</p>" if finding.get('evidence') else ""}
                {"<p><em>CVE:</em> " + _escape(finding.get('cve', '')) + "</p>" if finding.get('cve') else ""}
                {"<p><em>OWASP IoT:</em> " + _escape(finding.get('owasp_iot', '') + ' - ' + finding.get('owasp_iot_title', '')) + "</p>" if finding.get('owasp_iot') else ""}
                {"<p><em>CVSS:</em> " + str(finding.get('cvss_score', '')) + "/10.0</p>" if finding.get('cvss_score') else ""}
                {"<p><strong>Remediation:</strong> " + _escape(finding.get('remediation', '')) + "</p>" if finding.get('remediation') else ""}
            </div>
            """

    breakdown = summary.get("severity_breakdown", {})
    return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>IoT Security Scan Report - {_escape(summary.get('target', ''))}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; }}
        h1 {{ color: #333; border-bottom: 2px solid #333; padding-bottom: 10px; }}
        .summary {{ display: flex; gap: 20px; flex-wrap: wrap; }}
        .stat {{ background: #f8f9fa; padding: 15px; border-radius: 8px; min-width: 120px; text-align: center; }}
        .stat .count {{ font-size: 2em; font-weight: bold; }}
    </style>
</head>
<body>
    <h1>IoT Security Scan Report</h1>
    <p><strong>Target:</strong> {_escape(summary.get('target', ''))}</p>
    <p><strong>Scan Time:</strong> {_escape(summary.get('scan_start', ''))} - {_escape(summary.get('scan_end', ''))}</p>

    <div class="summary">
        <div class="stat"><div class="count" style="color: #dc3545;">{breakdown.get('critical', 0)}</div>Critical</div>
        <div class="stat"><div class="count" style="color: #fd7e14;">{breakdown.get('high', 0)}</div>High</div>
        <div class="stat"><div class="count" style="color: #ffc107;">{breakdown.get('medium', 0)}</div>Medium</div>
        <div class="stat"><div class="count" style="color: #17a2b8;">{breakdown.get('low', 0)}</div>Low</div>
        <div class="stat"><div class="count" style="color: #6c757d;">{breakdown.get('info', 0)}</div>Info</div>
    </div>

    {findings_html}

    <hr>
    <p><em>Report generated: {datetime.utcnow().isoformat()}</em></p>
</body>
</html>"""


def _escape(text: str) -> str:
    """Escape HTML special characters."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
