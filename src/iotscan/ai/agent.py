"""AI-powered IoT security analysis agent.

Provides LLM-driven reasoning over scan results for intelligent analysis,
adaptive scanning, and executive reporting. Supports multiple LLM providers.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field

from ..models import OWASP_IOT_TOP10, Finding, Severity
from .prompts import (
    ADAPTIVE_SCAN_PROMPT,
    ANALYZE_FINDINGS_PROMPT,
    FINDING_DEEP_DIVE_PROMPT,
    SYSTEM_PROMPT,
)

logger = logging.getLogger(__name__)


@dataclass
class AIAnalysis:
    """Result of AI-powered scan analysis."""

    executive_summary: str = ""
    risk_rating: str = ""
    priority_remediations: list[dict] = field(default_factory=list)
    attack_chains: list[dict] = field(default_factory=list)
    compliance_gaps: list[dict] = field(default_factory=list)
    raw_analysis: str = ""
    adaptive_recommendations: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "executive_summary": self.executive_summary,
            "risk_rating": self.risk_rating,
            "priority_remediations": self.priority_remediations,
            "attack_chains": self.attack_chains,
            "compliance_gaps": self.compliance_gaps,
            "adaptive_recommendations": self.adaptive_recommendations,
        }


class SecurityAnalysisAgent:
    """AI agent that reasons about IoT scan results and provides intelligent analysis.

    Supports Anthropic Claude, OpenAI, and local/offline fallback modes.
    Set the provider via IOTSCAN_AI_PROVIDER env var (anthropic, openai, offline).
    API keys: ANTHROPIC_API_KEY or OPENAI_API_KEY.
    """

    def __init__(self, provider: str = "", model: str = ""):
        self.provider = provider or os.environ.get("IOTSCAN_AI_PROVIDER", "offline")
        self.model = model
        self.api_key = ""
        self._client = None

        if self.provider == "anthropic":
            self.api_key = os.environ.get("ANTHROPIC_API_KEY", "")
            self.model = self.model or "claude-sonnet-4-20250514"
        elif self.provider == "openai":
            self.api_key = os.environ.get("OPENAI_API_KEY", "")
            self.model = self.model or "gpt-4o"

    def analyze_scan(self, summary: dict) -> AIAnalysis:
        """Analyze complete scan results and generate an intelligent report."""
        findings_detail = self._format_findings(summary)

        breakdown = summary.get("severity_breakdown", {})
        prompt = ANALYZE_FINDINGS_PROMPT.format(
            target=summary.get("target", "unknown"),
            device_type=summary.get("device_type", "IoT device"),
            modules=", ".join(summary.get("modules_run", [])),
            critical_count=breakdown.get("critical", 0),
            high_count=breakdown.get("high", 0),
            medium_count=breakdown.get("medium", 0),
            low_count=breakdown.get("low", 0),
            info_count=breakdown.get("info", 0),
            findings_detail=findings_detail,
        )

        if self.provider == "offline":
            return self._offline_analysis(summary)

        raw = self._call_llm(prompt)
        return self._parse_analysis(raw, summary)

    def get_adaptive_recommendations(self, summary: dict, available_modules: list[str]) -> list[dict]:
        """Use AI to recommend which additional modules to run based on initial findings."""
        findings_summary = self._format_findings_brief(summary)

        prompt = ADAPTIVE_SCAN_PROMPT.format(
            target=summary.get("target", "unknown"),
            findings_summary=findings_summary,
            available_modules=", ".join(available_modules),
        )

        if self.provider == "offline":
            return self._offline_adaptive(summary, available_modules)

        raw = self._call_llm(prompt)
        return self._parse_adaptive(raw)

    def deep_dive_finding(self, finding: dict, device_type: str = "") -> str:
        """Generate a deep technical analysis of a specific finding."""
        prompt = FINDING_DEEP_DIVE_PROMPT.format(
            title=finding.get("title", ""),
            severity=finding.get("severity", ""),
            module=finding.get("module", ""),
            description=finding.get("description", ""),
            evidence=finding.get("evidence", ""),
            device_type=device_type or "IoT device",
        )

        if self.provider == "offline":
            return self._offline_deep_dive(finding)

        return self._call_llm(prompt)

    def _call_llm(self, prompt: str) -> str:
        """Call the configured LLM provider."""
        if self.provider == "anthropic":
            return self._call_anthropic(prompt)
        elif self.provider == "openai":
            return self._call_openai(prompt)
        return ""

    def _call_anthropic(self, prompt: str) -> str:
        """Call Anthropic Claude API."""
        try:
            import anthropic

            if not self._client:
                self._client = anthropic.Anthropic(api_key=self.api_key)

            response = self._client.messages.create(
                model=self.model,
                max_tokens=4096,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
            return response.content[0].text
        except ImportError:
            logger.warning("anthropic package not installed. Run: pip install anthropic")
            return ""
        except Exception as e:
            logger.error("Anthropic API error: %s", e)
            return ""

    def _call_openai(self, prompt: str) -> str:
        """Call OpenAI API."""
        try:
            import openai

            if not self._client:
                self._client = openai.OpenAI(api_key=self.api_key)

            response = self._client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=4096,
            )
            return response.choices[0].message.content
        except ImportError:
            logger.warning("openai package not installed. Run: pip install openai")
            return ""
        except Exception as e:
            logger.error("OpenAI API error: %s", e)
            return ""

    # ── Offline / Rule-Based Fallback ─────────────────────────────

    def _offline_analysis(self, summary: dict) -> AIAnalysis:
        """Generate analysis using rule-based logic when no LLM is available."""
        analysis = AIAnalysis()
        breakdown = summary.get("severity_breakdown", {})
        total = summary.get("total_findings", 0)
        critical = breakdown.get("critical", 0)
        high = breakdown.get("high", 0)

        # Risk rating
        if critical > 0:
            analysis.risk_rating = "CRITICAL"
        elif high > 0:
            analysis.risk_rating = "HIGH"
        elif breakdown.get("medium", 0) > 0:
            analysis.risk_rating = "MEDIUM"
        else:
            analysis.risk_rating = "LOW"

        # Executive summary
        analysis.executive_summary = (
            f"Security assessment of {summary.get('target', 'the target device')} identified "
            f"{total} finding(s) across {len(summary.get('modules_run', []))} module(s). "
            f"{critical} critical and {high} high severity issues require immediate attention. "
            f"Overall risk level: {analysis.risk_rating}."
        )

        # Priority remediations from critical/high findings
        all_findings = []
        for module_result in summary.get("module_results", []):
            for finding in module_result.get("findings", []):
                all_findings.append(finding)

        critical_high = sorted(
            [f for f in all_findings if f.get("severity") in ("critical", "high")],
            key=lambda f: 0 if f.get("severity") == "critical" else 1,
        )

        for finding in critical_high[:5]:
            analysis.priority_remediations.append({
                "title": finding.get("title", ""),
                "severity": finding.get("severity", ""),
                "remediation": finding.get("remediation", ""),
                "effort": self._estimate_effort(finding),
                "owasp_iot": finding.get("owasp_iot", ""),
            })

        # Attack chain analysis
        analysis.attack_chains = self._build_attack_chains(all_findings)

        # Compliance gaps
        analysis.compliance_gaps = self._map_compliance(all_findings)

        return analysis

    def _offline_adaptive(self, summary: dict, available_modules: list[str]) -> list[dict]:
        """Rule-based adaptive scan recommendations."""
        recommendations = []
        all_findings = []
        modules_run = set(summary.get("modules_run", []))

        for module_result in summary.get("module_results", []):
            for finding in module_result.get("findings", []):
                all_findings.append(finding)

        finding_titles = " ".join(f.get("title", "").lower() for f in all_findings)

        # If credentials found, recommend web security
        if "web" in available_modules and "web_security" not in modules_run:
            if any(kw in finding_titles for kw in ["credential", "password", "default", "telnet"]):
                recommendations.append({
                    "module": "web",
                    "reason": "Default credentials found - web interface likely has additional vulnerabilities",
                    "priority": "high",
                    "config_overrides": {},
                })

        # If firmware secrets found, recommend attack path mapping
        if "attack_paths" in available_modules and "attack_path_mapper" not in modules_run:
            if any(kw in finding_titles for kw in ["hardcoded", "private key", "api key"]):
                recommendations.append({
                    "module": "attack_paths",
                    "reason": "Embedded secrets found in firmware - need to map how they connect to cloud services",
                    "priority": "high",
                    "config_overrides": {"ecosystem": {"firmware_accessible": True}},
                })

        # If network services found, recommend credential checking
        if "credentials" in available_modules and "credential_checker" not in modules_run:
            if any(kw in finding_titles for kw in ["open service", "telnet", "ssh", "http"]):
                recommendations.append({
                    "module": "credentials",
                    "reason": "Network services discovered - should test for default/weak credentials",
                    "priority": "high",
                    "config_overrides": {},
                })

        # If MQTT/CoAP found, recommend protocol testing
        if "protocols" in available_modules and "protocol_testing" not in modules_run:
            if any(kw in finding_titles for kw in ["mqtt", "coap", "1883", "5683"]):
                recommendations.append({
                    "module": "protocols",
                    "reason": "IoT protocol services detected - need detailed protocol security testing",
                    "priority": "high",
                    "config_overrides": {},
                })

        # Always recommend OTA if firmware was analyzed
        if "ota" in available_modules and "ota_analyzer" not in modules_run:
            if "firmware_analysis" in modules_run:
                recommendations.append({
                    "module": "ota",
                    "reason": "Firmware was analyzed - OTA update mechanism should be validated",
                    "priority": "medium",
                    "config_overrides": {},
                })

        return recommendations

    def _offline_deep_dive(self, finding: dict) -> str:
        """Rule-based deep dive for a specific finding."""
        title = finding.get("title", "")
        severity = finding.get("severity", "")
        description = finding.get("description", "")
        remediation = finding.get("remediation", "")

        return (
            f"## Deep Dive: {title}\n\n"
            f"**Severity:** {severity.upper()}\n\n"
            f"### Technical Details\n{description}\n\n"
            f"### Remediation\n{remediation}\n\n"
            f"### Verification\n"
            f"After applying the fix, re-run the scan with the same configuration "
            f"and verify this finding no longer appears."
        )

    @staticmethod
    def _estimate_effort(finding: dict) -> str:
        """Estimate remediation effort based on finding type."""
        title = finding.get("title", "").lower()
        if any(kw in title for kw in ["default credential", "permit join", "anonymous"]):
            return "Quick fix (< 1 hour)"
        if any(kw in title for kw in ["tls", "header", "telnet", "debug"]):
            return "Medium (1-4 hours)"
        if any(kw in title for kw in ["firmware signing", "secure boot", "hardening", "encryption"]):
            return "Major effort (days-weeks)"
        return "Medium (hours)"

    @staticmethod
    def _build_attack_chains(findings: list[dict]) -> list[dict]:
        """Build attack chains from related findings."""
        chains = []
        titles = [f.get("title", "").lower() for f in findings]
        titles_str = " ".join(titles)

        # Chain: default creds -> device access -> cloud pivot
        if ("default" in titles_str or "anonymous" in titles_str) and (
            "hardcoded" in titles_str or "api key" in titles_str
        ):
            chains.append({
                "name": "Credential Chain to Cloud Access",
                "steps": [
                    "Attacker uses default credentials to access device admin interface",
                    "Extracts stored API keys or cloud tokens from device",
                    "Uses extracted credentials to access cloud backend",
                ],
                "risk": "critical",
            })

        # Chain: telnet -> firmware dump -> secret extraction
        if "telnet" in titles_str and ("unsafe" in titles_str or "hardcoded" in titles_str):
            chains.append({
                "name": "Telnet to Full Device Compromise",
                "steps": [
                    "Attacker connects to exposed telnet service",
                    "Gains shell access via default credentials",
                    "Dumps firmware from flash storage",
                    "Extracts embedded credentials and private keys",
                ],
                "risk": "critical",
            })

        # Chain: unsigned OTA -> malicious firmware -> botnet
        if "not cryptographically signed" in titles_str or "unencrypted http" in titles_str:
            chains.append({
                "name": "Firmware Supply Chain Attack",
                "steps": [
                    "Attacker performs MITM on update channel",
                    "Injects malicious firmware update",
                    "Device installs and runs attacker's code",
                    "Device joins botnet or exfiltrates data",
                ],
                "risk": "critical",
            })

        return chains

    @staticmethod
    def _map_compliance(findings: list[dict]) -> list[dict]:
        """Map findings to compliance framework categories."""
        gaps = []
        owasp_seen = set()

        for finding in findings:
            owasp = finding.get("owasp_iot", "")
            if owasp and owasp not in owasp_seen:
                owasp_seen.add(owasp)
                gaps.append({
                    "standard": "OWASP IoT Top 10",
                    "category": f"{owasp}: {OWASP_IOT_TOP10.get(owasp, '')}",
                    "finding": finding.get("title", ""),
                    "severity": finding.get("severity", ""),
                })

        return gaps

    # ── Helpers ───────────────────────────────────────────────────

    def _format_findings(self, summary: dict) -> str:
        """Format all findings into a detailed string for LLM consumption."""
        lines = []
        for module_result in summary.get("module_results", []):
            module = module_result.get("module", "unknown")
            for finding in module_result.get("findings", []):
                owasp = f" [OWASP {finding.get('owasp_iot', '')}]" if finding.get("owasp_iot") else ""
                cvss = f" (CVSS {finding.get('cvss_score', '')})" if finding.get("cvss_score") else ""
                lines.append(
                    f"- [{finding.get('severity', 'info').upper()}]{owasp}{cvss} "
                    f"({module}) {finding.get('title', '')}: {finding.get('description', '')}"
                )
                if finding.get("evidence"):
                    lines.append(f"  Evidence: {finding['evidence']}")
                if finding.get("cve"):
                    lines.append(f"  CVE: {finding['cve']}")
        return "\n".join(lines) if lines else "No findings."

    def _format_findings_brief(self, summary: dict) -> str:
        """Format findings briefly for adaptive recommendations."""
        lines = []
        for module_result in summary.get("module_results", []):
            for finding in module_result.get("findings", []):
                if finding.get("severity") in ("critical", "high", "medium"):
                    lines.append(
                        f"- [{finding.get('severity', '').upper()}] {finding.get('title', '')}"
                    )
        return "\n".join(lines) if lines else "No significant findings."

    def _parse_analysis(self, raw: str, summary: dict) -> AIAnalysis:
        """Parse LLM response into structured AIAnalysis."""
        analysis = AIAnalysis(raw_analysis=raw)

        # Extract sections from markdown
        sections = raw.split("##")
        for section in sections:
            section_lower = section.lower().strip()
            if section_lower.startswith("executive summary"):
                analysis.executive_summary = section.split("\n", 1)[-1].strip()
            elif section_lower.startswith("risk assessment"):
                content = section.split("\n", 1)[-1].strip()
                analysis.risk_rating = content.split("\n")[0].strip() if content else ""

        # Keep the full raw for rich display
        return analysis

    def _parse_adaptive(self, raw: str) -> list[dict]:
        """Parse LLM adaptive recommendations from response."""
        try:
            # Try to extract JSON array from the response
            start = raw.find("[")
            end = raw.rfind("]") + 1
            if start != -1 and end > start:
                return json.loads(raw[start:end])
        except (json.JSONDecodeError, ValueError):
            logger.debug("Could not parse adaptive recommendations as JSON")
        return []
