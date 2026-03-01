"""Prompt templates for AI-powered IoT security analysis."""

SYSTEM_PROMPT = """You are an expert IoT security analyst with deep knowledge of embedded systems, \
network protocols, firmware reverse engineering, and the OWASP IoT Top 10.

You analyze scan results from automated IoT security tools and provide:
1. Contextual risk assessment considering the specific device type and deployment
2. Prioritized remediation steps with effort estimates
3. Attack chain analysis showing how findings combine into exploitable paths
4. Executive summary suitable for non-technical stakeholders

Be specific, actionable, and reference industry standards (OWASP IoT, IEC 62443, NIST).
Never hallucinate CVEs or vulnerability details - only reference what the scan found."""

ANALYZE_FINDINGS_PROMPT = """Analyze these IoT security scan results and provide an expert assessment.

**Target:** {target}
**Device Type:** {device_type}
**Modules Run:** {modules}

**Findings Summary:**
- Critical: {critical_count}
- High: {high_count}
- Medium: {medium_count}
- Low: {low_count}
- Info: {info_count}

**Detailed Findings:**
{findings_detail}

Provide your analysis in this structure:

## Executive Summary
A 2-3 sentence summary of the overall security posture for a non-technical audience.

## Risk Assessment
Overall risk rating (Critical/High/Medium/Low) with justification.

## Top Priority Remediations
The 3-5 most impactful fixes, ordered by risk reduction. For each:
- What to fix
- Why it matters (attack scenario)
- Effort estimate (Quick fix / Medium / Major effort)

## Attack Chain Analysis
Describe 1-3 realistic attack scenarios that chain multiple findings together. \
Show step-by-step how an attacker would exploit them.

## Compliance Gaps
Map findings to OWASP IoT Top 10 categories and note any compliance standard violations \
(IEC 62443, NIST IoT, ETSI EN 303 645).
"""

ADAPTIVE_SCAN_PROMPT = """Based on these initial scan results, recommend additional scan actions.

**Target:** {target}
**Findings so far:**
{findings_summary}

**Available modules not yet run:** {available_modules}

For each recommendation:
1. Which module to run and with what configuration
2. Why (what the initial findings suggest should be investigated further)
3. Priority (High/Medium/Low)

Return your recommendations as a JSON array:
```json
[
  {{
    "module": "module_name",
    "reason": "why this module should run",
    "priority": "high",
    "config_overrides": {{}}
  }}
]
```
"""

FINDING_DEEP_DIVE_PROMPT = """Provide a deep technical analysis of this specific IoT security finding.

**Finding:** {title}
**Severity:** {severity}
**Module:** {module}
**Description:** {description}
**Evidence:** {evidence}
**Device Type:** {device_type}

Provide:
1. **Technical Explanation**: What exactly is vulnerable and why
2. **Exploitation Scenario**: Step-by-step how an attacker would exploit this
3. **Real-World Impact**: What damage could result (data breach, physical safety, botnet recruitment, etc.)
4. **Detailed Remediation**: Specific configuration changes, code fixes, or architecture changes needed
5. **Verification**: How to verify the fix was applied correctly
"""
