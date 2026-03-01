"""Tests for the AI security analysis agent."""

from iotscan.ai.agent import AIAnalysis, SecurityAnalysisAgent


def _make_summary(critical=1, high=2, medium=1, low=0, info=1):
    """Create a mock scan summary for testing."""
    return {
        "target": "192.168.1.100",
        "device_type": "smart_camera",
        "scan_start": "2026-01-01T00:00:00",
        "scan_end": "2026-01-01T00:01:00",
        "modules_run": ["credential_checker", "firmware_analysis"],
        "total_findings": critical + high + medium + low + info,
        "severity_breakdown": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "info": info,
        },
        "module_results": [
            {
                "module": "credential_checker",
                "status": "completed",
                "findings": [
                    {
                        "title": "Default HTTP credentials accepted on port 80",
                        "severity": "critical",
                        "module": "credential_checker",
                        "description": "Device accepts admin:admin",
                        "evidence": "admin:admin",
                        "remediation": "Change default credentials",
                        "owasp_iot": "I1",
                        "cvss_score": 9.8,
                    },
                    {
                        "title": "Telnet service is accessible",
                        "severity": "high",
                        "module": "credential_checker",
                        "description": "Telnet is open on port 23",
                        "remediation": "Disable telnet",
                        "owasp_iot": "I2",
                    },
                ],
            },
            {
                "module": "firmware_analysis",
                "status": "completed",
                "findings": [
                    {
                        "title": "Hardcoded API key found in firmware",
                        "severity": "high",
                        "module": "firmware_analysis",
                        "description": "API key embedded in binary",
                        "remediation": "Remove hardcoded keys",
                        "owasp_iot": "I1",
                    },
                    {
                        "title": "Unsafe C functions detected",
                        "severity": "medium",
                        "module": "firmware_analysis",
                        "description": "strcpy, gets found",
                        "remediation": "Use safe alternatives",
                    },
                    {
                        "title": "Firmware sections identified",
                        "severity": "info",
                        "module": "firmware_analysis",
                        "description": "Found SquashFS",
                    },
                ],
            },
        ],
    }


def test_offline_analysis_risk_rating():
    agent = SecurityAnalysisAgent(provider="offline")
    summary = _make_summary(critical=2)
    analysis = agent.analyze_scan(summary)
    assert analysis.risk_rating == "CRITICAL"


def test_offline_analysis_risk_high():
    agent = SecurityAnalysisAgent(provider="offline")
    summary = _make_summary(critical=0, high=3)
    analysis = agent.analyze_scan(summary)
    assert analysis.risk_rating == "HIGH"


def test_offline_analysis_executive_summary():
    agent = SecurityAnalysisAgent(provider="offline")
    summary = _make_summary()
    analysis = agent.analyze_scan(summary)
    assert "192.168.1.100" in analysis.executive_summary
    assert len(analysis.executive_summary) > 20


def test_offline_analysis_priority_remediations():
    agent = SecurityAnalysisAgent(provider="offline")
    summary = _make_summary()
    analysis = agent.analyze_scan(summary)
    assert len(analysis.priority_remediations) > 0
    first = analysis.priority_remediations[0]
    assert "title" in first
    assert "effort" in first


def test_offline_analysis_attack_chains():
    agent = SecurityAnalysisAgent(provider="offline")
    summary = _make_summary()
    analysis = agent.analyze_scan(summary)
    assert len(analysis.attack_chains) > 0
    chain = analysis.attack_chains[0]
    assert "name" in chain
    assert "steps" in chain
    assert len(chain["steps"]) > 0


def test_offline_analysis_compliance_gaps():
    agent = SecurityAnalysisAgent(provider="offline")
    summary = _make_summary()
    analysis = agent.analyze_scan(summary)
    assert len(analysis.compliance_gaps) > 0
    gap = analysis.compliance_gaps[0]
    assert gap["standard"] == "OWASP IoT Top 10"


def test_offline_adaptive_recommendations():
    agent = SecurityAnalysisAgent(provider="offline")
    summary = _make_summary()
    available = ["web", "ota", "attack_paths", "protocols", "network"]
    recs = agent.get_adaptive_recommendations(summary, available)
    assert len(recs) > 0
    modules = [r["module"] for r in recs]
    # Should recommend web security since credentials were found
    assert "web" in modules


def test_offline_deep_dive():
    agent = SecurityAnalysisAgent(provider="offline")
    finding = {
        "title": "Default credentials",
        "severity": "critical",
        "description": "admin:admin works",
        "remediation": "Change passwords",
    }
    result = agent.deep_dive_finding(finding)
    assert "Default credentials" in result
    assert "Change passwords" in result


def test_analysis_to_dict():
    analysis = AIAnalysis(
        executive_summary="Test summary",
        risk_rating="HIGH",
        priority_remediations=[{"title": "Fix X"}],
        attack_chains=[{"name": "Chain 1", "steps": ["Step 1"]}],
        compliance_gaps=[{"standard": "OWASP"}],
    )
    d = analysis.to_dict()
    assert d["risk_rating"] == "HIGH"
    assert d["executive_summary"] == "Test summary"
    assert len(d["priority_remediations"]) == 1


def test_effort_estimation():
    agent = SecurityAnalysisAgent(provider="offline")
    assert "Quick" in agent._estimate_effort({"title": "Default credential found"})
    assert "Major" in agent._estimate_effort({"title": "Firmware signing needed"})
    assert "Medium" in agent._estimate_effort({"title": "TLS misconfigured"})
