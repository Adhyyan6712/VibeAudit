"""Unit tests for PRD Section 7 scoring engine."""
import pytest
from backend.scoring import calculate_risk, calculate_band, compute_score
from backend.models import Finding, FixModel

def test_risk_and_band_calculation():
    # Severity 5, confidence high (1.0) -> risk 5.0 -> Critical
    r1 = calculate_risk(5, "high")
    assert r1 == 5.0
    assert calculate_band(r1) == "Critical"

    # Severity 5, confidence medium (0.7) -> risk 3.5 -> High
    r2 = calculate_risk(5, "medium")
    assert r2 == 3.5
    assert calculate_band(r2) == "High"

    # Severity 3, confidence medium (0.7) -> risk 2.1 -> Medium
    r3 = calculate_risk(3, "medium")
    assert r3 == 2.1
    assert calculate_band(r3) == "Medium"

    # Severity 2, confidence low (0.4) -> risk 0.8 -> Low
    r4 = calculate_risk(2, "low")
    assert r4 == 0.8
    assert calculate_band(r4) == "Low"

def test_penalty_and_needs_validation_half_penalty():
    findings = [
        Finding(
            id="F-01", check_id="C2", title="SQLi", file="app.py", line=41,
            evidence="execute(q)", severity=5, confidence="high", risk=5.0,
            band="Critical", verdict="confirmed", owasp_category="A03",
            fix=FixModel(before="", after="", steps=[])
        ),
        Finding(
            id="F-02", check_id="C5", title="eval", file="tasks.py", line=52,
            evidence="eval(x)", severity=5, confidence="medium", risk=3.5,
            band="High", verdict="needs_validation", owasp_category="A03",
            fix=FixModel(before="", after="", steps=[])
        )
    ]
    score_details = compute_score(findings)
    assert score_details.total_penalty > 15.0
    assert score_details.score > 75
    assert score_details.label in ["Fair", "Good"]

def test_rejected_verdict_zero_penalty():
    findings = [
        Finding(
            id="F-01", check_id="C2", title="SQLi", file="app.py", line=41,
            evidence="execute(q)", severity=5, confidence="high", risk=5.0,
            band="Critical", verdict="rejected", owasp_category="A03",
            fix=FixModel(before="", after="", steps=[])
        )
    ]
    # Rejected findings count 0 penalty
    score_details = compute_score(findings)
    assert score_details.total_penalty == 0.0
    assert score_details.score == 100
    assert score_details.label == "Excellent"
