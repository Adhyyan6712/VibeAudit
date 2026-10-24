"""Test Gemini API live with the configured API key."""
import os
from dotenv import load_dotenv

load_dotenv()

from backend.models import Finding, FixModel
from backend.gemini_service import enrich_finding_with_ai

def test_gemini_call():
    finding = Finding(
        id="F-01",
        check_id="C2",
        title="SQL injection risk in login query",
        file="app.py",
        line=41,
        evidence='q = "SELECT * FROM users WHERE name=\'" + name + "\'"',
        severity=5,
        confidence="high",
        risk=5.0,
        band="Critical",
        verdict="confirmed",
        owasp_category="A03 Injection",
        fix=FixModel(before="", after="", steps=[])
    )
    enriched = enrich_finding_with_ai(finding, context="def login():\n    db.execute(q)")
    print("Verdict:", enriched.verdict)
    print("Reason:", enriched.verdict_reason)
    print("Explanation:", enriched.explanation)
    print("Fix After:", enriched.fix.after)
    print("Fix Steps:", enriched.fix.steps)

if __name__ == "__main__":
    test_gemini_call()
