"""Test Gemini API live with the configured API key."""
import sys
from pathlib import Path
from dotenv import load_dotenv

# Ensure project root is in sys.path
root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

load_dotenv()

from app import config, gemini_client
from app.models import Finding, Fix
import asyncio

def test_gemini_call():
    print(f"Testing live Gemini API (Model: {config.GEMINI_MODEL})...")
    if not gemini_client.available():
        print("Error: GEMINI_API_KEY is not set or empty in .env!")
        return

    finding = Finding(
        id="F-01",
        check_id="C2",
        title="SQL injection risk in login query",
        file="app.py",
        line=41,
        evidence='q = "SELECT * FROM users WHERE name=\'" + name + "\'"',
        context="def login():\n    db.execute(q)",
        severity=5,
        confidence="high",
        risk=5.0,
        band="Critical",
        verdict="confirmed",
        owasp_category="A03 Injection",
        fix=Fix(before="", after="", steps=[])
    )

    async def run():
        res = await gemini_client._call(finding)
        print("\n--- Live Gemini Enrichment Result ---")
        print("Verdict:       ", res.verdict)
        print("Verdict Reason:", res.verdict_reason)
        print("Explanation:   ", res.explanation)
        print("Fix Before:    ", res.fix.before)
        print("Fix After:     ", res.fix.after)
        print("Fix Steps:     ", res.fix.steps)

    asyncio.run(run())

if __name__ == "__main__":
    test_gemini_call()

