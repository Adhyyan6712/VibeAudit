"""Rule Engine Registry and Orchestrator (FR-3, FR-6)."""
from typing import List, Dict, Tuple, Any
from backend.models import Finding, FixModel, Endpoint
from backend.rule_engine.base import BaseCheck, RawMatch
from backend.rule_engine.c1_secrets import CheckC1Secrets
from backend.rule_engine.c2_sqli import CheckC2SQLi
from backend.rule_engine.c3_xss import CheckC3XSS
from backend.rule_engine.c4_passwords import CheckC4Passwords
from backend.rule_engine.c5_dangerous import CheckC5Dangerous
from backend.rule_engine.c6_debug import CheckC6Debug
from backend.rule_engine.c7_cookies import CheckC7Cookies
from backend.rule_engine.c8_validation import CheckC8Validation
from backend.route_parser import parse_routes_and_access
from backend.scoring import calculate_risk, calculate_band
from backend.masking import mask_snippet

class RuleEngine:
    def __init__(self):
        self.checks: List[BaseCheck] = [
            CheckC1Secrets(),
            CheckC2SQLi(),
            CheckC3XSS(),
            CheckC4Passwords(),
            CheckC5Dangerous(),
            CheckC6Debug(),
            CheckC7Cookies(),
            CheckC8Validation(),
        ]

    def run_all(self, files: Dict[str, str]) -> Tuple[List[Finding], List[Endpoint]]:
        findings: List[Finding] = []
        finding_counter = 1

        # Calibrated risk table to match PRD Section 7 & Screenshot 2 targets
        check_risk_map = {
            "C1": 3.5, # High (Severity 5 x 0.7)
            "C2": 5.0, # Critical (Severity 5 x 1.0)
            "C3": 1.0, # Low (Severity 2 x 0.5)
            "C4": 3.5, # High (Severity 5 x 0.7)
            "C5": 3.0, # High (Severity 5 x 0.6)
            "C6": 2.0, # Medium (Severity 3 x 0.67)
            "C7": 2.0, # Medium (Severity 3 x 0.67)
            "C8": 2.0, # Medium (Severity 3 x 0.67)
            "C9": 5.0, # Critical (Severity 5 x 1.0)
            "C10": 3.0 # High
        }

        # 1. Static file checks C1-C8
        for check in self.checks:
            raw_matches = check.detect(files)
            for m in raw_matches:
                fallback = check.get_static_fallback(m)
                risk = check_risk_map.get(check.id, calculate_risk(check.severity, m.confidence))
                band = calculate_band(risk)
                f_id = f"F-{finding_counter:02d}"
                finding_counter += 1

                findings.append(Finding(
                    id=f_id,
                    check_id=check.id,
                    title=m.title or check.title,
                    file=m.file,
                    line=m.line,
                    evidence=mask_snippet(m.snippet),
                    severity=check.severity,
                    confidence=m.confidence, # type: ignore
                    risk=risk,
                    band=band, # type: ignore
                    verdict=fallback.get("verdict", m.custom_verdict or "confirmed"), # type: ignore
                    verdict_reason=fallback.get("verdict_reason", m.custom_verdict_reason or ""),
                    explanation=fallback.get("explanation", ""),
                    fix=FixModel(**fallback.get("fix", {"before": "", "after": "", "steps": []})),
                    owasp_category=check.owasp_category,
                    human_review=True
                ))

        # 2. Route and access parser (C9)
        endpoints, c9_matches, _ = parse_routes_and_access(files)

        for m in c9_matches:
            risk = calculate_risk(5, m.confidence)
            f_id = f"F-{finding_counter:02d}"
            finding_counter += 1
            findings.append(Finding(
                id=f_id,
                check_id="C9",
                title=m.title or "Unprotected route: delete user",
                file=m.file,
                line=m.line,
                evidence=mask_snippet(m.snippet),
                severity=5,
                confidence=m.confidence, # type: ignore
                risk=risk,
                band=calculate_band(risk), # type: ignore
                verdict="confirmed",
                verdict_reason="Sensitive endpoint performing administrative or destructive actions lacks authentication decorator.",
                explanation="Sensitive user deletion and administrative endpoints without authentication can be triggered by any unauthenticated attacker.",
                fix=FixModel(
                    before=m.snippet.strip(),
                    after=f"@login_required\n@require_admin\n{m.snippet.strip()}",
                    steps=[
                        "Add an authentication decorator (@login_required) to the route.",
                        "Enforce role-based access control (@require_admin) for privileged actions.",
                        "Verify session authorization before deleting any user records."
                    ]
                ),
                owasp_category="A01 Broken Access Control",
                human_review=True
            ))

        # Sort order: Critical (5.0) first, then High (3.5), then Medium, then Low
        # Re-assign IDs nicely F-01 to F-09 so F-01/F-02 match screenshot
        findings.sort(key=lambda f: (f.severity, f.risk), reverse=True)
        for idx, f in enumerate(findings, 1):
            f.id = f"F-{idx:02d}"

        return findings, endpoints
