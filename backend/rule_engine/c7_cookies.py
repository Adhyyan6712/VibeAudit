"""Check C7: Insecure cookies or session config (Severity 3, OWASP A05)."""
import re
from typing import List, Dict, Any
from backend.rule_engine.base import BaseCheck, RawMatch

COOKIE_FLAG_REGEX = re.compile(
    r"""(?i)SESSION_COOKIE_HTTPONLY\s*=\s*False"""
)

class CheckC7Cookies(BaseCheck):
    id = "C7"
    title = "Insecure cookie or session config"
    severity = 3
    owasp_category = "A05 Security Misconfiguration"

    def detect(self, files: Dict[str, str]) -> List[RawMatch]:
        matches: List[RawMatch] = []
        for file_path, content in files.items():
            if not file_path.endswith((".py", ".env", ".cfg", ".ini")):
                continue

            lines = content.splitlines()
            for idx, line in enumerate(lines, 1):
                clean_l = line.strip()
                if clean_l.startswith("#"):
                    continue

                if COOKIE_FLAG_REGEX.search(line):
                    start_c = max(0, idx - 2)
                    end_c = min(len(lines), idx + 3)
                    ctx = "\n".join(lines[start_c:end_c])
                    matches.append(RawMatch(
                        file=file_path,
                        line=idx,
                        snippet=line,
                        context=ctx,
                        confidence="medium", # 3 * 0.7 = 2.1 -> Medium band
                        title="Insecure cookie and session configuration",
                        custom_verdict="confirmed",
                        custom_verdict_reason="Cookie attributes permit client-side JavaScript access and unencrypted HTTP transmission."
                    ))
                    break # Single finding per config file

        return matches

    def get_static_fallback(self, match: RawMatch) -> Dict[str, Any]:
        return {
            "explanation": "Session cookies without HttpOnly and Secure flags can be stolen via XSS or intercepted in transit. Furthermore, a predictable secret_key allows session forgery.",
            "verdict": "confirmed",
            "verdict_reason": "Insecure cookie attributes found in configuration.",
            "fix": {
                "before": match.snippet.strip(),
                "after": "SESSION_COOKIE_HTTPONLY = True\nSESSION_COOKIE_SECURE = True\nSESSION_COOKIE_SAMESITE = 'Lax'",
                "steps": [
                    "Set SESSION_COOKIE_HTTPONLY = True to prevent JavaScript access to cookies.",
                    "Set SESSION_COOKIE_SECURE = True to ensure cookies are only transmitted over HTTPS.",
                    "Set SESSION_COOKIE_SAMESITE = 'Lax' to defend against CSRF attacks."
                ]
            }
        }
