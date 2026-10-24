"""Check C2: SQL injection risk (Severity 5, OWASP A03 Injection)."""
import re
from typing import List, Dict, Any
from backend.rule_engine.base import BaseCheck, RawMatch

SQL_CONCAT_REGEX = re.compile(
    r"""(?i)(?:(?:q|query|sql|stmt)\s*=\s*|\.execute\s*\(\s*)(?:f["'].*(?:SELECT|INSERT|UPDATE|DELETE|DROP).*\{.*\}|["'].*(?:SELECT|INSERT|UPDATE|DELETE|DROP).*["']\s*(?:\+|\%)\s*[^,\)\n]+)"""
)

class CheckC2SQLi(BaseCheck):
    id = "C2"
    title = "SQL injection risk in login query"
    severity = 5
    owasp_category = "A03 Injection"

    def detect(self, files: Dict[str, str]) -> List[RawMatch]:
        matches: List[RawMatch] = []
        for file_path, content in files.items():
            if not file_path.endswith(".py"):
                continue

            lines = content.splitlines()
            for idx, line in enumerate(lines, 1):
                clean_l = line.strip()
                if clean_l.startswith("#"):
                    continue

                if SQL_CONCAT_REGEX.search(line):
                    start_c = max(0, idx - 3)
                    end_c = min(len(lines), idx + 2)
                    ctx = "\n".join(lines[start_c:end_c])
                    title = "SQL injection risk in login query" if "login" in ctx.lower() else "SQL injection risk in query construction"

                    matches.append(RawMatch(
                        file=file_path,
                        line=idx,
                        snippet=line,
                        context=ctx,
                        confidence="high",
                        title=title,
                        custom_verdict="confirmed",
                        custom_verdict_reason="SQL query is built using dynamic string concatenation with unparameterized variables."
                    ))

        return matches

    def get_static_fallback(self, match: RawMatch) -> Dict[str, Any]:
        return {
            "explanation": "User input is placed directly into the query text. Someone could change what the query does and read or alter data they should not reach, such as other users’ accounts.",
            "verdict": "confirmed",
            "verdict_reason": "Query string is built using string concatenation with untrusted input without parameterization.",
            "fix": {
                "before": match.snippet.strip(),
                "after": 'db.execute("SELECT * FROM users WHERE name = ?", (name,))',
                "steps": [
                    "Replace concatenated string with parameterized SQL placeholder (?).",
                    "Pass user query parameters as a safe tuple to execute().",
                    "Verify the query executor uses parameterized prepared statements."
                ]
            }
        }
