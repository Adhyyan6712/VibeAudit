"""Check C5: Dangerous functions (Severity 5, OWASP A03 Injection)."""
import re
from typing import List, Dict, Any
from backend.rule_engine.base import BaseCheck, RawMatch

DANGEROUS_REGEX = re.compile(
    r"""(?:\beval\s*\(|\bexec\s*\(|os\.system\s*\(|subprocess\.(?:run|call|Popen)\s*\([^)]*shell\s*=\s*True|pickle\.loads\s*\()"""
)

class CheckC5Dangerous(BaseCheck):
    id = "C5"
    title = "Dangerous function call"
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
                if clean_l.startswith("#") or clean_l.startswith('"""') or clean_l.startswith("'''") or clean_l.startswith("//") or clean_l.startswith("*"):
                    continue

                if DANGEROUS_REGEX.search(line):
                    start_c = max(0, idx - 3)
                    end_c = min(len(lines), idx + 2)
                    ctx = "\n".join(lines[start_c:end_c])
                    t = "eval() on a user-supplied filter" if "eval(" in line else "Dangerous command execution"

                    matches.append(RawMatch(
                        file=file_path,
                        line=idx,
                        snippet=line,
                        context=ctx,
                        confidence="medium", # 5 * 0.7 = 3.5 -> High band
                        title=t,
                        custom_verdict="needs_validation",
                        custom_verdict_reason="Plausible remote code execution; depends on whether input is strictly sanitized upstream."
                    ))

        return matches

    def get_static_fallback(self, match: RawMatch) -> Dict[str, Any]:
        return {
            "explanation": "Evaluating dynamic expressions from request parameters can lead to arbitrary code execution if an attacker supplies Python dunder methods or syntax escapes.",
            "verdict": "needs_validation",
            "verdict_reason": "Dynamic eval() expression used with user input; needs verification whether strict validation precedes execution.",
            "fix": {
                "before": match.snippet.strip(),
                "after": "allowed_statuses = {'pending', 'done'}\nmatched = [t for t in TASKS_STORE.values() if t.get('status') == status_filter]",
                "steps": [
                    "Remove eval() entirely from request handlers.",
                    "Filter collections using dictionary key matching or safe whitelists.",
                    "If arithmetic expressions are required, use safe abstract syntax tree parsers."
                ]
            }
        }
