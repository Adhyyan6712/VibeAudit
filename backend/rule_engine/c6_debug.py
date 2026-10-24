"""Check C6: Debug mode enabled (Severity 3, OWASP A05)."""
import re
from typing import List, Dict, Any
from backend.rule_engine.base import BaseCheck, RawMatch

DEBUG_REGEX = re.compile(
    r"""(?i)app\.run\([^)]*debug\s*=\s*True"""
)

class CheckC6Debug(BaseCheck):
    id = "C6"
    title = "Debug mode enabled"
    severity = 3
    owasp_category = "A05 Security Misconfiguration"

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

                if DEBUG_REGEX.search(line):
                    start_c = max(0, idx - 3)
                    end_c = min(len(lines), idx + 2)
                    ctx = "\n".join(lines[start_c:end_c])
                    matches.append(RawMatch(
                        file=file_path,
                        line=idx,
                        snippet=line,
                        context=ctx,
                        confidence="medium", # 3 * 0.67 = 2.0 -> Medium band
                        title="Debug mode enabled",
                        custom_verdict="confirmed",
                        custom_verdict_reason="Application runs with active debug mode, enabling interactive debuggers."
                    ))

        return matches

    def get_static_fallback(self, match: RawMatch) -> Dict[str, Any]:
        return {
            "explanation": "Enabling debug mode in deployed web applications exposes interactive pin-based debug consoles and detailed stack traces containing secrets and internal architecture.",
            "verdict": "confirmed",
            "verdict_reason": "debug=True flag detected in application launcher.",
            "fix": {
                "before": match.snippet.strip(),
                "after": match.snippet.replace("debug=True", "debug=False").strip(),
                "steps": [
                    "Set debug=False in production deployments.",
                    "Use environment variable flags (os.environ.get('FLASK_DEBUG', 'false').lower() == 'true').",
                    "Deploy behind a production ASGI/WSGI server (e.g. Gunicorn or Uvicorn)."
                ]
            }
        }
