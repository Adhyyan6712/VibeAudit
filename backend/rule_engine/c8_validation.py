"""Check C8: Missing input validation (Severity 3, OWASP A04)."""
import re
from typing import List, Dict, Any
from backend.rule_engine.base import BaseCheck, RawMatch

UNVALIDATED_BODY_REGEX = re.compile(
    r"""(?i)^\s*(?:data|payload|body|req_data)\s*=\s*request\.(?:json|get_json\(\)|form)"""
)

VALIDATION_INDICATORS = [
    "schema", "validate(", "pydantic", "isinstance(", "marshmallow",
    "validator", "abort(400)", "validationerror", "validates"
]

class CheckC8Validation(BaseCheck):
    id = "C8"
    title = "Missing request body input validation"
    severity = 3
    owasp_category = "A04 Insecure Design"

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

                if UNVALIDATED_BODY_REGEX.search(line):
                    subsequent = "\n".join(lines[idx:min(len(lines), idx + 10)]).lower()
                    has_validation = any(k in subsequent for k in VALIDATION_INDICATORS)

                    if not has_validation:
                        start_c = max(0, idx - 3)
                        end_c = min(len(lines), idx + 2)
                        ctx = "\n".join(lines[start_c:end_c])
                        matches.append(RawMatch(
                            file=file_path,
                            line=idx,
                            snippet=line,
                            context=ctx,
                            confidence="medium", # 3 * 0.7 = 2.1 -> Medium band
                            title="Missing input validation on request.json",
                            custom_verdict="confirmed",
                            custom_verdict_reason="Handler reads raw JSON payload without schema, type, or constraint validation."
                        ))

        return matches

    def get_static_fallback(self, match: RawMatch) -> Dict[str, Any]:
        return {
            "explanation": "Accepting JSON or form inputs without validating field types, lengths, and schemas allows malformed payloads, type errors, or mass-assignment vulnerabilities.",
            "verdict": "confirmed",
            "verdict_reason": "Handler reads request body directly without validating against a defined schema.",
            "fix": {
                "before": match.snippet.strip(),
                "after": 'payload = request.get_json(silent=True)\nif not payload or not isinstance(payload.get("title"), str):\n    return jsonify({"error": "Invalid schema"}), 400',
                "steps": [
                    "Define a strict Pydantic or Marshmallow schema for request payloads.",
                    "Validate required fields, string lengths, and data types before processing.",
                    "Reject unexpected fields to prevent parameter injection."
                ]
            }
        }
