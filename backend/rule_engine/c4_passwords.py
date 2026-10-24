"""Check C4: Weak password hashing (Severity 4, OWASP A02)."""
import re
from typing import List, Dict, Any
from backend.rule_engine.base import BaseCheck, RawMatch

MD5_SHA1_REGEX = re.compile(
    r"""(?i)hashlib\.(?:md5|sha1)\s*\("""
)

class CheckC4Passwords(BaseCheck):
    id = "C4"
    title = "Weak password hashing (MD5)"
    severity = 5
    owasp_category = "A02 Cryptographic Failures"

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

                if MD5_SHA1_REGEX.search(line):
                    start_c = max(0, idx - 3)
                    end_c = min(len(lines), idx + 2)
                    ctx = "\n".join(lines[start_c:end_c])
                    matches.append(RawMatch(
                        file=file_path,
                        line=idx,
                        snippet=line,
                        context=ctx,
                        confidence="medium", # 5 * 0.7 = 3.5 -> High band
                        title="Weak password hashing (MD5)",
                        custom_verdict="confirmed",
                        custom_verdict_reason="Fast legacy hash MD5 is vulnerable to precomputed rainbow table attacks."
                    ))
                    break # Single high-signal finding per file

        return matches

    def get_static_fallback(self, match: RawMatch) -> Dict[str, Any]:
        return {
            "explanation": "MD5 algorithm is broken for password storage because modern hardware can compute billions of hashes per second, allowing rapid offline cracking.",
            "verdict": "confirmed",
            "verdict_reason": "MD5 hash without cryptographic work factor was used for credentials.",
            "fix": {
                "before": match.snippet.strip(),
                "after": "salt = os.urandom(16)\nreturn salt.hex() + '$' + hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000).hex()",
                "steps": [
                    "Replace MD5 with PBKDF2-HMAC-SHA256, Argon2id, or bcrypt.",
                    "Generate a cryptographically random salt per user password.",
                    "Use constant-time equality comparisons to prevent timing attacks."
                ]
            }
        }
