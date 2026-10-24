"""Check C1: Hardcoded secrets (Severity 5, OWASP A02)."""
import re
from typing import List, Dict, Any
from backend.rule_engine.base import BaseCheck, RawMatch
from backend.masking import mask_snippet, mask_secret

class CheckC1Secrets(BaseCheck):
    id = "C1"
    title = "Hardcoded secret detected"
    severity = 5
    owasp_category = "A02 Cryptographic Failures"

    def detect(self, files: Dict[str, str]) -> List[RawMatch]:
        matches: List[RawMatch] = []
        for file_path, content in files.items():
            # Skip documentation templates and examples
            if any(file_path.endswith(sfx) for sfx in [".example", ".sample", ".md"]):
                continue

            lines = content.splitlines()

            # Check committed .env files (non-example)
            if file_path.endswith("/.env") or file_path == ".env":
                for idx, line in enumerate(lines, 1):
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#") and "=" in stripped and not any(p in stripped.lower() for p in ["your_", "placeholder", "xxx"]):
                        start_c = max(0, idx - 3)
                        end_c = min(len(lines), idx + 2)
                        ctx = "\n".join(lines[start_c:end_c])
                        matches.append(RawMatch(
                            file=file_path,
                            line=idx,
                            snippet=line,
                            context=ctx,
                            confidence="high",
                            title=f"Committed .env secret: {line.split('=')[0].strip()}",
                            custom_verdict="confirmed",
                            custom_verdict_reason="Environment file containing active credentials was committed to repository."
                        ))
                        break

            # Check config or code files
            for idx, line in enumerate(lines, 1):
                clean_l = line.strip()
                if clean_l.startswith("#") or clean_l.startswith("//"):
                    continue

                # Check known secret patterns
                matched_secret = False
                for pat, label in [
                    (r"""(sk-[a-zA-Z0-9_\-]{8,})""", "API key"),
                    (r"""(AKIA[0-9A-Z]{16})""", "AWS Access Key"),
                    (r"""(ghp_[a-zA-Z0-9]{36})""", "GitHub Token"),
                    (r"""((?:sk|rk)_(?:live|test)_[a-zA-Z0-9]{20,})""", "Stripe API Key"),
                    (r"""(AIza[0-9A-Za-z-_]{35})""", "Google API Key"),
                    (r"""(?:SECRET_KEY|JWT_SECRET|AUTH_SECRET|AWS_SECRET)\s*=\s*["']([^"']{8,})["']""", "Hardcoded secret")
                ]:
                    if "os.environ" in line or "placeholder" in line.lower() or "your_" in line.lower():
                        continue
                    m_key = re.search(pat, line)
                    if m_key:
                        masked = mask_secret(m_key.group(1))
                        start_c = max(0, idx - 3)
                        end_c = min(len(lines), idx + 2)
                        ctx = "\n".join(lines[start_c:end_c])
                        matches.append(RawMatch(
                            file=file_path,
                            line=idx,
                            snippet=line,
                            context=ctx,
                            confidence="medium", # 5 * 0.7 = 3.5 -> High band
                            title=f"Hardcoded {label} ({masked})",
                            custom_verdict="confirmed",
                            custom_verdict_reason="Found plaintext secret or credential assigned directly in source code."
                        ))
                        matched_secret = True
                        break
                if matched_secret:
                    break

        return matches

    def get_static_fallback(self, match: RawMatch) -> Dict[str, Any]:
        masked_snip = mask_snippet(match.snippet)
        clean_snip = match.snippet.strip()
        var_name = clean_snip.split("=")[0].strip() if "=" in clean_snip else "API_KEY"

        return {
            "explanation": "Hardcoded credentials or API keys committed to source code can be extracted by unauthorized users, leaked in repository history, or harvested by bots.",
            "verdict": match.custom_verdict or "confirmed",
            "verdict_reason": match.custom_verdict_reason or "Secret value is hardcoded in source files rather than loaded from environment.",
            "fix": {
                "before": masked_snip,
                "after": f"{var_name} = os.environ.get(\"{var_name.upper()}\")",
                "steps": [
                    f"Remove the hardcoded secret from {match.file}.",
                    "Store the credential in a local .env file added to .gitignore.",
                    "Rotate the exposed secret key immediately if it was ever pushed."
                ]
            }
        }
