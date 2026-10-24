"""Check C3: XSS risk (Severity 3, OWASP A03 Injection)."""
import re
from typing import List, Dict, Any
from backend.rule_engine.base import BaseCheck, RawMatch

JINJA_SAFE_REGEX = re.compile(r"""\{\{.*?\|\s*safe\s*\}\}""")
PYTHON_RAW_HTML_REGEX = re.compile(r"""(?i)f["'].*<(?:div|li|p|a|span|h[1-6]|table|script|img|button|ul|ol|body|html)\b.*\{[a-zA-Z0-9_]+.*\}""")
DOM_XSS_REGEX = re.compile(r"""(?:\.innerHTML\s*=\s*(?![`'"]<[a-z0-9_\-\s="'/]+>[`'"];?$)[a-zA-Z0-9_$.]+|document\.write\s*\()""")

class CheckC3XSS(BaseCheck):
    id = "C3"
    title = "Cross-Site Scripting (XSS) via unescaped HTML template rendering"
    severity = 2
    owasp_category = "A03 Injection"

    def detect(self, files: Dict[str, str]) -> List[RawMatch]:
        matches: List[RawMatch] = []
        for file_path, content in files.items():
            lines = content.splitlines()

            # 1. Check Jinja/HTML templates
            if file_path.endswith((".html", ".htm", ".jinja", ".j2")):
                for idx, line in enumerate(lines, 1):
                    if JINJA_SAFE_REGEX.search(line):
                        start_c = max(0, idx - 2)
                        end_c = min(len(lines), idx + 2)
                        ctx = "\n".join(lines[start_c:end_c])
                        matches.append(RawMatch(
                            file=file_path,
                            line=idx,
                            snippet=line,
                            context=ctx,
                            confidence="low", # 2 * 0.4 = 0.8 -> Low band
                            title="Unescaped HTML rendering via |safe filter",
                            custom_verdict="confirmed",
                            custom_verdict_reason="Template bypasses HTML auto-escaping using |safe on potentially user-controlled variables."
                        ))

            # 2. Check Python files building raw HTML strings without escaping
            elif file_path.endswith(".py"):
                file_matches = 0
                for idx, line in enumerate(lines, 1):
                    clean_l = line.strip()
                    if clean_l.startswith("#") or clean_l.startswith('"""') or clean_l.startswith("'''"):
                        continue
                    if PYTHON_RAW_HTML_REGEX.search(line) and not ("html.escape" in line or "markupsafe" in line):
                        start_c = max(0, idx - 2)
                        end_c = min(len(lines), idx + 2)
                        ctx = "\n".join(lines[start_c:end_c])
                        matches.append(RawMatch(
                            file=file_path,
                            line=idx,
                            snippet=line,
                            context=ctx,
                            confidence="low",
                            title="Unescaped raw HTML string interpolation",
                            custom_verdict="confirmed",
                            custom_verdict_reason="Dynamic values interpolated directly into raw HTML tags without HTML escaping, creating stored or reflected XSS risk."
                        ))
                        file_matches += 1
                        if file_matches >= 2: # Limit to top 2 to avoid flooding
                            break

            # 3. Check JavaScript files for direct innerHTML DOM sinks
            elif file_path.endswith((".js", ".jsx", ".ts", ".tsx")):
                file_matches = 0
                for idx, line in enumerate(lines, 1):
                    clean_l = line.strip()
                    if clean_l.startswith("//") or clean_l.startswith("/*") or clean_l.startswith("*"):
                        continue
                    if DOM_XSS_REGEX.search(line) and not any(p in line.lower() for p in ["dompurify", "sanitize", "escape"]):
                        start_c = max(0, idx - 2)
                        end_c = min(len(lines), idx + 2)
                        ctx = "\n".join(lines[start_c:end_c])
                        matches.append(RawMatch(
                            file=file_path,
                            line=idx,
                            snippet=line,
                            context=ctx,
                            confidence="low",
                            title="Potential DOM XSS via unescaped innerHTML sink",
                            custom_verdict="needs_validation",
                            custom_verdict_reason="Direct assignment to innerHTML without explicit sanitization; verify if variable is sanitized upstream."
                        ))
                        file_matches += 1
                        if file_matches >= 2:
                            break

        return matches

    def get_static_fallback(self, match: RawMatch) -> Dict[str, Any]:
        snip = match.snippet.strip()
        if match.file.endswith((".html", ".htm", ".jinja", ".j2")):
            after = snip.replace("| safe", "").replace("|safe", "").strip()
            steps = [
                "Remove the |safe filter so template engine auto-escapes special characters.",
                "Ensure variables are rendered with default escaping: {{ comment }}.",
                "If HTML formatting is required, sanitize with Bleach or DOMPurify."
            ]
        elif match.file.endswith(".py"):
            after = "import html\n# Escape dynamic values before inserting into HTML:\nescaped_val = html.escape(val)"
            steps = [
                "Import Python's standard `html` module.",
                "Wrap all dynamic variables in `html.escape()` before interpolating into HTML tags.",
                "Prefer template engines (Jinja2) with autoescaping enabled over raw string formatting."
            ]
        else:
            after = "element.textContent = data; // Or DOMPurify.sanitize(data)"
            steps = [
                "Use .textContent or .innerText instead of .innerHTML when displaying untrusted text.",
                "If HTML formatting is needed, pass values through DOMPurify.sanitize().",
                "Avoid document.write() and raw eval() in frontend code."
            ]

        return {
            "explanation": "Untrusted user data rendered without context-aware HTML escaping allows attackers to inject malicious scripts into other users' browser sessions.",
            "verdict": match.custom_verdict or "confirmed",
            "verdict_reason": match.custom_verdict_reason or "HTML output escaping is explicitly bypassed or missing.",
            "fix": {
                "before": snip,
                "after": after,
                "steps": steps
            }
        }
