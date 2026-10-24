"""Masking utility for VibeAudit.

Ensures sensitive secrets (API keys, passwords, database URIs, tokens)
are masked everywhere: UI, reports, logs, and AI requests (FR-4).
Example: sk-live-9481abf082e4a9f2 -> sk-••••a9f2
"""
import re

PATTERNS = [
    # OpenAI / generic sk- tokens: sk-xxxx
    (r"(sk-[a-zA-Z0-9_\-]{3})[a-zA-Z0-9_\-]+([a-zA-Z0-9_\-]{4})", r"\1••••\2"),
    # AWS Access Key IDs
    (r"(AKIA[0-9A-Z]{4})[0-9A-Z]+([0-9A-Z]{4})", r"\1••••\2"),
    # GitHub Tokens: ghp_xxxx
    (r"(gh[pours]_[a-zA-Z0-9]{4})[a-zA-Z0-9]+([a-zA-Z0-9]{4})", r"\1••••\2"),
    # Database URLs (e.g., postgres://user:password@host)
    (r"://([^:]+):([^@]{4})[^@]*([^@]{2})@", r"://\1:\2••••\3@"),
    # Simple assignment strings: password="...", secret="...", api_key="..."
    (r"""(?i)(password|secret|api_key|token|auth_key)\s*[:=]\s*["']([^"']{1,3})([^"']*)([^"']{2})["']""",
     r"""\1 = "\2••••\4\""""),
    # Generic high entropy hex / base64 tokens of length >= 24
    (r"\b([a-zA-Z0-9_\-]{3})[a-zA-Z0-9_\-]{18,}([a-zA-Z0-9_\-]{3})\b", r"\1••••\2")
]

def mask_secret(text: str) -> str:
    """Masks secret substrings while preserving readability for auditing."""
    if not text:
        return ""
    masked = text
    for pattern, repl in PATTERNS:
        masked = re.sub(pattern, repl, masked)
    return masked

def mask_snippet(code: str) -> str:
    """Masks entire code snippet lines."""
    lines = code.splitlines()
    return "\n".join(mask_secret(l) for l in lines)
