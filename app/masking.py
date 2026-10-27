"""Secret detection helpers and masking. Secrets must never leave this process unmasked."""
import math
import re

SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("API key (sk- style)", re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}")),
    ("Stripe key", re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
]
ASSIGNMENT = re.compile(
    r"""(?ix)(?P<name>[\w.\-]*(?:password|passwd|pwd|secret|api[_\-]?key|apikey|access[_\-]?key|
    auth[_\-]?token|token|private[_\-]?key)[\w\-]*)(?P<sep>["']?\s*[:=]\s*)(?P<q>["'])(?P<value>[^"'\n]{6,})(?P=q)""")
URL_CRED = re.compile(r"\b[a-z][a-z0-9+.\-]*://[^\s:/@\"']+:(?P<pw>[^\s@\"']{3,})@")
ENV_LINE = re.compile(r"^\s*(?P<name>[A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|TOKEN|KEY|PASS)[A-Z0-9_]*)\s*=\s*['\"]?(?P<value>[^\s'\"#]{6,})")
PLACEHOLDER = re.compile(r"(?i)^(your[_\-\s]|<|\$\{|\{\{|x{3,}|changeme|change_me|example|placeholder|dummy|todo|none$|null$|\*+$|•+|replace|insert|enter[_\s]|my[_\-]|\.\.\.)")
NOT_SECRET_SUFFIX = ("_url", "_name", "_path", "_header", "_field", "_type", "_env", "_file", "_label", "_text")


def is_placeholder(value: str) -> bool:
    return bool(PLACEHOLDER.match(value.strip()))


def shannon(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in freq.values())


def mask_value(v: str) -> str:
    """sk-live-1234567890a9f2 -> sk-••••a9f2 (short values show only the first character)."""
    v = v.strip()
    return v[:1] + "••••" if len(v) <= 8 else v[:3] + "••••" + v[-4:]


def mask_text(text: str) -> str:
    """Mask every secret-looking value in a piece of text (for UI, reports, logs, and AI prompts)."""
    for kind, pat in SECRET_PATTERNS:
        if kind == "Private key block":
            text = pat.sub("[PRIVATE KEY BLOCK]", text)
        else:
            text = pat.sub(lambda m: mask_value(m.group(0)), text)
    text = URL_CRED.sub(lambda m: m.group(0).replace(m.group("pw"), "••••"), text)

    def _assign(m):
        val = m.group("value")
        if is_placeholder(val) or m.group("name").lower().endswith(NOT_SECRET_SUFFIX):
            return m.group(0)
        return m.group(0).replace(val, mask_value(val))
    text = ASSIGNMENT.sub(_assign, text)
    return "\n".join(
        (lambda m: ln.replace(m.group("value"), mask_value(m.group("value"))) if m and not is_placeholder(m.group("value")) else ln)(ENV_LINE.match(ln))
        for ln in text.split("\n"))


