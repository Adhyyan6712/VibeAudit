"""Deterministic static checks (C1-C7) plus the full check catalog (C1-C13).

Detection is regex-based and never uses AI. Each CheckDef carries its own static explanation and fix
template, which are used as the fallback whenever Gemini is unavailable.
"""
import re
from dataclasses import dataclass, field
from typing import Callable, Optional

from .loader import SourceFile
from .masking import (ASSIGNMENT, ENV_LINE, NOT_SECRET_SUFFIX, SECRET_PATTERNS, URL_CRED, is_placeholder,
                      mask_text, shannon)

PY = {".py"}
JS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
TPL = {".html", ".htm", ".jinja", ".j2"}


@dataclass
class Match:
    line: int
    snippet: str
    confidence: str
    note: str = ""
    severity: Optional[int] = None


@dataclass(frozen=True)
class CheckDef:
    id: str
    title: str
    severity: int
    owasp: str
    explanation: str
    fix_before: str
    fix_after: str
    steps: tuple
    detector: Optional[Callable[[SourceFile], list]] = field(default=None, compare=False)
    kind: str = "static"          # static | route | live


def _lines(f: SourceFile):
    for i, line in enumerate(f.lines, 1):
        if line.strip():
            yield i, line


def _code(f: SourceFile):
    for i, line in _lines(f):
        if not line.strip().startswith(("#", "//", "/*", "*", "<!--")):
            yield i, line


def _snip(line: str) -> str:
    return mask_text(line.strip())[:300]


# ---------------------------------------------------------------- C1 secrets
_WEAK_NAMES = ("password", "passwd", "pwd", "secret", "api_key", "apikey", "private_key", "access_key")


def detect_secrets(f: SourceFile):
    name = f.name.lower()
    if any(w in name for w in ("example", "sample", "template")):
        return []
    is_env = name.startswith(".env")
    out = []
    for i, line in _lines(f):
        hit = None
        for kind, pat in SECRET_PATTERNS:
            if pat.search(line):
                hit = ("high", f"Known credential format: {kind}")
                break
        if not hit:
            m = URL_CRED.search(line)
            if m and not is_placeholder(m.group("pw")):
                hit = ("high", "Credentials embedded in a connection URL")
        if not hit:
            m = ASSIGNMENT.search(line)
            if m:
                key, val = m.group("name").lower(), m.group("value")
                skip = (is_placeholder(val) or key.endswith(NOT_SECRET_SUFFIX) or (" " in val and len(val) > 30)
                        or re.fullmatch(r"https?://[^:@]+", val))
                if not skip:
                    if any(k in key for k in _WEAK_NAMES):
                        hit = ("high" if len(val) >= 8 else "medium", "Hardcoded value assigned to a secret-like name")
                    elif len(val) >= 12 and shannon(val) >= 3.0:
                        hit = ("medium", "High-entropy value assigned to a token-like name")
        if not hit and is_env:
            m = ENV_LINE.match(line)
            if m and not is_placeholder(m.group("value")):
                hit = ("medium", "Secret-looking value in an .env file included in the project")
        if hit:
            out.append(Match(i, _snip(line), hit[0], hit[1]))
    return out


# ---------------------------------------------------------------- C2 SQL injection
_SQL = re.compile(r"\b(select\s.+?\sfrom|insert\s+into|update\s+\w+\s+set|delete\s+from)\b", re.I)
_INTERP = [
    re.compile(r"""\bf(?:"|')[^\n]*\{[^}]+\}"""),
    re.compile(r"""["']\s*\+\s*[\w.(\[]|[\w)\]]\s*\+\s*["']"""),
    re.compile(r"""["']\s*%\s*[(\w]"""),
    re.compile(r"""["']\s*\.format\("""),
    re.compile(r"`[^`\n]*\$\{[^}]+\}"),
]
_EXEC = re.compile(r"(execute|executemany|query|raw|run|all|get)\s*\(", re.I)


def detect_sqli(f: SourceFile):
    if f.ext not in PY | JS:
        return []
    out = []
    for i, line in _code(f):
        if _SQL.search(line) and any(p.search(line) for p in _INTERP):
            conf = "high" if _EXEC.search(line) else "medium"
            out.append(Match(i, _snip(line), conf, "SQL text built with string interpolation"))
    return out


# ---------------------------------------------------------------- C3 XSS
def detect_xss(f: SourceFile):
    out = []
    near = lambda i: "\n".join(f.lines[max(0, i - 3): i + 2])
    for i, line in _code(f):
        s = line.strip()
        if f.ext in JS | TPL:
            m = re.search(r"\.(?:innerHTML|outerHTML)\s*\+?=\s*(.+)$", line)
            if m and not re.fullmatch(r"""["'`][^"'`$+]*["'`];?""", m.group(1).strip()):
                conf = "high" if re.search(r"\$\{|\+|\b(req|params|query|input|value|data|user)", m.group(1)) else "medium"
                out.append(Match(i, _snip(s), conf, "Assigning dynamic content to innerHTML"))
            elif "dangerouslySetInnerHTML" in line and not re.search(r"DOMPurify|sanitize", near(i)):
                out.append(Match(i, _snip(s), "medium", "dangerouslySetInnerHTML without visible sanitization"))
            elif re.search(r"document\.write\(|insertAdjacentHTML\(", line):
                out.append(Match(i, _snip(s), "medium", "Writes raw HTML into the page"))
        if f.ext in PY:
            if re.search(r"""render_template_string\(\s*(?!["'][^"']*["']\s*[,)])""", line):
                out.append(Match(i, _snip(s), "high", "render_template_string with a dynamic template"))
            elif re.search(r"\b(Markup|mark_safe)\(\s*(?!\s*[\"'][^\"']*[\"']\s*\))", line):
                out.append(Match(i, _snip(s), "medium", "Marks dynamic content as safe HTML"))
        if f.ext in TPL:
            if re.search(r"\|\s*safe\b", line):
                out.append(Match(i, _snip(s), "medium", "Template filter |safe disables escaping"))
            elif re.search(r"{%\s*autoescape\s+(false|off)", line, re.I):
                out.append(Match(i, _snip(s), "high", "Auto-escaping disabled"))
    return out


# ---------------------------------------------------------------- C4 weak password handling
_WEAK_HASH = re.compile(r"""hashlib\.(?:md5|sha1)\s*\(|createHash\(\s*["'](?:md5|sha1)["']|(?<![\w.])(?:md5|sha1)\s*\(""", re.I)
_PLAIN_PW = re.compile(r"""\bpassword["'\])]*\s*(?:===?)\s*[\w.\["']""", re.I)


def detect_weak_crypto(f: SourceFile):
    if f.ext not in PY | JS:
        return []
    out = []
    for i, line in _code(f):
        if _WEAK_HASH.search(line) and not re.match(r"\s*def\s", line):
            window = "\n".join(f.lines[max(0, i - 4): i + 3])
            pw = re.search(r"pass(word|wd)|pwd|\bpw\b|_pw\b|pw_", window, re.I)
            out.append(Match(i, _snip(line), "high" if pw else "low",
                             "MD5/SHA-1 used near password handling" if pw else "MD5/SHA-1 used (fine for checksums, not passwords)"))
        elif _PLAIN_PW.search(line) and not re.search(r"check_password|compare|bcrypt|argon|verify|hash", line, re.I):
            out.append(Match(i, _snip(line), "medium", "Password compared in plaintext"))
    return out


# ---------------------------------------------------------------- C5 dangerous functions
_DANGER = [
    (re.compile(r"""(?<![\w.])eval\s*\((?!\s*["'][^"']*["']\s*\))"""), "eval() runs text as code", "high"),
    (re.compile(r"""(?<![\w.])exec\s*\((?!\s*["'][^"']*["']\s*\))"""), "exec() runs text as code", "high"),
    (re.compile(r"\bos\.(?:system|popen)\s*\("), "os.system/popen runs shell commands", "high"),
    (re.compile(r"\bsubprocess\.\w+\([^\n]*shell\s*=\s*True"), "subprocess with shell=True", "high"),
    (re.compile(r"\bpickle\.loads?\s*\("), "pickle can execute code when loading data", "medium"),
    (re.compile(r"\byaml\.load\s*\((?![^\n]*Loader\s*=\s*(?:yaml\.)?C?Safe)"), "yaml.load without SafeLoader", "medium"),
    (re.compile(r"\bchild_process\b[^\n]*\.exec(?:Sync)?\s*\(|(?<![\w.])execSync\s*\("), "child_process exec runs shell commands", "high"),
    (re.compile(r"\bnew\s+Function\s*\("), "new Function() runs text as code", "medium"),
]


def detect_dangerous(f: SourceFile):
    if f.ext not in PY | JS:
        return []
    out = []
    for i, line in _code(f):
        for pat, note, conf in _DANGER:
            if pat.search(line):
                out.append(Match(i, _snip(line), conf, note))
                break
    return out


# ---------------------------------------------------------------- C6 debug mode
_DEBUG = [
    (re.compile(r"\bdebug\s*=\s*True\b"), "debug=True", "high"),
    (re.compile(r"^\s*DEBUG\s*=\s*True\b"), "DEBUG = True", "medium"),
    (re.compile(r"""FLASK_DEBUG["']?\s*[=:]\s*["']?(?:1|true)""", re.I), "FLASK_DEBUG enabled", "medium"),
    (re.compile(r"return[^\n]*traceback\.format_exc\(\)"), "Stack trace returned to the client", "high"),
    (re.compile(r"(?:res|response)\.(?:send|json)\([^\n]*\b(?:err|error|e)\.stack\b"), "Stack trace sent to the client", "medium"),
]


def detect_debug(f: SourceFile):
    if f.ext not in PY | JS | {".env", ".ini", ".cfg", ".yml", ".yaml", ".toml"}:
        return []
    out = []
    for i, line in _code(f):
        if re.match(r"\s*def\s", line):
            continue
        for pat, note, conf in _DEBUG:
            if pat.search(line):
                out.append(Match(i, _snip(line), conf, note))
                break
    return out


# ---------------------------------------------------------------- C7 cookies and sessions
_WEAK_SECRETS = {"dev", "secret", "changeme", "password", "123456", "test", "key", "default", "supersecret",
                 "secretkey", "mysecret", "development", "admin"}
_COOKIE = [
    (re.compile(r"SESSION_COOKIE_HTTPONLY[\"'\]\s=:]*False"), "Session cookie HttpOnly disabled", "high"),
    (re.compile(r"SESSION_COOKIE_SECURE[\"'\]\s=:]*False"), "Session cookie Secure flag disabled", "medium"),
    (re.compile(r"SESSION_COOKIE_SAMESITE[\"'\]\s=:]*None"), "Session cookie SameSite disabled", "medium"),
    (re.compile(r"httponly\s*[=:]\s*(?:False|false)", re.I), "Cookie HttpOnly disabled", "high"),
    (re.compile(r"\bsecure\s*:\s*false\b", re.I), "Cookie Secure flag disabled", "medium"),
]
_SECRET_KEY = re.compile(r"""\b(?:secret_key|SECRET_KEY|JWT_SECRET|SESSION_SECRET|jwtSecret)\b["'\]]*\s*[=:]\s*["']([^"'\n]*)["']""")


def detect_cookies(f: SourceFile):
    if f.ext not in PY | JS | {".env", ".ini", ".cfg", ".yml", ".yaml", ".toml"}:
        return []
    out = []
    for i, line in _code(f):
        done = False
        for pat, note, conf in _COOKIE:
            if pat.search(line):
                out.append(Match(i, _snip(line), conf, note))
                done = True
                break
        if done:
            continue
        m = _SECRET_KEY.search(line)
        if m and (m.group(1).lower() in _WEAK_SECRETS or len(m.group(1)) < 12) and not is_placeholder(m.group(1)):
            out.append(Match(i, _snip(line), "high", "Weak or guessable signing key"))
        elif re.search(r"set_cookie\(", line) and not re.search(r"httponly", line, re.I):
            out.append(Match(i, _snip(line), "low", "set_cookie without an explicit HttpOnly flag"))
    return out


# ---------------------------------------------------------------- catalog
def _c(id, title, sev, owasp, expl, before, after, steps, det=None, kind="static"):
    return CheckDef(id, title, sev, owasp, expl, before, after, tuple(steps), det, kind)


CHECKS: list[CheckDef] = [
    _c("C1", "Hardcoded secret", 5, "A02 Cryptographic Failures / A05 Security Misconfiguration",
       "A password, key or token is written directly in the code. Anyone who can read the repository, including old commits, can use it to access your services.",
       'API_KEY = "sk-••••a9f2"', 'API_KEY = os.environ["API_KEY"]',
       ["Revoke or rotate the exposed secret now.", "Load secrets from environment variables or a secret manager.",
        "Add .env to .gitignore and remove the value from git history."], detect_secrets),
    _c("C2", "SQL injection risk", 5, "A03 Injection",
       "User input is joined into the SQL text. An attacker could change what the query does and read or modify data they should not reach.",
       'q = f"SELECT * FROM users WHERE name=\'{name}\'"\ndb.execute(q)',
       'db.execute("SELECT * FROM users WHERE name = ?", (name,))',
       ["Use parameterized queries or an ORM.", "Never build SQL with f-strings, + or % formatting.", "Validate input types as well."], detect_sqli),
    _c("C3", "Cross-site scripting (XSS) risk", 4, "A03 Injection",
       "Untrusted content is written into the page as raw HTML. A malicious script could run in other users' browsers and steal sessions.",
       "el.innerHTML = userInput", "el.textContent = userInput",
       ["Prefer textContent or auto-escaped template output.", "Remove |safe / Markup() on user data.", "If HTML is required, sanitize it with a vetted library."], detect_xss),
    _c("C4", "Weak password handling", 4, "A02 Cryptographic Failures",
       "Passwords are hashed with a fast, broken algorithm or compared as plain text. If the database leaks, passwords can be recovered quickly.",
       "hashlib.md5(pw.encode()).hexdigest()", "generate_password_hash(pw)  # or bcrypt / argon2",
       ["Use bcrypt, scrypt or argon2 with a per-user salt.", "Compare using the library's verify function.", "Re-hash existing users on next login."], detect_weak_crypto),
    _c("C5", "Dangerous function use", 4, "A03 Injection",
       "Functions like eval or shell execution run text as code or commands. If any part comes from a user, an attacker can run their own code.",
       "result = eval(user_expr)", "result = ast.literal_eval(user_expr)  # or a small allow-list parser",
       ["Avoid eval/exec on anything user-controlled.", "Use subprocess with a list of arguments and shell=False.", "Replace pickle/yaml.load with safe formats."], detect_dangerous),
    _c("C6", "Debug mode enabled", 3, "A05 Security Misconfiguration",
       "Debug mode can expose stack traces, source code and, in some frameworks, an interactive console to anyone who triggers an error.",
       "app.run(debug=True)", 'app.run(debug=os.environ.get("FLASK_DEBUG") == "1")',
       ["Turn debug off outside local development.", "Return a generic error page and log details server-side."], detect_debug),
    _c("C7", "Insecure cookie or session settings", 3, "A05 Security Misconfiguration / A07 Authentication Failures",
       "Cookies without HttpOnly/Secure/SameSite, or a guessable signing key, make session theft and forgery easier.",
       'app.secret_key = "dev"\napp.config["SESSION_COOKIE_HTTPONLY"] = False',
       'app.secret_key = os.environ["SECRET_KEY"]\napp.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SECURE=True, SESSION_COOKIE_SAMESITE="Lax")',
       ["Set HttpOnly, Secure and SameSite on session cookies.", "Use a long random signing key from the environment."], detect_cookies),
    _c("C8", "Missing input validation", 3, "A03 Injection / A04 Insecure Design",
       "The handler reads data from the request without validating its type, size or format, which makes injection and crash bugs more likely.",
       'data = request.get_json()\ndb.add(data["title"])',
       "class TaskIn(BaseModel):\n    title: constr(max_length=100)\ndata = TaskIn(**request.get_json())",
       ["Define a schema (pydantic, marshmallow, zod, joi).", "Reject unknown or oversized fields.", "Return 400 with a clear message on invalid input."], None, "route"),
    _c("C9", "Unprotected sensitive route", 5, "A01 Broken Access Control",
       "This route looks sensitive but has no visible authentication or authorization check. Anyone who knows the URL may be able to call it.",
       '@app.route("/admin/users")\ndef users(): ...', '@app.route("/admin/users")\n@login_required\n@admin_required\ndef users(): ...',
       ["Require login on the route (decorator, dependency or middleware).", "Check the user's role for admin actions.", "Deny by default and open routes explicitly."], None, "route"),
    _c("C10", "Possible IDOR (missing ownership check)", 4, "A01 Broken Access Control",
       "The route takes an object ID from the URL but does not visibly check that the object belongs to the logged-in user. Users may read or change each other's data.",
       "task = Task.query.get(task_id)", "task = Task.query.filter_by(id=task_id, owner_id=current_user.id).first_or_404()",
       ["Filter by the current user when loading the object.", "Return 404 or 403 when it belongs to someone else."], None, "route"),
    _c("C11", "Missing security headers", 2, "A05 Security Misconfiguration",
       "The live response lacks standard browser protections, which makes clickjacking, MIME sniffing and some XSS attacks easier.",
       "(no security headers set)", "@app.after_request\ndef headers(r):\n    r.headers['X-Content-Type-Options'] = 'nosniff'\n    r.headers['X-Frame-Options'] = 'DENY'\n    r.headers['Content-Security-Policy'] = \"default-src 'self'\"\n    return r",
       ["Add CSP, X-Frame-Options and X-Content-Type-Options.", "Add HSTS when serving over HTTPS."], None, "live"),
    _c("C12", "Permissive CORS", 3, "A05 Security Misconfiguration",
       "The API allows any website to read its responses from a browser. With credentials, this can expose user data.",
       'CORS(app, origins="*")', 'CORS(app, origins=["https://your-frontend.example"])',
       ["List the exact origins you trust.", "Never combine * with credentials."], None, "live"),
    _c("C13", "Sensitive endpoint reachable without credentials", 5, "A01 Broken Access Control",
       "A sensitive-looking endpoint returned a successful response to an anonymous GET request in the live check.",
       "GET /admin/users -> 200 OK (anonymous)", "GET /admin/users -> 401 Unauthorized (anonymous)",
       ["Require authentication before returning data.", "Re-run the live check after the fix."], None, "live"),
]
CHECK_BY_ID = {c.id: c for c in CHECKS}
