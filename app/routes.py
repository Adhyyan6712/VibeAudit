"""Endpoint inventory (Flask/FastAPI via ast, Express via regex) and route-based checks C8, C9, C10."""
import ast
import re

from .loader import SourceFile
from .models import Endpoint
from .rules import JS, Match
from .masking import mask_text

AUTH_NAME = re.compile(r"(?i)(login[_]?required|logged[_]?in|jwt|auth|permission|requires?_|token_required|roles?_|admin_required|protect|verify|current_user|get_current|oauth|api_key_required)")
INLINE_AUTH = re.compile(r"(session\s*\[|session\.get\(|current_user|\bg\.user\b|Authorization|abort\(\s*40[13]|HTTPException\([^)]*40[13]|jwt\.decode|is_authenticated|is_admin|req\.user|req\.session|res\.status\(\s*40[13]\))")
OWNERSHIP = re.compile(r"""(?i)(?:(?:user_id|owner(?:_id)?|\.user|userId)\s*(?:==|!=|===|!==)|(?:==|!=|===|!==)\s*(?:session|current_user|g\.user|req\.user|request\.user)|(?:filter_by|filter|where|find\w*)\([^)\n]*(?:user_id|owner|userId)[^)\n]*(?:session|current_user|g\.user|req\.user)|current_user\.(?:id|has_access|can)|(?:can|has)_(?:access|permission)\()""")
VALIDATION = re.compile(r"(?i)(validate|schema|basemodel|marshmallow|wtforms|jsonschema|cerberus|pydantic|isinstance\(|\bjoi\b|\bzod\b|\byup\b|celebrate|express-validator|checkSchema)")
DB_HINT = re.compile(r"(?i)(execute|\.get\(|\.query|\.filter|find\w*\(|select\s|\.where|\.first\()")
BODY_READ = re.compile(r"request\.(?:get_json\(|json\b|form\b|data\b|values\b)|req\.body")
PUBLIC_PATH = re.compile(r"(?i)^/?(?:$|login|logout|register|signup|sign-up|signin|health|healthz|ping|static|favicon|docs|openapi|robots|index|home|about|public|auth|token|oauth|callback|forgot|reset)\b")
SENSITIVE_PATH = re.compile(r"(?i)(admin|delete|remove|destroy|user|account|export|config|setting|internal|debug|backup|payment|billing|secret|key|dump|manage|upload)")
CRITICAL_PATH = re.compile(r"(?i)(admin|delete|remove|destroy|payment|billing|backup|dump|secret)")
WRITE = {"POST", "PUT", "PATCH", "DELETE"}
ROUTE_ATTRS = {"route", "get", "post", "put", "delete", "patch", "api_route", "head", "options"}
PATH_PARAM = re.compile(r"<(?:[\w.]+:)?(\w+)>|\{(\w+)(?::[^}]*)?\}|/:(\w+)")
EXP_ROUTE = re.compile(r"""\b(?P<obj>\w+)\.(?P<m>get|post|put|delete|patch|all)\(\s*(?P<q>["'`])(?P<path>/[^"'`]*)(?P=q)\s*(?P<rest>,.*)?$""")
EXP_CLIENT = {"axios", "http", "$", "fetch", "request", "superagent", "client", "agent", "supertest", "cy", "page"}


def _is_test(path: str) -> bool:
    p = path.lower()
    return bool(re.search(r"(^|/)(tests?|__tests__|spec)/|(^|/)test_|\.(test|spec)\.", p))


def _id_params(path: str) -> list[str]:
    names = [next(g for g in m.groups() if g) for m in PATH_PARAM.finditer(path)]
    return [n for n in names if n.lower() in {"id", "uid", "pk", "uuid"} or n.lower().endswith("_id") or n.endswith("Id")]


def _ctx(f: SourceFile, line: int) -> str:
    lo, hi = max(0, line - 4), min(len(f.lines), line + 3)
    return mask_text("\n".join(f"{n + 1}: {f.lines[n]}" for n in range(lo, hi)))


class _Out:
    def __init__(self):
        self.endpoints: list[Endpoint] = []
        self.matches: list[tuple[str, str, Match]] = []

    def add(self, f, line, deco_line, methods, path, handler, status, note, body, body_read_line):
        public = bool(PUBLIC_PATH.match(path)) or path in ("", "/")
        ids = _id_params(path)
        own = "n/a"
        if ids:
            own = "yes" if OWNERSHIP.search(body) else "no"
        if status == "unprotected" and public:
            note = (note + " " if note else "") + "Public by convention (login, health, static, docs)."
        self.endpoints.append(Endpoint(method=",".join(methods), path=path or "/", handler=handler, file=f.path,
                                       line=line, auth_status=status, ownership_check=own, public=public, notes=note.strip()))
        snippet = mask_text(deco_line.strip())[:300]
        write = any(m in WRITE for m in methods)
        if status == "unprotected" and not public and (SENSITIVE_PATH.search(path) or write):
            crit = bool(CRITICAL_PATH.search(path))
            self.matches.append(("C9", f.path, Match(line, snippet, "high" if crit else "medium",
                                                     "No authentication found on a sensitive route", 5 if crit else 4)))
        if ids and own == "no" and not public and not re.search(r"(?i)admin|role", path + " " + note):
            self.matches.append(("C10", f.path, Match(line, snippet, "medium" if DB_HINT.search(body) else "low",
                                                      f"ID parameter '{ids[0]}' is used without a visible ownership check")))
        if write and body_read_line and not VALIDATION.search(body):
            self.matches.append(("C8", f.path, Match(body_read_line, mask_text(f.lines[body_read_line - 1].strip())[:300],
                                                     "medium", "Request body used without visible validation")))


# ------------------------------------------------------------------ Python (Flask / FastAPI)
def _route_info(d):
    if not (isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr in ROUTE_ATTRS):
        return None
    path = None
    if d.args and isinstance(d.args[0], ast.Constant) and isinstance(d.args[0].value, str):
        path = d.args[0].value
    else:
        for k in d.keywords:
            if k.arg in ("rule", "path") and isinstance(k.value, ast.Constant):
                path = k.value.value
    if path is None or not (path.startswith("/") or path == ""):
        return None
    methods = [d.func.attr.upper()]
    if d.func.attr in ("route", "api_route"):
        methods = ["GET"]
        for k in d.keywords:
            if k.arg == "methods" and isinstance(k.value, (ast.List, ast.Tuple, ast.Set)):
                methods = [e.value.upper() for e in k.value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)] or ["GET"]
    return methods, path


def _is_before_request(d) -> bool:
    t = ast.unparse(d)
    return "before_request" in t or "before_app_request" in t


def _py(f: SourceFile, out: _Out):
    try:
        tree = ast.parse(f.text)
    except (SyntaxError, ValueError):
        return
    funcs = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    seg = lambda n: "\n".join(f.lines[n.lineno - 1: n.end_lineno])
    guard = any(any(_is_before_request(d) for d in n.decorator_list) and (INLINE_AUTH.search(seg(n)) or AUTH_NAME.search(seg(n)))
                for n in funcs)
    for node in funcs:
        routes, auths = [], []
        for d in node.decorator_list:
            r = _route_info(d)
            if r:
                routes.append((d, *r))
            else:
                t = ast.unparse(d)
                if AUTH_NAME.search(t):
                    auths.append(t)
        if not routes:
            continue
        auth = ", ".join(auths) or None
        body = seg(node)
        defaults = list(node.args.defaults) + [k for k in node.args.kw_defaults if k]
        dep = next((ast.unparse(x) for x in defaults if re.search(r"Depends\(|Security\(", ast.unparse(x)) and AUTH_NAME.search(ast.unparse(x))), None)
        read_line = next((i for i in range(node.lineno, node.end_lineno + 1) if BODY_READ.search(f.lines[i - 1])), 0)
        for d, methods, path in routes:
            route_dep = next((ast.unparse(k.value) for k in d.keywords if k.arg == "dependencies" and AUTH_NAME.search(ast.unparse(k.value))), None)
            status, note = "unprotected", ""
            if auth or dep or route_dep:
                status, note = "protected", f"Auth via {auth or dep or route_dep}."
            elif INLINE_AUTH.search(body):
                status, note = "unknown", "Inline auth/session check found; verify it covers every case."
            elif guard:
                status, note = "unknown", "A before_request guard exists in this file; verify it covers this route."
            out.add(f, node.lineno, f.lines[d.lineno - 1], methods, path, node.name, status, note, body, read_line)


# ------------------------------------------------------------------ Express
def _js(f: SourceFile, out: _Out):
    guard = False
    n = len(f.lines)
    route_idx = [i for i, ln in enumerate(f.lines) if EXP_ROUTE.search(ln)]
    for i, line in enumerate(f.lines):
        if re.search(r"\.use\(\s*[\w.]*(?:auth|jwt|passport|protect|verify)", line, re.I):
            guard = True
        m = EXP_ROUTE.search(line)
        if not m or m.group("obj") in EXP_CLIENT:
            continue
        nxt = next((j for j in route_idx if j > i), n)
        body = "\n".join(f.lines[i: min(nxt, i + 30)])
        rest = m.group("rest") or ""
        if not re.search(r"=>|function|\w", rest):
            continue
        status, note = "unprotected", ""
        if AUTH_NAME.search(rest):
            status, note = "protected", "Auth middleware on the route."
        elif INLINE_AUTH.search(body):
            status, note = "unknown", "Inline auth/session check found; verify it."
        elif guard:
            status, note = "unknown", "Global auth middleware (app.use) found earlier in this file; verify it."
        read_line = next((i + k + 1 for k, ln in enumerate(body.split("\n")) if re.search(r"req\.body", ln)), 0)
        if VALIDATION.search(f.text):
            read_line = 0
        method = m.group("m").upper()
        out.add(f, i + 1, line, ["GET", "POST", "PUT", "DELETE", "PATCH"] if method == "ALL" else [method],
                m.group("path"), "handler", status, note, body, read_line)


def analyze_routes(files: list[SourceFile]):
    out = _Out()
    for f in files:
        if _is_test(f.path):
            continue
        if f.ext == ".py":
            _py(f, out)
        elif f.ext in JS:
            _js(f, out)
    out.endpoints.sort(key=lambda e: ({"unprotected": 0, "unknown": 1, "protected": 2}[e.auth_status], e.file, e.line))
    return out.endpoints, out.matches
