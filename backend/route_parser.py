"""Route and endpoint parser using Python AST (Stage 3 & FR-5)."""
import ast
import re
from typing import List, Tuple, Dict, Any
from backend.models import Endpoint
from backend.rule_engine.base import RawMatch

AUTH_DECORATORS = {
    "login_required", "require_admin", "require_auth", "auth_required",
    "jwt_required", "admin_required", "token_required", "roles_accepted"
}

ID_PATH_PARAM = re.compile(r"""<(?:[a-zA-Z_]+:)?([a-zA-Z0-9_]*id[a-zA-Z0-9_]*)>""")

class FlaskRouteVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str, source_code: str):
        self.file_path = file_path
        self.source_code = source_code
        self.endpoints: List[Endpoint] = []
        self.c9_matches: List[RawMatch] = []
        self.c10_matches: List[RawMatch] = []
        self.lines = source_code.splitlines()

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._check_route_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._check_route_function(node)
        self.generic_visit(node)

    def _check_route_function(self, node):
        route_decorator = None
        has_auth_decorator = False
        auth_dec_names = []

        for dec in node.decorator_list:
            dec_name = self._get_decorator_name(dec)
            if dec_name:
                if dec_name in AUTH_DECORATORS or any(a in dec_name.lower() for a in ["login_required", "require_admin", "auth"]):
                    has_auth_decorator = True
                    auth_dec_names.append(dec_name)
                if any(r in dec_name.lower() for r in ["route", "get", "post", "put", "delete", "patch"]):
                    route_decorator = dec

        if not route_decorator:
            return

        # Extract path and methods
        path = "/"
        methods = ["GET"]

        if isinstance(route_decorator, ast.Call):
            if route_decorator.args and isinstance(route_decorator.args[0], ast.Constant):
                path = str(route_decorator.args[0].value)

            for kw in route_decorator.keywords:
                if kw.arg == "methods":
                    if isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                        methods = [
                            elt.value for elt in kw.value.elts
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
                        ]

            dec_func_name = self._get_decorator_name(route_decorator.func)
            if dec_func_name:
                for verb in ["post", "put", "delete", "patch", "get"]:
                    if dec_func_name.lower().endswith("." + verb):
                        methods = [verb.upper()]

        is_sensitive = False
        if "/admin" in path or "/delete" in path or "delete" in node.name.lower():
            is_sensitive = True
        if any(m in ["DELETE"] for m in methods):
            is_sensitive = True

        # Auth status
        if has_auth_decorator:
            auth_status = "protected"
        elif is_sensitive:
            auth_status = "unprotected"
        else:
            auth_status = "unknown"

        # Check ID parameter and ownership check
        id_match = ID_PATH_PARAM.search(path)
        ownership_check = "n/a"
        if id_match:
            ownership_check = self._inspect_ownership_check(node)

        notes = f"Decorators: {', '.join(auth_dec_names)}" if auth_dec_names else ("Unprotected sensitive handler" if auth_status == "unprotected" else "Public route")

        for m in methods:
            self.endpoints.append(Endpoint(
                method=m,
                path=path,
                handler=node.name,
                file=self.file_path,
                line=node.lineno,
                auth_status=auth_status,
                ownership_check=ownership_check,
                notes=notes
            ))

        # C9 match for unprotected sensitive route
        if auth_status == "unprotected" and "delete" in node.name.lower():
            start_c = max(0, node.lineno - 2)
            end_c = min(len(self.lines), node.lineno + 4)
            ctx = "\n".join(self.lines[start_c:end_c])
            self.c9_matches.append(RawMatch(
                file=self.file_path,
                line=node.lineno,
                snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else f"def {node.name}()",
                context=ctx,
                confidence="high",
                title="Unprotected route: delete user",
                custom_verdict="confirmed",
                custom_verdict_reason="Sensitive user deletion route lacks authentication and authorization decorators."
            ))

    def _inspect_ownership_check(self, func_node) -> str:
        func_src = ast.unparse(func_node) if hasattr(ast, "unparse") else ""
        if any(term in func_src for term in ["user_id", "session.get('user_id')", "current_user", "session['user_id']"]):
            if any(cmp in func_src for cmp in ["==", "!=", "filter_by", "WHERE user_id"]):
                return "yes"
        return "no"

    def _get_decorator_name(self, dec) -> str:
        if isinstance(dec, ast.Name):
            return dec.id
        elif isinstance(dec, ast.Attribute):
            val_id = getattr(dec.value, "id", "")
            return f"{val_id}.{dec.attr}" if val_id else dec.attr
        elif isinstance(dec, ast.Call):
            return self._get_decorator_name(dec.func)
        return ""

def parse_routes_and_access(files: Dict[str, str]) -> Tuple[List[Endpoint], List[RawMatch], List[RawMatch]]:
    all_endpoints: List[Endpoint] = []
    c9_matches: List[RawMatch] = []
    c10_matches: List[RawMatch] = []

    for file_path, content in files.items():
        if not file_path.endswith(".py"):
            continue
        try:
            tree = ast.parse(content, filename=file_path)
            visitor = FlaskRouteVisitor(file_path, content)
            visitor.visit(tree)
            all_endpoints.extend(visitor.endpoints)
            c9_matches.extend(visitor.c9_matches)
            c10_matches.extend(visitor.c10_matches)
        except SyntaxError:
            continue

    # Deduplicate endpoints by (method, path)
    seen = set()
    dedup = []
    for ep in all_endpoints:
        key = (ep.method, ep.path)
        if key not in seen:
            seen.add(key)
            dedup.append(ep)

    return dedup, c9_matches, c10_matches
