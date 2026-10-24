"""Unit tests for static checks C1-C9 and route parser."""
import pytest
from backend.rule_engine.c1_secrets import CheckC1Secrets
from backend.rule_engine.c2_sqli import CheckC2SQLi
from backend.rule_engine.c3_xss import CheckC3XSS
from backend.rule_engine.c4_passwords import CheckC4Passwords
from backend.rule_engine.c5_dangerous import CheckC5Dangerous
from backend.rule_engine.c6_debug import CheckC6Debug
from backend.rule_engine.c7_cookies import CheckC7Cookies
from backend.rule_engine.c8_validation import CheckC8Validation
from backend.route_parser import parse_routes_and_access

def test_c1_hardcoded_secrets():
    c1 = CheckC1Secrets()
    files = {
        "config.py": 'API_KEY = "sk-live-9481abf082e4a9f2"\nSECRET = "plain_secret_12345"',
        "clean.py": 'API_KEY = os.environ.get("API_KEY")'
    }
    matches = c1.detect(files)
    assert len(matches) >= 1
    assert matches[0].file == "config.py"
    assert "sk-" in matches[0].snippet

def test_c2_sqli():
    c2 = CheckC2SQLi()
    files = {
        "app.py": '@app.route("/login")\ndef login():\n    q = "SELECT * FROM users WHERE name=\'" + name + "\'\"\n    db.execute(q)'
    }
    matches = c2.detect(files)
    assert len(matches) == 1
    assert matches[0].line == 3
    assert matches[0].confidence == "high"

def test_c3_xss():
    c3 = CheckC3XSS()
    files = {
        "templates/comment.html": '<div class="body">{{ comment | safe }}</div>',
        "safe.html": '<div>{{ comment }}</div>'
    }
    matches = c3.detect(files)
    assert len(matches) == 1
    assert "templates/comment.html" in matches[0].file

def test_c4_passwords():
    c4 = CheckC4Passwords()
    files = {
        "auth.py": 'def hash_pwd(p):\n    return hashlib.md5(p.encode()).hexdigest()'
    }
    matches = c4.detect(files)
    assert len(matches) == 1
    assert "MD5" in matches[0].title

def test_c5_dangerous():
    c5 = CheckC5Dangerous()
    files = {
        "tasks.py": 'def filter_items():\n    matched = [x for x in items if eval(expr)]'
    }
    matches = c5.detect(files)
    assert len(matches) == 1
    assert matches[0].custom_verdict == "needs_validation"

def test_c6_debug():
    c6 = CheckC6Debug()
    files = {
        "run.py": 'if __name__ == "__main__":\n    app.run(debug=True)'
    }
    matches = c6.detect(files)
    assert len(matches) == 1
    assert matches[0].line == 2

def test_c7_cookies():
    c7 = CheckC7Cookies()
    files = {
        "config.py": 'SESSION_COOKIE_HTTPONLY = False\nSESSION_COOKIE_SECURE = False'
    }
    matches = c7.detect(files)
    assert len(matches) == 1

def test_c8_validation():
    c8 = CheckC8Validation()
    files = {
        "api.py": 'def save():\n    data = request.json\n    db.save(data)'
    }
    matches = c8.detect(files)
    assert len(matches) == 1

def test_c9_unprotected_route():
    source = """
@app.route("/admin/delete/<id>", methods=["POST", "DELETE"])
def delete_user(id):
    db.execute(f"DELETE FROM users WHERE id = {id}")
"""
    endpoints, c9_matches, _ = parse_routes_and_access({"app.py": source})
    assert len(endpoints) == 2 # POST and DELETE
    assert len(c9_matches) == 1
    assert c9_matches[0].confidence == "high"
