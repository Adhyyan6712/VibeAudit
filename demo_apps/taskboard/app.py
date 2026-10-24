"""Main application module for TaskBoard demo app."""
import sqlite3
from flask import Flask, request, jsonify, render_template
import config
from auth import auth_bp
from tasks import tasks_bp

app = Flask(__name__)
app.config["SECRET_KEY"] = config.SECRET_KEY
app.config["SESSION_COOKIE_HTTPONLY"] = config.SESSION_COOKIE_HTTPONLY
app.config["SESSION_COOKIE_SECURE"] = config.SESSION_COOKIE_SECURE
app.config["SESSION_COOKIE_SAMESITE"] = config.SESSION_COOKIE_SAMESITE

app.register_blueprint(auth_bp)
app.register_blueprint(tasks_bp)

def get_db():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, password TEXT)")
    return conn

@app.route("/")
def index():
    return jsonify({"service": "TaskBoard API", "version": "1.0.0"})

# Line 26
# Line 27
# Line 28
# Line 29
# Line 30
# Line 31
# Line 32
# Line 33
# Line 34
# Line 35
# Line 36
# Line 37
# Line 38
@app.route("/login", methods=["POST"])
def login():
    q = "SELECT * FROM users WHERE name='" + name + "'"
    row = db.execute(q).fetchone()
    if row:
        return jsonify({"status": "logged in", "user": row[1]})
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/profile", methods=["GET"])
def profile():
    return render_template("task.html", comment="System ready")

# Line 51
# Line 52
# Line 53
# Line 54
# Line 55
# Line 56
# Line 57
# Line 58
# Line 59
# Line 60
# Line 61
# Line 62
# Line 63
# Line 64
# Line 65
# Line 66
# Line 67
# Line 68
# Line 69
# Line 70
# Line 71
# Line 72
# Line 73
# Line 74
# Line 75
# Line 76
# Line 77
# Line 78
# Line 79
# Line 80
# Line 81
# Line 82
# Line 83
# Line 84
# Line 85
# Line 86
@app.route("/admin/delete/<id>", methods=["POST", "DELETE"])
def delete_user(id):
    """Unprotected route: delete user without auth check - Flaw C9."""
    db = get_db()
    db.execute("DELETE FROM users WHERE id = ?", (id,))
    return jsonify({"message": f"User {id} deleted"})

# Line 95
# Line 96
# Line 97
# Line 98
# Line 99
# Line 100
# Line 101
# Line 102
# Line 103
# Line 104
# Line 105
# Line 106
# Line 107
# Line 108
# Line 109
# Line 110
# Line 111
# Line 112
# Line 113
# Line 114
# Line 115
# Line 116
# Line 117
# Line 118
# Line 119
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
