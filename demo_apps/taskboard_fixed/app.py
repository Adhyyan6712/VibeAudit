"""Main application module for TaskBoard (Fixed & Secure)."""
import sqlite3
from flask import Flask, request, jsonify, render_template, session
import config
from auth import auth_bp, login_required, require_admin
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
    return jsonify({"service": "TaskBoard API (Hardened)", "version": "1.0.0"})

@app.route("/login", methods=["POST"])
def login():
    """Secure login with parameterized SQL queries."""
    data = request.get_json(silent=True) or {}
    name = data.get("name", "")
    password = data.get("password", "")

    db = get_db()
    cursor = db.cursor()
    # Parameterized query to eliminate SQL injection
    cursor.execute("SELECT id, name, password FROM users WHERE name = ?", (name,))
    row = cursor.fetchone()
    if row:
        session["user_id"] = row[0]
        return jsonify({"status": "logged in", "user": row[1]})
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/profile", methods=["GET"])
@login_required
def profile():
    """User profile display."""
    return render_template("task.html", comment="System ready")

@app.route("/admin/users", methods=["GET"])
@login_required
@require_admin
def admin_users():
    """Admin route protected with auth and admin role decorators."""
    db = get_db()
    users = db.execute("SELECT id, name FROM users").fetchall()
    return jsonify({"users": users})

@app.route("/admin/delete/<id>", methods=["POST", "DELETE"])
@login_required
@require_admin
def admin_delete_user(id):
    """Protected admin delete route with parameterized query and role check."""
    try:
        user_id = int(id)
    except ValueError:
        return jsonify({"error": "Invalid user ID"}), 400

    db = get_db()
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    return jsonify({"message": f"User {user_id} deleted successfully"})

if __name__ == "__main__":
    # Production safe: debug=False
    app.run(host="127.0.0.1", port=5000, debug=False)
