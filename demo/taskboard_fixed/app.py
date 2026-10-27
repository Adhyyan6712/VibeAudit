import os
import sqlite3
from functools import wraps

from flask import Flask, abort, jsonify, request, session
from markupsafe import escape
from pydantic import BaseModel, constr
from werkzeug.security import check_password_hash

import config

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SECURE=True, SESSION_COOKIE_SAMESITE="Lax")
db = sqlite3.connect("tasks.db", check_same_thread=False)


class LoginIn(BaseModel):
    name: constr(max_length=50)
    password: constr(min_length=8, max_length=128)


class TaskIn(BaseModel):
    title: constr(min_length=1, max_length=100)


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            abort(401)
        return view(*args, **kwargs)
    return wrapper


def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("is_admin"):
            abort(403)
        return view(*args, **kwargs)
    return wrapper


@app.route("/login", methods=["POST"])
def login():
    data = LoginIn.model_validate(request.get_json())
    row = db.execute("SELECT id, pw FROM users WHERE name = ?", (data.name,)).fetchone()
    ok = bool(row) and check_password_hash(row[1], data.password)
    if ok:
        session["user_id"] = row[0]
    return jsonify(ok=ok)


@app.route("/admin/users")
@login_required
@admin_required
def admin_users():
    return jsonify(db.execute("SELECT id, name FROM users").fetchall())


@app.route("/admin/delete/<int:user_id>", methods=["POST", "DELETE"])
@login_required
@admin_required
def admin_delete(user_id):
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    return jsonify(ok=True)


@app.route("/tasks/<int:task_id>")
@login_required
def get_task(task_id):
    row = db.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
    if row is None or row[2] != session["user_id"]:
        abort(404)
    return jsonify(row)


@app.route("/comments")
def comments():
    return "<p>" + str(escape(request.args.get("t", ""))) + "</p>"


@app.route("/api/tasks", methods=["POST"])
@login_required
def create_task():
    data = TaskIn.model_validate(request.get_json())
    db.execute("INSERT INTO tasks (title) VALUES (?)", (data.title,))
    return jsonify(ok=True)


@app.route("/health")
def health():
    return "ok"


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
