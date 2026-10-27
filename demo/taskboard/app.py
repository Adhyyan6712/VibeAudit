import hashlib
import sqlite3

from flask import Flask, jsonify, render_template_string, request, session

import config

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
app.config["SESSION_COOKIE_HTTPONLY"] = False
db = sqlite3.connect("tasks.db", check_same_thread=False)


def hash_pw(pw):
    return hashlib.md5(pw.encode()).hexdigest()


@app.route("/login", methods=["POST"])
def login():
    name = request.form["name"]
    pw = hash_pw(request.form["password"])
    q = f"SELECT * FROM users WHERE name='{name}' AND pw='{pw}'"
    row = db.execute(q).fetchone()
    if row:
        session["user_id"] = row[0]
    return jsonify(ok=bool(row))


@app.route("/admin/users")
def admin_users():
    return jsonify(db.execute("SELECT * FROM users").fetchall())


@app.route("/admin/delete/<int:user_id>", methods=["POST", "DELETE"])
def admin_delete(user_id):
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    return jsonify(ok=True)


@app.route("/tasks/<int:task_id>")
def get_task(task_id):
    row = db.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
    return jsonify(row)


@app.route("/comments")
def comments():
    text = request.args.get("t", "")
    return render_template_string("<p>" + text + "</p>")


@app.route("/filter")
def apply_filter():
    expr = request.args.get("expr", "1")
    return str(eval(expr))


@app.route("/api/tasks", methods=["POST"])
def create_task():
    data = request.get_json()
    db.execute("INSERT INTO tasks (title) VALUES (?)", (data["title"],))
    return jsonify(ok=True)


@app.route("/health")
def health():
    return "ok"


if __name__ == "__main__":
    app.run(debug=True)
