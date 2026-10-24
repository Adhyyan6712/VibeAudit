"""Tasks management module for TaskBoard."""
from flask import Blueprint, request, jsonify, session, render_template_string

tasks_bp = Blueprint("tasks", __name__)

TASKS_STORE = {
    1: {"id": 1, "user_id": 101, "title": "Audit AI code", "status": "pending", "comment": "Review with team"},
    2: {"id": 2, "user_id": 102, "title": "Submit Hackathon project", "status": "done", "comment": "On time"},
}

@tasks_bp.route("/tasks", methods=["GET"])
def list_tasks():
    """List all tasks."""
    return jsonify(list(TASKS_STORE.values()))

@tasks_bp.route("/tasks/<id>", methods=["GET"])
def get_task(id):
    """Retrieve task by ID - Flaw: C10 Possible IDOR (no ownership check)."""
    task_id = int(id)
    task = TASKS_STORE.get(task_id)
    if not task:
        return jsonify({"error": "Task not found"}), 404
    return jsonify(task)

@tasks_bp.route("/api/tasks", methods=["POST"])
def create_task():
    """Create task - Flaw: C8 Missing input validation on request.json."""
    data = request.json
    new_id = len(TASKS_STORE) + 1
    task = {
        "id": new_id,
        "title": data.get("title"),
        "status": data.get("status", "pending"),
        "user_id": data.get("user_id", 0)
    }
    TASKS_STORE[new_id] = task
    return jsonify(task), 201

# Padding lines to place eval at exactly line 52
#
#
#
#
#
#
#

@tasks_bp.route("/tasks/filter", methods=["POST"])
def filter_tasks():
    """Filter tasks using dynamic expression - Flaw: C5 Dangerous eval()."""
    expr = request.args.get("filter", "True")
    matched = [t for t in TASKS_STORE.values() if eval(expr, {"t": t})]
    return jsonify(matched)

@tasks_bp.route("/tasks/<id>/comment", methods=["POST"])
def add_comment(id):
    """Render comment - Flaw: C3 XSS risk."""
    comment = request.form.get("comment", "")
    return jsonify({"id": id, "comment": comment})
