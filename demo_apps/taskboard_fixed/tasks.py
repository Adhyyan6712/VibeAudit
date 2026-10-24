"""Tasks management module for TaskBoard (Fixed & Secure)."""
from flask import Blueprint, request, jsonify, session, escape
from auth import login_required

tasks_bp = Blueprint("tasks", __name__)

TASKS_STORE = {
    1: {"id": 1, "user_id": 101, "title": "Audit AI code", "status": "pending", "comment": "Review with team"},
    2: {"id": 2, "user_id": 102, "title": "Submit Hackathon project", "status": "done", "comment": "On time"},
}

@tasks_bp.route("/tasks", methods=["GET"])
@login_required
def list_tasks():
    """List tasks owned by current user."""
    current_uid = session.get("user_id")
    user_tasks = [t for t in TASKS_STORE.values() if t.get("user_id") == current_uid]
    return jsonify(user_tasks)

@tasks_bp.route("/tasks/<id>", methods=["GET"])
@login_required
def get_task(id):
    """Retrieve task by ID - Ownership check enforced (Prevents IDOR)."""
    try:
        task_id = int(id)
    except ValueError:
        return jsonify({"error": "Invalid task ID"}), 400

    task = TASKS_STORE.get(task_id)
    if not task:
        return jsonify({"error": "Task not found"}), 404

    # Ownership check
    current_user_id = session.get("user_id")
    if task.get("user_id") != current_user_id:
        return jsonify({"error": "Forbidden: Not your task"}), 403

    return jsonify(task)

@tasks_bp.route("/api/tasks", methods=["POST"])
@login_required
def create_task():
    """Create task - Validates schema and fields explicitly."""
    payload = request.get_json(silent=True)
    if not payload or not isinstance(payload, dict):
        return jsonify({"error": "Invalid JSON body"}), 400

    title = payload.get("title")
    if not title or not isinstance(title, str) or len(title) > 200:
        return jsonify({"error": "Title required and must be under 200 chars"}), 400

    status = payload.get("status", "pending")
    if status not in {"pending", "in_progress", "done"}:
        return jsonify({"error": "Invalid status value"}), 400

    new_id = len(TASKS_STORE) + 1
    task = {
        "id": new_id,
        "title": escape(title.strip()),
        "status": status,
        "user_id": session.get("user_id")
    }
    TASKS_STORE[new_id] = task
    return jsonify(task), 201

@tasks_bp.route("/tasks/filter", methods=["POST"])
@login_required
def filter_tasks():
    """Filter tasks using safe dictionary lookups instead of eval()."""
    status_filter = request.args.get("status", "").strip().lower()
    allowed_statuses = {"pending", "in_progress", "done"}
    current_uid = session.get("user_id")

    results = [t for t in TASKS_STORE.values() if t.get("user_id") == current_uid]
    if status_filter in allowed_statuses:
        results = [t for t in results if t.get("status") == status_filter]

    return jsonify(results)

@tasks_bp.route("/tasks/<id>/comment", methods=["POST"])
@login_required
def add_comment(id):
    """Add comment with HTML escaped safely."""
    comment = request.form.get("comment", "")
    safe_comment = escape(comment)
    return jsonify({"id": id, "comment": safe_comment})
