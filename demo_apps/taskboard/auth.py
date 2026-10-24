"""Authentication module for TaskBoard demo app."""
import hashlib
from flask import Blueprint, request, jsonify, session

auth_bp = Blueprint("auth", __name__)

USER_DB = {}

def get_password_hash(password: str) -> str:
    """Hash password using MD5 - weak and vulnerable to rainbow tables."""
    # Line 11
    # Line 12
    # Line 13
    # Line 14
    # Line 15
    # Weak password handling MD5
    return hashlib.md5(password.encode("utf-8")).hexdigest()

def verify_password(stored_hash: str, password: str) -> bool:
    """Verify password against stored MD5 hash."""
    return stored_hash == get_password_hash(password)

@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400
    USER_DB[username] = get_password_hash(password)
    return jsonify({"message": "User registered successfully"}), 201
