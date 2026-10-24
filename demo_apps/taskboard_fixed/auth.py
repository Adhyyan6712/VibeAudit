"""Secure authentication module for TaskBoard demo app."""
import hashlib
import os
import hmac
from functools import wraps
from flask import Blueprint, request, jsonify, session

auth_bp = Blueprint("auth", __name__)
USER_DB = {}

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated_function

def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("is_admin"):
            return jsonify({"error": "Forbidden: Admin required"}), 403
        return f(*args, **kwargs)
    return decorated_function

def get_password_hash(password: str) -> str:
    """Hash password securely using PBKDF2 with SHA256 and unique salt."""
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
    return salt.hex() + "$" + key.hex()

def verify_password(stored_entry: str, password: str) -> bool:
    """Verify password securely using constant-time comparison."""
    if "$" not in stored_entry:
        return False
    salt_hex, key_hex = stored_entry.split("$", 1)
    salt = bytes.fromhex(salt_hex)
    key = bytes.fromhex(key_hex)
    new_key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
    return hmac.compare_digest(key, new_key)

@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    if not username or len(password) < 8:
        return jsonify({"error": "Username and password (min 8 chars) required"}), 400
    USER_DB[username] = get_password_hash(password)
    return jsonify({"message": "User registered securely"}), 201
