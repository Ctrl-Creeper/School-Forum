# /utils/csrf.py
import secrets
from flask import session, jsonify, request
from functools import wraps

def generate_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]

def verify_csrf_token(token):
    stored_token = session.get("csrf_token")
    if not stored_token or token != stored_token:
        return False
    session.pop("csrf_token", None)
    return True

def csrf_protect(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == "POST":
            token = (request.headers.get("X-CSRF-Token") or 
                     request.form.get("csrf_token") or 
                     (request.json and request.json.get("csrf_token")))
            from app.utils.logger import logging
            if not token or not verify_csrf_token(token):
                logging.warning(f"CSRF 保护触发: {request.path}")
                return jsonify({"success": False, "message": "CSRF token 验证失败"}), 403
        return f(*args, **kwargs)
    return decorated_function