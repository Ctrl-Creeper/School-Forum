from flask import Blueprint, jsonify, session
from datetime import datetime, timezone
from app.utils.csrf import generate_csrf_token

csrf_token_bp = Blueprint("csrf_token", __name__)

@csrf_token_bp.route("/csrf_token", methods=["GET"])
def get_csrf_token():
    token = generate_csrf_token()
    return jsonify({
        "success": True,
        "csrf_token": token,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
