# app/routes/logout.py
from flask import Blueprint, session, jsonify, request
from app.utils.csrf import csrf_protect
from datetime import datetime, timezone
from app.utils.logger import logger

logout_bp = Blueprint("logout", __name__)

@logout_bp.route("/logout", methods=["POST"])
@csrf_protect
def logout():
    try:
        user_id = session.get("user_id")
        username = session.get("username", "Unknown")
        email = session.get("email", "Unknown")
        session.clear()
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        logger.info(f"用户登出: UID={user_id}, Username={username}, Email={email}, IP={client_ip}")
        return jsonify({"success": True, "message": "已登出", "timestamp": datetime.now(timezone.utc).isoformat()})
    except Exception as e:
        logger.error(f"登出异常: {e}")
        return jsonify({"success": False, "message": "服务器错误"}), 500