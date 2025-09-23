from functools import wraps
from flask import session, jsonify
from datetime import datetime, timedelta, timezone
import logging
import config 

logger = logging.getLogger(__name__)

def error_response(message, status_code, error_code=None):
    response_data = {
        "success": False,
        "message": message,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    if error_code:
        response_data["error_code"] = error_code
    return jsonify(response_data), status_code

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            logger.warning("缺少认证 Session")
            return error_response("请先登录", 401)

        last_active_str = session.get("last_active")
        if not last_active_str:
            session.clear()
            return error_response("登录已过期，请重新登录", 401)

        try:
            last_active = datetime.fromisoformat(last_active_str)
            if last_active.tzinfo is None:
                last_active = last_active.replace(tzinfo=timezone.utc)
        except Exception:
            session.clear()
            return error_response("登录已过期，请重新登录", 401)

        now_utc = datetime.now(timezone.utc)
        if now_utc - last_active > timedelta(days=config.SESSION_EXPIRE_DAYS):
            session.clear()
            return error_response("登录已过期，请重新登录", 401)

        # 更新活跃时间
        session["last_active"] = now_utc.isoformat()
        return f(session["user_id"], *args, **kwargs)
    return decorated

def get_current_user():
    return session.get("user_id")