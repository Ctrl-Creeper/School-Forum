# app/routes/forget.py
from flask import Blueprint, request, jsonify
from app.utils.csrf import csrf_protect
from app.utils.validators import validate_email, validate_password
from app.services.email import send_verification_email
from app.services.verification import verify_code
from app.utils.config import config
from app.utils.db import get_db_connection
from werkzeug.security import generate_password_hash
from datetime import datetime, timezone
from app.utils.logger import logger

forget_bp = Blueprint("forget", __name__)

@forget_bp.route("/send_reset_code", methods=["POST"])
@csrf_protect
def send_reset_code():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "message": "缺少请求数据"}), 400

        email = data.get("email")
        if not email:
            return jsonify({"success": False, "message": "缺少邮箱参数"}), 400
        validate_email(email)

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT uid FROM users WHERE email=?", (email,))
            if not cursor.fetchone():
                return jsonify({"success": False, "message": "该邮箱未注册"}), 404

        if send_verification_email(email, 'reset'):
            return jsonify({"success": True, "message": "重置验证码已发送", "timestamp": datetime.now(timezone.utc).isoformat()})
        else:
            return jsonify({"success": False, "message": "验证码发送失败，请稍后重试"}), 500

    except Exception as e:
        logger.error(f"发送重置验证码异常: {e}")
        return jsonify({"success": False, "message": "服务器错误"}), 500

@forget_bp.route("/reset_password", methods=["POST"])
@csrf_protect
def reset_password():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "message": "缺少请求数据"}), 400

        email = data.get("email")
        code = data.get("code")
        new_password = data.get("new_password")
        if not all([email, code, new_password]):
            return jsonify({"success": False, "message": "缺少必要参数"}), 400

        validate_email(email)
        validate_password(new_password)

        is_valid, message = verify_code(email, code)
        if not is_valid:
            return jsonify({"success": False, "message": message}), 400

        with get_db_connection() as conn:
            cursor = conn.cursor()
            hashed_password = generate_password_hash(new_password)
            updated_at = datetime.now(timezone.utc).strftime(config["TIME_FORMAT"])
            result = cursor.execute("UPDATE users SET password=?, updated_at=? WHERE email=?", 
                                    (hashed_password, updated_at, email))
            conn.commit()
            if result.rowcount == 0:
                return jsonify({"success": False, "message": "用户不存在"}), 404

        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        logger.info(f"密码重置成功: Email={email}, IP={client_ip}")
        return jsonify({"success": True, "message": "密码已重置成功", "timestamp": datetime.now(timezone.utc).isoformat()})

    except Exception as e:
        logger.error(f"重置密码异常: {e}")
        return jsonify({"success": False, "message": "服务器错误"}), 500