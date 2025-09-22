# app/routes/login.py
from flask import Blueprint, request, jsonify, session
from app.utils.csrf import csrf_protect
from app.utils.config import config, get_db_connection
from app.utils.logger import logger
from werkzeug.security import check_password_hash
from datetime import datetime, timezone

login_bp = Blueprint("login", __name__)

@login_bp.route("/login", methods=["POST"])
@csrf_protect
def login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "message": "缺少请求数据"}), 400

        login_field = data.get("login_field")
        password = data.get("password")

        if not all([login_field, password]):
            return jsonify({"success": False, "message": "缺少必要参数"}), 400

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT uid, username, email, password FROM users
                WHERE username=? OR email=?
            """, (login_field, login_field))
            row = cursor.fetchone()

            if not row or not check_password_hash(row["password"], password):
                return jsonify({"success": False, "message": "用户名/邮箱或密码错误"}), 401

            uid = row["uid"]
            username = row["username"]
            email = row["email"]

            session.permanent = True
            session["user_id"] = uid
            session["username"] = username
            session["email"] = email
            session["last_active"] = datetime.now(timezone.utc).isoformat()

        login_type = "邮箱" if "@" in login_field else "用户名"
        return jsonify({
            "success": True,
            "message": "登录成功",
            "data": {
                "username": username,
                "email": email,
                "login_type": login_type
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
    except Exception as e:
        logger.error(f"登录异常: {e}")
        return jsonify({"success": False, "message": "服务器错误"}), 500