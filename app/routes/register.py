# app/routes/register.py
from flask import Blueprint, request, jsonify, session
from app.utils.validators import validate_email, validate_username, validate_password, validate_gender
from app.services.verification import verify_code
from app.services.email import send_verification_email
from app.utils.csrf import csrf_protect
from app.utils.config import config
from app.utils.logger import logger
from app.utils.config import get_db_connection
from werkzeug.security import generate_password_hash
from datetime import datetime, timezone

register_bp = Blueprint("register", __name__)

@register_bp.route("/send_code", methods=["POST"])
@csrf_protect
def send_code():
    # 调用 send_verification_email
    pass

@register_bp.route("/register", methods=["POST"])
@csrf_protect
def register():
    # 调用验证函数、verify_code、数据库插入用户
    pass