# /utils/validators.py
import re
from markupsafe import escape
from app.utils.config import config


def validate_email(email):
    if not email or not re.match(config["EMAIL_REGEX"], email):
        raise ValueError("无效邮箱")
    return email.strip().lower()

def validate_username(username):
    if not username:
        raise ValueError("用户名不能为空")
    if len(username) < config["USERNAME_MIN_LENGTH"]:
        raise ValueError(f"用户名至少{config['USERNAME_MIN_LENGTH']}个字符")
    if len(username) > config["USERNAME_MAX_LENGTH"]:
        raise ValueError(f"用户名不能超过{config['USERNAME_MAX_LENGTH']}个字符")
    if not re.match(f"^[{config['USERNAME_ALLOWED_CHARS']}]+$", username):
        raise ValueError("用户名格式不符合要求")
    return escape(username.strip())

def validate_password(password):
    if not password:
        raise ValueError("密码不能为空")
    if len(password) < config["PASSWORD_MIN_LENGTH"]:
        raise ValueError(f"密码至少{config['PASSWORD_MIN_LENGTH']}位")
    if len(password) > config["PASSWORD_MAX_LENGTH"]:
        raise ValueError(f"密码不能超过{config['PASSWORD_MAX_LENGTH']}位")
    if not re.search(config["PASSWORD_PATTERN"], password):
        raise ValueError("密码必须包含大小写字母、数字和特殊字符")
    return password

def validate_gender(gender):
    return gender.lower() if gender else ''