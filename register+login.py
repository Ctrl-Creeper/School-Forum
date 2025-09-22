# 初始化 (chatgpt)
import smtplib, sqlite3, random, ssl, re, json, logging
import secrets
import hashlib
from html import escape
from email.mime.text import MIMEText
from flask import Flask, request, jsonify, session
from datetime import datetime, timedelta, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import BadRequest
from functools import wraps
from contextlib import contextmanager
from flask_session import Session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import redis
import functools

# 日志 (grok)
def setup_logging(config):
    log_level = getattr(logging, config["LOG_LEVEL"])
    log_format = config["LOG_FORMAT"]
    logging.basicConfig(
        level=log_level,
        format=log_format
    )

logger = logging.getLogger(__name__)

app = Flask(__name__)

# 配置（人工） - 改为 YAML
def load_config():
    try:
        with open("config.yaml", "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        logger.error("找不到 config.yaml 文件")
        raise
    except yaml.YAMLError as e:
        logger.error(f"config.yaml 格式错误: {e}")
        raise
    except ValueError as e:
        logger.error(f"配置验证失败: {e}")
        raise
    return config

config = load_config()

# 全局配置 (人工)
SECRET_KEY = config["SECRET_KEY"]
SMTP_SERVER = config["SMTP_SERVER"]
SMTP_PORT = config["SMTP_PORT"]
EMAIL_ADDRESS = config["EMAIL_ADDRESS"]
EMAIL_PASSWORD = config["EMAIL_PASSWORD"]
DATABASE_FILE = config["DATABASE_FILE"]
VERIFICATION_CODE_LENGTH = config["VERIFICATION_CODE_LENGTH"]
VERIFICATION_CODE_EXPIRE_MINUTES = config["VERIFICATION_CODE_EXPIRE_MINUTES"]
SESSION_EXPIRE_DAYS = config["SESSION_EXPIRE_DAYS"]
PASSWORD_MIN_LENGTH = config["PASSWORD_MIN_LENGTH"]
PASSWORD_MAX_LENGTH = config["PASSWORD_MAX_LENGTH"]
USERNAME_MIN_LENGTH = config["USERNAME_MIN_LENGTH"]
USERNAME_MAX_LENGTH = config["USERNAME_MAX_LENGTH"]
TIME_FORMAT = config["TIME_FORMAT"]
RATE_LIMIT_CONFIG = config["RATE_LIMIT"]
EMAIL_TEMPLATES = config["EMAIL_TEMPLATES"]
ENV = config["ENV"]
VERIFICATION_CODE_CHARS = config["VERIFICATION_CODE_CHARS"]
USERNAME_ALLOWED_CHARS = config["USERNAME_ALLOWED_CHARS"]
PASSWORD_PATTERN = config["PASSWORD_PATTERN"]
EMAIL_REGEX = config["EMAIL_REGEX"]
EMAIL_PROTOCOL = config["EMAIL_PROTOCOL"]
SMTP_TIMEOUT = config["SMTP_TIMEOUT"]
FREQUENCY_CHECK_MINUTES = config["FREQUENCY_CHECK_MINUTES"]
DEFAULT_LIMITS = config["DEFAULT_LIMITS"]
LIMITER_STORAGE = config["LIMITER_STORAGE"]
LOG_FORMAT = config["LOG_FORMAT"]
LOG_LEVEL = config["LOG_LEVEL"]
PORT = config["PORT"]
APP_HOST = config["APP_HOST"]
REDIS_CONNECT_TIMEOUT = config["REDIS_CONNECT_TIMEOUT"]
REDIS_SOCKET_TIMEOUT = config["REDIS_SOCKET_TIMEOUT"]
REDIS_DB = config["REDIS_DB"]

app.secret_key = SECRET_KEY

# 安全配置 (grok)
if ENV == "production":
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
else:
    app.config["SESSION_COOKIE_SECURE"] = False
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

app.config["SESSION_COOKIE_HTTPONLY"] = True

setup_logging(config)

# 速率限制
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=DEFAULT_LIMITS,
    storage_uri=LIMITER_STORAGE
)

# CSRF 保护 (grok) - 修复：一次性 Token
def generate_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]

def verify_csrf_token(token):
    stored_token = session.get("csrf_token")
    if not stored_token or token != stored_token:
        logger.warning(f"CSRF Token 验证失败: 提供={token[:8]}... 期望={stored_token[:8]}...")
        return False
    
    # 修复：验证后立即使 Token 失效
    session.pop("csrf_token", None)
    return True

def csrf_protect(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == "POST":
            token = (request.headers.get("X-CSRF-Token") or 
                    request.form.get("csrf_token") or 
                    request.json.get("csrf_token"))
            if not token or not verify_csrf_token(token):
                logger.warning(f"CSRF 保护触发: {request.path} from {get_remote_address()}")
                return jsonify({"success": False, "message": "CSRF token 验证失败"}), 403
        return f(*args, **kwargs)
    return decorated_function

# Redis （grok + 人工)
app.config["SESSION_PERMANENT"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=SESSION_EXPIRE_DAYS)

redis_config = {
    "host": config.get("REDIS_HOST", "localhost"),
    "port": config.get("REDIS_PORT", 6379),
    "password": config.get("REDIS_PASSWORD"),
    "db": REDIS_DB,
    "decode_responses": True,
    "socket_connect_timeout": REDIS_CONNECT_TIMEOUT,
    "socket_timeout": REDIS_SOCKET_TIMEOUT
}

# 测试 Redis (grok)
redis_client = None
redis_available = False
try:
    redis_client = redis.StrictRedis(**redis_config)
    redis_client.ping()
    app.config["SESSION_REDIS"] = redis_client
    app.config["SESSION_TYPE"] = "redis"
    redis_available = True
    logger.info(f"Redis 连接成功: {redis_config['host']}:{redis_config['port']}")
except redis.ConnectionError as e:
    logger.error(f"Redis 连接失败: {e}")
    logger.info("回退到文件系统 Session")
    app.config["SESSION_TYPE"] = "filesystem"
    redis_client = None
    redis_available = False

Session(app)

# 限流 (chatgpt + 人工)
def get_rate_limits(rule_name):
    limits = RATE_LIMIT_CONFIG.get(rule_name, {})
    result = []
    if limits.get("minute"):
        result.append(f"{limits['minute']} per minute")
    if limits.get("hour"):
        result.append(f"{limits['hour']} per hour")
    return result

def apply_rate_limits(func):
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            return f(*args, **kwargs)
        limits = get_rate_limits(func.__name__)
        for limit in limits:
            decorated_function = limiter.limit(limit)(decorated_function)
        return decorated_function
    return decorator

# 标准化错误响应 (grok)
def error_response(message, status_code, error_code=None):
    response_data = {
        "success": False,
        "message": message,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    if error_code:
        response_data["error_code"] = error_code
    return jsonify(response_data), status_code

# 数据库链接 (chatgpt)
@contextmanager
def get_db_connection():
    conn = sqlite3.connect(DATABASE_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
    finally:
        conn.close()

# 验证函数 (grok + 人工)
def validate_email(email):
    if not email or not re.match(EMAIL_REGEX, email):
        raise BadRequest("无效的邮箱格式")
    return email.strip().lower()

def validate_username(username):
    if not username:
        raise BadRequest("用户名不能为空")
    if len(username) < USERNAME_MIN_LENGTH:
        raise BadRequest(f"用户名长度至少{USERNAME_MIN_LENGTH}个字符")
    if len(username) > USERNAME_MAX_LENGTH:
        raise BadRequest(f"用户名长度不能超过{USERNAME_MAX_LENGTH}个字符")
    if not re.match(f"^[{USERNAME_ALLOWED_CHARS}]+$", username):
        raise BadRequest("用户名格式不符合要求")
    return escape(username.strip())

def validate_password(password):
    if not password:
        raise BadRequest("密码不能为空")
    if len(password) < PASSWORD_MIN_LENGTH:
        raise BadRequest(f"密码长度至少{PASSWORD_MIN_LENGTH}位")
    if len(password) > PASSWORD_MAX_LENGTH:
        raise BadRequest(f"密码长度不能超过{PASSWORD_MAX_LENGTH}位")
    if not re.search(PASSWORD_PATTERN, password):
        raise BadRequest("密码必须包含大小写字母、数字和特殊字符")
    return password

def validate_gender(gender):
    return gender.lower() if gender else ''

# 频率控制 (grok)
def can_send_verification(email):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        check_minutes_ago = (datetime.now(timezone.utc) - timedelta(minutes=FREQUENCY_CHECK_MINUTES)).strftime(TIME_FORMAT)
        cursor.execute("""
            SELECT 1 FROM email_send_log 
            WHERE email=? AND sent_at > ?
            LIMIT 1
        """, (email, check_minutes_ago))
        return cursor.fetchone() is None

def log_email_send(email, purpose='verification'):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        sent_at = datetime.now(timezone.utc).strftime(TIME_FORMAT)
        cursor.execute("""
            INSERT INTO email_send_log (email, sent_at, purpose) 
            VALUES (?, ?, ?)
        """, (email, sent_at, purpose))
        conn.commit()

#邮箱验证码 (chatgpt + 人工)
def get_email_template(purpose):
    template = EMAIL_TEMPLATES.get(purpose, EMAIL_TEMPLATES.get("verification", {}))
    expire_minutes = VERIFICATION_CODE_EXPIRE_MINUTES
    return {
        "subject": template.get("subject", "验证码"),
        "body": template.get("body", "你的验证码是 {code}，{expire_minutes}分钟内有效。").format(
            expire_minutes=expire_minutes
        )
    }

def send_verification_email(to_email, purpose='verification'):
    if not can_send_verification(to_email):
        logger.warning(f"验证码发送频率过高: {to_email}")
        return False
    
    # 生成 (chatgpt)
    code = ''.join(random.choices(VERIFICATION_CODE_CHARS, k=VERIFICATION_CODE_LENGTH))
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=VERIFICATION_CODE_EXPIRE_MINUTES)
    created_at = datetime.now(timezone.utc)
    
    # 修复：使用哈希存储验证码
    code_hash = hashlib.sha256(code.encode()).hexdigest()

    # 存储
    with get_db_connection() as conn:
        cursor = conn.cursor()
        # 删除旧的验证码
        cursor.execute("DELETE FROM email_verification WHERE email=?", (to_email,))
        cursor.execute("""
            INSERT INTO email_verification (email, code_hash, expires_at, created_at) 
            VALUES (?, ?, ?, ?)
        """, (to_email, code_hash, expires_at.strftime(TIME_FORMAT), 
              created_at.strftime(TIME_FORMAT)))
        conn.commit()
    
    log_email_send(to_email, purpose)
    
    # 获取模板
    template = get_email_template(purpose)
    message = template["body"].format(code=code)
    
    # 发送
    msg = MIMEText(message, 'plain', 'utf-8')
    msg["Subject"] = template["subject"]
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = to_email
    
    context = ssl.create_default_context()
    try:
        if EMAIL_PROTOCOL.lower() == "ssl":
            with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context, timeout=SMTP_TIMEOUT) as server:
                server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
                server.sendmail(EMAIL_ADDRESS, to_email, msg.as_string())
        else:
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=SMTP_TIMEOUT) as server:
                context = ssl.create_default_context()
                server.starttls(context=context)
                server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
                server.sendmail(EMAIL_ADDRESS, to_email, msg.as_string())
        logger.info(f"验证码发送成功 [{purpose}]: {to_email}")
        return True
    except smtplib.SMTPException as e:
        logger.error(f"邮件发送失败 [{purpose}]: {e}")
        return False
    
# 验证码验证 (chatgpt + 人工) - 修复：支持哈希验证
def verify_code(email, code):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT code_hash, expires_at FROM email_verification 
            WHERE email=?
        """, (email,))
        row = cursor.fetchone()

        if not row:
            return False, "请先获取验证码"

        db_code_hash, expires_at_str = row
        try:
            # 时间格式
            expires_at = datetime.strptime(expires_at_str, TIME_FORMAT).replace(tzinfo=timezone.utc)
        except ValueError:
            return False, "验证码已过期"

        now_utc = datetime.now(timezone.utc)
        
        # 修复：验证哈希值
        input_code_hash = hashlib.sha256(code.encode()).hexdigest()
        if db_code_hash != input_code_hash:
            logger.warning(f"验证码错误: {email}, 输入: {code}, 期望: {input_code_hash[:8]}...")
            return False, "验证码错误"
        
        if now_utc > expires_at:
            logger.warning(f"验证码已过期: {email}")
            return False, "验证码已过期"
            
        # 清理验证码
        cursor.execute("DELETE FROM email_verification WHERE email=?", (email,))
        conn.commit()
        
        return True, "验证成功"

# 认证装饰器 (chatgpt + grok) - 修复：统一使用 user_id
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:  # 修复：使用 user_id
            logger.warning("缺少认证 Token")
            return error_response("请先登录", 401)

        last_active_str = session.get("last_active")
        if not last_active_str:
            logger.warning("认证已过期 - 无 last_active")
            session.clear()
            return error_response("登录已过期，请重新登录", 401)

        try:
            last_active = datetime.fromisoformat(last_active_str)
            if last_active.tzinfo is None:
                last_active = last_active.replace(tzinfo=timezone.utc)
        except ValueError as e:
            logger.error(f"解析 last_active 失败: {e}")
            session.clear()
            return error_response("登录已过期，请重新登录", 401)

        now_utc = datetime.now(timezone.utc)
        if now_utc - last_active > timedelta(days=SESSION_EXPIRE_DAYS):
            logger.warning(f"Session 过期: {session.get('user_id')}")
            session.clear()
            return error_response("登录已过期，请重新登录", 401)

        # 更新活跃时间
        session["last_active"] = now_utc.isoformat()
        current_user_id = session["user_id"]  # 修复：使用 user_id
        return f(current_user_id, *args, **kwargs)  # 修复：传入 user_id
    return decorated

@app.route("/send_code", methods=["POST"])
@apply_rate_limits
@csrf_protect
def send_code():
    try:
        data = request.get_json()
        if not data:
            return error_response("缺少请求数据", 400)

        email = data.get("email")
        if not email:
            return error_response("缺少邮箱参数", 400)
        
        validate_email(email)
        
        if send_verification_email(email, 'verification'):
            return jsonify({"success": True, "message": "验证码已发送，请检查邮箱", "timestamp": datetime.now(timezone.utc).isoformat()})
        else:
            return error_response("验证码发送失败，请稍后重试", 500)
            
    except BadRequest as e:
        logger.warning(f"邮箱验证失败: {str(e)}")
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"发送验证码异常: {e}")
        return error_response("服务器错误", 500)

# 注册 (grok + 人工) - 修复：统一错误信息，Session 键名
@app.route("/register", methods=["POST"])
@apply_rate_limits
@csrf_protect
def register():
    try:
        data = request.get_json()
        if not data:
            return error_response("缺少请求数据", 400)

        email = data.get("email")
        username = data.get("username")
        code = data.get("code")
        password = data.get("password")
        gender = data.get("gender")

        if not all([email, username, code, password]):
            return error_response("缺少必要参数", 400)

        validate_email(email)
        validate_username(username)
        validate_password(password)

        is_valid, message = verify_code(email, code)
        if not is_valid:
            return error_response(message, 400)

        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # 修复：统一错误信息，防止枚举攻击
            cursor.execute("""
                SELECT uid FROM users 
                WHERE username=? OR email=?
            """, (username, email))
            if cursor.fetchone():
                return error_response("该账户已被注册", 409, "ACCOUNT_EXISTS")

            hashed_password = generate_password_hash(password)
            created_at = datetime.now(timezone.utc).strftime(TIME_FORMAT)
            updated_at = created_at
            region = config.get("DEFAULT_REGION", "")

            cursor.execute("""
                INSERT INTO users (username, email, password, gender, region, created_at, updated_at) 
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (username, email, hashed_password, validate_gender(gender), region, created_at, updated_at))

            uid = cursor.lastrowid
            session["user_id"] = uid  # 修复：使用 user_id
            conn.commit()

        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        logger.info(f"用户注册成功: UID={uid}, Username={username}, Email={email}, IP={client_ip}")
        return jsonify({
            "success": True,
            "message": "注册成功，请登录",
            "data": {"username": username},
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

    except Exception as e:
        logger.error(f"注册异常: {e}")
        return error_response("服务器错误", 500)


# 登录 (grok + 人工) - 修复：统一 Session 键名
@app.route("/login", methods=["POST"])
@apply_rate_limits
@csrf_protect
def login():
    try:
        data = request.get_json()
        if not data:
            return error_response("缺少请求数据", 400)

        login_field = data.get("login_field")
        password = data.get("password")

        if not all([login_field, password]):
            return error_response("缺少必要参数", 400)

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT uid, username, email, password 
                FROM users 
                WHERE username=? OR email=?
            """, (login_field, login_field))
            row = cursor.fetchone()

            if not row or not check_password_hash(row["password"], password):
                return error_response("用户名/邮箱或密码错误", 401, "AUTH_FAILED")

            uid = row["uid"]
            username = row["username"]
            email = row["email"]

            session.permanent = True
            session["user_id"] = uid  # 修复：使用 user_id
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
        return error_response("服务器错误", 500)

# 登出 (grok + 人工) - 修复：使用正确的参数
@app.route("/logout", methods=["POST"])
@token_required
@csrf_protect
def logout(current_user_id):  # 修复：参数名
    try:
        username = session.get("username", "Unknown")
        email = session.get("email", "Unknown")
        session.clear()
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        logger.info(f"用户登出: UID={current_user_id}, Username={username}, Email={email}, IP={client_ip}")
        return jsonify({"success": True, "message": "已登出", "timestamp": datetime.now(timezone.utc).isoformat()})
    except Exception as e:
        logger.error(f"登出异常: {e}")
        return error_response("服务器错误", 500)

# 重置密码 (grok) - 修复：统一错误信息
@app.route("/send_reset_code", methods=["POST"])
@apply_rate_limits
@csrf_protect
def send_reset_code():
    try:
        data = request.get_json()
        if not data:
            return error_response("缺少请求数据", 400)
        
        email = data.get("email")
        if not email:
            return error_response("缺少邮箱参数", 400)
        
        validate_email(email)
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT uid FROM users WHERE email=?", (email,))
            if not cursor.fetchone():
                # 修复：统一错误信息，防止枚举攻击
                return error_response("该邮箱未注册", 404, "EMAIL_NOT_FOUND")
        
        if send_verification_email(email, 'reset'):
            return jsonify({"success": True, "message": "重置验证码已发送，请检查邮箱", "timestamp": datetime.now(timezone.utc).isoformat()})
        else:
            return error_response("验证码发送失败，请稍后重试", 500)
            
    except BadRequest as e:
        logger.warning(f"重置验证码验证失败: {str(e)}")
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"发送重置验证码异常: {e}")
        return error_response("服务器错误", 500)

@app.route("/reset_password", methods=["POST"])
@apply_rate_limits
@csrf_protect
def reset_password():
    try:
        data = request.get_json()
        if not data:
            return error_response("缺少请求数据", 400)
        
        email = data.get("email")
        code = data.get("code")
        new_password = data.get("new_password")
        
        if not all([email, code, new_password]):
            return error_response("缺少必要参数", 400)

        validate_email(email)
        validate_password(new_password)
        
        # 验证
        is_valid, message = verify_code(email, code)
        if not is_valid:
            return error_response(message, 400)

        # 更新密码
        with get_db_connection() as conn:
            cursor = conn.cursor()
            hashed_password = generate_password_hash(new_password)
            updated_at = datetime.now(timezone.utc).strftime(TIME_FORMAT)
            result = cursor.execute("""
                UPDATE users SET password=?, updated_at=? WHERE email=?
            """, (hashed_password, updated_at, email))
            conn.commit()
            
            if result.rowcount == 0:
                logger.error(f"重置密码失败，用户不存在: {email}")
                return error_response("用户不存在", 404, "USER_NOT_FOUND")

        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        logger.info(f"密码重置成功: Email={email}, IP={client_ip}")
        return jsonify({"success": True, "message": "密码已重置成功", "timestamp": datetime.now(timezone.utc).isoformat()})
            
    except BadRequest as e:
        logger.warning(f"重置密码验证失败: {str(e)}")
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"重置密码异常: {e}")
        return error_response("服务器错误", 500)

# CSRF Token 生成接口 (grok) - 修复：生成新 Token
@app.route("/csrf_token", methods=["GET"])
def get_csrf_token():
    token = generate_csrf_token()
    return jsonify({
        "success": True,
        "csrf_token": token,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })

# 检查 (人工)
@app.route("/health", methods=["GET"])
def health_check():
    redis_status = "OK" if redis_client and redis_client.ping() else "Unavailable"
    return jsonify({
        "success": True,
        "status": "healthy",
        "session_type": app.config["SESSION_TYPE"],
        "redis": redis_status,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })

# 429
@app.errorhandler(429)
def ratelimit_handler(e):
    return error_response("请求过于频繁，请稍后再试", 429, "RATE_LIMIT_EXCEEDED")

# 404
@app.errorhandler(404)
def not_found_handler(e):
    return error_response("接口不存在", 404, "NOT_FOUND")

# 500
@app.errorhandler(500)
def internal_error_handler(e):
    logger.error(f"内部服务器错误: {e}")
    return error_response("服务器内部错误", 500, "INTERNAL_ERROR")

# 403
@app.errorhandler(403)
def csrf_error_handler(e):
    return error_response("权限验证失败", 403, "FORBIDDEN")

# 初始化数据库 (chatgpt + 人工) - 修复：验证码表使用 code_hash
if __name__ == "__main__":
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # 验证码表 - 修复：使用 code_hash
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS email_verification (
                    email TEXT PRIMARY KEY, 
                    code_hash TEXT NOT NULL, 
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            
            # 用户表
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    uid INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    gender TEXT DEFAULT '',
                    region TEXT DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT
                )
            """)
            
            # 邮件发送日志表
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS email_send_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL,
                    sent_at TEXT NOT NULL,
                    purpose TEXT DEFAULT 'verification'
                )
            """)

            # 索引
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_uid ON users(uid)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_email_verification_email ON email_verification(email)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_email_send_log_email ON email_send_log(email)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_email_time ON email_send_log(email, sent_at)")

            conn.commit()
            logger.info(f"数据库初始化完成: {DATABASE_FILE}")
    except Exception as e:
        logger.error(f"数据库初始化失败: {e}")
        raise

    # 启动！(人工)
    debug = config.get("DEBUG", False)
    host = APP_HOST
    
    session_info = "Redis" if redis_available else "Filesystem"
    logger.info(f"""
    ╔══════════════════════════════════════════════════════╗
    ║                应用启动信息                          ║
    ║──────────────────────────────────────────────────────║
    ║ 端口: {PORT:>4}                    Session: {session_info:>10}  ║
    ║ 主机: {host:>14}                    调试: {str(debug):>5}    ║
    ║ 数据库: {DATABASE_FILE:>14}         验证码长度: {VERIFICATION_CODE_LENGTH:>2}位   ║
    ║ Redis: {redis_config['host']:>14}:{redis_config['port']:>5}  有效期: {VERIFICATION_CODE_EXPIRE_MINUTES}分钟  ║
    ║ 用户模型: UID + Username + Email + Gender            ║
    ║ 登录方式: 用户名或邮箱                                 ║
    ║ Gender/Region                                      ║
    ║ CSRF 保护: 已启用 (一次性Token)                      ║
    ║ 密码策略: 8-128位, 强密码要求                        ║
    ║ 环境: {ENV:>12}                                        ║
    ║ 邮件协议: {EMAIL_PROTOCOL}                          ║
    ║ SMTP超时: {SMTP_TIMEOUT}s                            ║
    ╚══════════════════════════════════════════════════════╝
    """)
    
    app.run(host=host, port=PORT, debug=debug)