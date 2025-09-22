# 初始化 (chatgpt)
import smtplib, sqlite3, random, ssl, re, json, logging
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
    log_level = getattr(logging, config.get("LOG_LEVEL", "INFO"))
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

logger = logging.getLogger(__name__)

app = Flask(__name__)

# 配置（人工）
def load_config():
    try:
        with open("config.json", "r", encoding="utf-8") as f:
            config = json.load(f)
        
        default_config = {
            "DATABASE_FILE": "data.db",
            "VERIFICATION_CODE_LENGTH": 6,
            "VERIFICATION_CODE_EXPIRE_MINUTES": 5,
            "SESSION_EXPIRE_DAYS": 7,
            "PASSWORD_MIN_LENGTH": 8,
            "PASSWORD_MAX_LENGTH": 128,
            "REDIS_CONNECT_TIMEOUT": 5,
            "REDIS_SOCKET_TIMEOUT": 5,
            "REDIS_DB": 0,
            "PORT": 5000,
            "DEBUG": True,
            "LOG_LEVEL": "INFO",
            "APP_HOST": "0.0.0.0",
            "RATE_LIMIT": {
                "send_code": {"minute": 5, "hour": 30},
                "register": {"hour": 5},
                "login": {"minute": 10, "hour": 100},
                "send_reset_code": {"minute": 3, "hour": 20},
                "reset_password": {"hour": 5}
            },
            "EMAIL_TEMPLATES": {
                "verification": {
                    "subject": "注册验证码",
                    "body": "你的验证码是 {code}，{expire_minutes}分钟内有效。"
                },
                "reset": {
                    "subject": "密码重置验证码",
                    "body": "你正在重置密码，验证码是 {code}，{expire_minutes}分钟内有效。"
                }
            },
            "TIME_FORMAT": "%Y-%m-%d %H:%M:%S"
        }
        
        for key, value in default_config.items():
            if key not in config:
                config[key] = value
        
        required_configs = [
            "SECRET_KEY", "SMTP_SERVER", "SMTP_PORT", 
            "EMAIL_ADDRESS", "EMAIL_PASSWORD"
        ]
        missing = [key for key in required_configs if key not in config]
        if missing:
            raise ValueError(f"配置文件缺少必需项: {', '.join(missing)}")
        
        return config
        
    except FileNotFoundError:
        logger.error("找不到 config.json 文件")
        raise
    except json.JSONDecodeError:
        logger.error("config.json 格式错误")
        raise
    except ValueError as e:
        logger.error(f"配置验证失败: {e}")
        raise

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
TIME_FORMAT = config["TIME_FORMAT"]
RATE_LIMIT_CONFIG = config["RATE_LIMIT"]
EMAIL_TEMPLATES = config["EMAIL_TEMPLATES"]

app.secret_key = SECRET_KEY

setup_logging(config)

# 速率限制
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Redis （grok + 人工)
app.config["SESSION_TYPE"] = "redis"
app.config["SESSION_PERMANENT"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=SESSION_EXPIRE_DAYS)

redis_config = {
    "host": config.get("REDIS_HOST", "localhost"),
    "port": config.get("REDIS_PORT", 6379),
    "password": config.get("REDIS_PASSWORD"),
    "db": config.get("REDIS_DB", 0),
    "decode_responses": True,
    "socket_connect_timeout": config.get("REDIS_CONNECT_TIMEOUT", 5),
    "socket_timeout": config.get("REDIS_SOCKET_TIMEOUT", 5)
}

# 测试 Redis (grok)
redis_client = None
try:
    redis_client = redis.StrictRedis(**redis_config)
    redis_client.ping()
    app.config["SESSION_REDIS"] = redis_client
    logger.info(f"Redis 连接成功: {redis_config['host']}:{redis_config['port']}")
except redis.ConnectionError as e:
    logger.error(f"Redis 连接失败: {e}")
    logger.info("回退到文件系统 Session")
    app.config["SESSION_TYPE"] = "filesystem"
    redis_client = None

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

#数据库链接 (chatgpt))
@contextmanager
def get_db_connection():
    conn = sqlite3.connect(DATABASE_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
    finally:
        conn.close()

#邮箱格式验证 (grok + 人工)
def validate_email(email):
    if not email or not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email):
        raise BadRequest("无效的邮箱格式")
    return email.strip().lower()

def validate_password(password):
    if not password:
        raise BadRequest("密码不能为空")
    if len(password) < PASSWORD_MIN_LENGTH:
        raise BadRequest(f"密码长度至少{PASSWORD_MIN_LENGTH}位")
    if len(password) > PASSWORD_MAX_LENGTH:
        raise BadRequest(f"密码长度不能超过{PASSWORD_MAX_LENGTH}位")
    if not re.search(r"(?=.*[a-zA-Z])(?=.*\d)", password):
        raise BadRequest("密码必须包含字母和数字")
    return password

# 频率控制 (grok)
def can_send_verification(email):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        one_minute_ago = (datetime.now(timezone.utc) - timedelta(minutes=1)).strftime(TIME_FORMAT)
        cursor.execute("""
            SELECT 1 FROM email_send_log 
            WHERE email=? AND sent_at > ?
            LIMIT 1
        """, (email, one_minute_ago))
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

#邮箱验证码 (chatgpt + 人工))
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
    code = ''.join(random.choices('0123456789', k=VERIFICATION_CODE_LENGTH))
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=VERIFICATION_CODE_EXPIRE_MINUTES)
    created_at = datetime.now(timezone.utc)

    # 存储
    with get_db_connection() as conn:
        cursor = conn.cursor()
        # 删除
        cursor.execute("DELETE FROM email_verification WHERE email=?", (to_email,))
        cursor.execute("""
            INSERT INTO email_verification (email, code, expires_at, created_at) 
            VALUES (?, ?, ?, ?)
        """, (to_email, code, expires_at.strftime(TIME_FORMAT), 
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
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.sendmail(EMAIL_ADDRESS, to_email, msg.as_string())
        logger.info(f"验证码发送成功 [{purpose}]: {to_email}")
        return True
    except smtplib.SMTPException as e:
        logger.error(f"邮件发送失败 [{purpose}]: {e}")
        return False
    
# 验证码验证 (chatgpt + 人工))
def verify_code(email, code):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT code, expires_at FROM email_verification 
            WHERE email=?
        """, (email,))
        row = cursor.fetchone()

        if not row:
            return False, "请先获取验证码"

        db_code, expires_at_str = row
        try:
            # 时间格式
            expires_at = datetime.strptime(expires_at_str, TIME_FORMAT).replace(tzinfo=timezone.utc)
        except ValueError:
            return False, "验证码已过期"

        now_utc = datetime.now(timezone.utc)
        
        if db_code != code:
            logger.warning(f"验证码错误: {email}, 输入: {code}, 正确: {db_code}")
            return False, "验证码错误"
        
        if now_utc > expires_at:
            logger.warning(f"验证码已过期: {email}")
            return False, "验证码已过期"
            
        # 清理验证码
        cursor.execute("DELETE FROM email_verification WHERE email=?", (email,))
        conn.commit()
        
        return True, "验证成功"

# 认证装饰器 (chatgpt + grok)
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            logger.warning("缺少认证 Token")
            return jsonify({"success": False, "message": "请先登录"}), 401
        
        last_active_str = session.get("last_active")
        if not last_active_str:
            logger.warning("认证已过期 - 无 last_active")
            session.clear()
            return jsonify({"success": False, "message": "登录已过期，请重新登录"}), 401
        
        try:
            last_active = datetime.fromisoformat(last_active_str)
        except ValueError as e:
            logger.error(f"解析 last_active 失败: {e}")
            session.clear()
            return jsonify({"success": False, "message": "登录已过期，请重新登录"}), 401
        
        now_utc = datetime.now(timezone.utc)
        if now_utc - last_active > timedelta(days=SESSION_EXPIRE_DAYS):
            logger.warning(f"Session 过期: {session.get('user')}")
            session.clear()
            return jsonify({"success": False, "message": "登录已过期，请重新登录"}), 401
        
        # 更新活跃时间
        session["last_active"] = now_utc.isoformat()
        current_user = session["user"]
        return f(current_user, *args, **kwargs)
    return decorated

@app.route("/send_code", methods=["POST"])
@apply_rate_limits
def send_code():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "message": "缺少请求数据"}), 400
        
        email = data.get("email")
        if not email:
            return jsonify({"success": False, "message": "缺少邮箱参数"}), 400
        
        validate_email(email)
        
        if send_verification_email(email, 'verification'):
            return jsonify({"success": True, "message": "验证码已发送，请检查邮箱"})
        else:
            return jsonify({"success": False, "message": "验证码发送失败，请稍后重试"}), 500
            
    except BadRequest as e:
        logger.warning(f"邮箱验证失败: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 400
    except Exception as e:
        logger.error(f"发送验证码异常: {e}")
        return jsonify({"success": False, "message": "服务器错误"}), 500

# 注册 (grok + 人工)
@app.route("/register", methods=["POST"])
@apply_rate_limits
def register():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "message": "缺少请求数据"}), 400
        
        email = data.get("email")
        code = data.get("code")
        password = data.get("password")
        
        if not all([email, code, password]):
            return jsonify({"success": False, "message": "缺少必要参数"}), 400

        validate_email(email)
        validate_password(password)
        
        # 验证
        is_valid, message = verify_code(email, code)
        if not is_valid:
            return jsonify({"success": False, "message": message}), 400

        # 检查是否存在
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE email=?", (email,))
            if cursor.fetchone():
                return jsonify({"success": False, "message": "邮箱已被注册"}), 409

            # 创建
            hashed_password = generate_password_hash(password)
            created_at = datetime.now(timezone.utc).strftime(TIME_FORMAT)
            cursor.execute("""
                INSERT INTO users (email, password, created_at) 
                VALUES (?, ?, ?)
            """, (email, hashed_password, created_at))
            user_id = cursor.lastrowid
            conn.commit()
            
        logger.info(f"用户注册成功: {email} (ID: {user_id})")
        return jsonify({"success": True, "message": "注册成功，请登录"})
                
    except BadRequest as e:
        logger.warning(f"注册验证失败: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 400
    except sqlite3.IntegrityError as e:
        logger.error(f"注册时数据库完整性错误: {email}, 错误: {e}")
        return jsonify({"success": False, "message": "注册失败，邮箱可能已被使用"}), 409
    except Exception as e:
        logger.error(f"注册异常: {e}")
        return jsonify({"success": False, "message": "服务器错误"}), 500

# 登录
@app.route("/login", methods=["POST"])
@apply_rate_limits
def login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "message": "缺少请求数据"}), 400
        
        email = data.get("email")
        password = data.get("password")
        
        if not all([email, password]):
            return jsonify({"success": False, "message": "缺少必要参数"}), 400

        validate_email(email)
        
        # 验证用户凭据
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, password FROM users WHERE email=?", (email,))
            row = cursor.fetchone()

            if row is None or not check_password_hash(row["password"], password):
                logger.warning(f"登录失败: {email}")
                return jsonify({"success": False, "message": "邮箱或密码错误"}), 401

            user_id = row["id"]
            # 设置 session
            session.permanent = True
            session["user"] = email
            session["user_id"] = user_id
            session["last_active"] = datetime.now(timezone.utc).isoformat()
            
        logger.info(f"用户登录成功: {email} (ID: {user_id})")
        return jsonify({
            "success": True,
            "message": "登录成功"
        })
                
    except BadRequest as e:
        logger.warning(f"登录验证失败: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 400
    except Exception as e:
        logger.error(f"登录异常: {e}")
        return jsonify({"success": False, "message": "服务器错误"}), 500

# 登出
@app.route("/logout", methods=["POST"])
@token_required
def logout(current_user):
    try:
        user_id = session.get("user_id")
        session.clear()
        logger.info(f"用户登出: {current_user} (ID: {user_id})")
        return jsonify({"success": True, "message": "已登出"})
    except Exception as e:
        logger.error(f"登出异常: {e}")
        return jsonify({"success": False, "message": "服务器错误"}), 500

# 重置密码 (grok)
@app.route("/send_reset_code", methods=["POST"])
@apply_rate_limits
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
            cursor.execute("SELECT id FROM users WHERE email=?", (email,))
            if not cursor.fetchone():
                return jsonify({"success": False, "message": "邮箱未注册"}), 404
        
        if send_verification_email(email, 'reset'):
            return jsonify({"success": True, "message": "重置验证码已发送，请检查邮箱"})
        else:
            return jsonify({"success": False, "message": "验证码发送失败，请稍后重试"}), 500
            
    except BadRequest as e:
        logger.warning(f"重置验证码验证失败: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 400
    except Exception as e:
        logger.error(f"发送重置验证码异常: {e}")
        return jsonify({"success": False, "message": "服务器错误"}), 500

@app.route("/reset_password", methods=["POST"])
@apply_rate_limits
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
        
        # 验证
        is_valid, message = verify_code(email, code)
        if not is_valid:
            return jsonify({"success": False, "message": message}), 400

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
                return jsonify({"success": False, "message": "用户不存在"}), 404

        logger.info(f"密码重置成功: {email}")
        return jsonify({"success": True, "message": "密码已重置成功"})
            
    except BadRequest as e:
        logger.warning(f"重置密码验证失败: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 400
    except Exception as e:
        logger.error(f"重置密码异常: {e}")
        return jsonify({"success": False, "message": "服务器错误"}), 500

@app.route("/profile", methods=["GET"])
@token_required
def profile(current_user):
    try:
        user_id = session.get("user_id")
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, email, created_at, updated_at 
                FROM users WHERE email=?
            """, (current_user,))
            user_data = cursor.fetchone()
            
            if not user_data:
                session.clear()
                return jsonify({"success": False, "message": "用户数据异常"}), 500
            
            # 转换时间格式
            created_at = user_data["created_at"]
            updated_at = user_data["updated_at"] or created_at
            
            user_info = {
                "id": user_data["id"],
                "email": user_data["email"],
                "created_at": created_at,
                "last_updated": updated_at
            }
            
        return jsonify({
            "success": True, 
            "data": user_info,
            "message": f"欢迎回来，{current_user}"
        })
    except Exception as e:
        logger.error(f"获取用户信息异常: {e}")
        return jsonify({"success": False, "message": "服务器错误"}), 500

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
    return jsonify({
        "success": False, 
        "message": "请求过于频繁，请稍后再试"
    }), 429

# 404
@app.errorhandler(404)
def not_found_handler(e):

    return jsonify({
        "success": False,
        "message": "接口不存在"
    }), 404

# 500
@app.errorhandler(500)
def internal_error_handler(e):
    logger.error(f"内部服务器错误: {e}")
    return jsonify({
        "success": False,
        "message": "服务器内部错误"
    }), 500

# 初始化数据库 (chatgpt + 人工)
if __name__ == "__main__":
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # 验证码表
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS email_verification (
                    email TEXT PRIMARY KEY, 
                    code TEXT NOT NULL, 
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            
            # 用户表
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL, 
                    password TEXT NOT NULL,
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
                    purpose TEXT DEFAULT 'verification',
                    INDEX idx_email_time (email, sent_at)
                )
            """)
            
            # 添加索引
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_email_verification_email ON email_verification(email)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_email_send_log_email ON email_send_log(email)")
            
            conn.commit()
            logger.info(f"数据库初始化完成: {DATABASE_FILE}")
            
    except Exception as e:
        logger.error(f"数据库初始化失败: {e}")
        raise

    # 启动！(人工))
    port = config.get("PORT", 5000)
    debug = config.get("DEBUG", False)
    host = config.get("APP_HOST", "0.0.0.0")
    
    session_info = f"Redis" if redis_client else "Filesystem"
    logger.info(f"""
    ╔══════════════════════════════════════════════════════╗
    ║                应用启动信息                          ║
    ║──────────────────────────────────────────────────────║
    ║ 端口: {port:>4}                    Session: {session_info:>10}  ║
    ║ 主机: {host:>14}                    调试: {str(debug):>5}    ║
    ║ 数据库: {DATABASE_FILE:>14}         验证码长度: {VERIFICATION_CODE_LENGTH:>2}位   ║
    ║ Redis: {redis_config['host']:>14}:{redis_config['port']:>5}  有效期: {VERIFICATION_CODE_EXPIRE_MINUTES}分钟  ║
    ╚══════════════════════════════════════════════════════╝
    """)
    
    app.run(host=host, port=port, debug=debug)