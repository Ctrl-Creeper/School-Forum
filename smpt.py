import smtplib, sqlite3, random, ssl, re, jwt, json
from email.mime.text import MIMEText
from flask import Flask, request, jsonify
from datetime import datetime, timedelta, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import BadRequest
from functools import wraps
from contextlib import contextmanager

app = Flask(__name__)

# config
with open("config.json", "r") as config_file:
    config = json.load(config_file)

SMTP_SERVER = config["SMTP_SERVER"]
SMTP_PORT = config["SMTP_PORT"]
EMAIL_ADDRESS = config["EMAIL_ADDRESS"]
EMAIL_PASSWORD = config["EMAIL_PASSWORD"]

    

# JWT
SECRET_KEY = config["SECRET_KEY"]
ACCESS_TOKEN_EXP = timedelta(hours=2)   # 短token
REFRESH_TOKEN_EXP = timedelta(days=7)   # 长token
REFRESH_TOKEN_SLIDING_EXP = timedelta(days=14)  #滑动过期

@contextmanager
def get_db_connection():
    conn = sqlite3.connect("data.db")
    try:
        yield conn
    finally:
        conn.close()

def validate_email(email):
    if not email or not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        raise BadRequest("无效的邮箱格式")
    return email

# 发送验证码
def send_verification_email(to_email):
    code = ''.join(random.choices('0123456789', k=6))
    expires_at = datetime.utcnow() + timedelta(minutes=5)

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM email_verification WHERE email=?", (to_email,))
        cursor.execute("INSERT INTO email_verification (email, code, expires_at) VALUES (?, ?, ?)",
                       (to_email, code, expires_at.isoformat()))
        conn.commit()
    
    msg = MIMEText(f"你的验证码是 {code}，5分钟内有效。")
    msg["Subject"] = "验证码"
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = to_email
    
    context = ssl.create_default_context()
    
    try:
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.sendmail(EMAIL_ADDRESS, to_email, msg.as_string())
        return True
    except smtplib.SMTPException as e:
        print(f"SMTPS 发送失败: {e}")
        return False

# 生成JWT
def generate_tokens(email):
    access_payload = {"email": email, "exp": datetime.utcnow() + ACCESS_TOKEN_EXP}
    refresh_payload = {"email": email, "exp": datetime.utcnow() + REFRESH_TOKEN_EXP}

    access_token = jwt.encode(access_payload, SECRET_KEY, algorithm="HS256")
    refresh_token = jwt.encode(refresh_payload, SECRET_KEY, algorithm="HS256")

    # 存储refresh_token & last_used
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO refresh_tokens (refresh_token, last_used, email) VALUES (?, ?, ?)",
                       (refresh_token, datetime.utcnow().isoformat(), email))
        conn.commit()

    return access_token, refresh_token

# 验证token
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            auth_header = request.headers["Authorization"]
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]

        if not token:
            return jsonify({"success": False, "message": "缺少认证 Token"}), 401

        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            current_user = data["email"]
        except jwt.ExpiredSignatureError:
            return jsonify({"success": False, "message": "登录状态已过期"}), 401
        except Exception:
            return jsonify({"success": False, "message": "无效的 Token"}), 401

        return f(current_user, *args, **kwargs)
    return decorated

@app.route("/send_code", methods=["POST"])
def send_code():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "message": "缺少请求数据"}), 400
        
        email = data.get("email")
        validate_email(email)
        
        if send_verification_email(email):
            return jsonify({"success": True, "message": "验证码已发送"})
        else:
            return jsonify({"success": False, "message": "验证码发送失败"}), 500
    except BadRequest as e:
        return jsonify({"success": False, "message": str(e)}), 400
    except Exception as e:
        return jsonify({"success": False, "message": "服务器错误"}), 500

# 注册
@app.route("/register", methods=["POST"])
def register():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "message": "缺少请求数据"}), 400
        
        email = data.get("email")
        code = data.get("code")
        password = data.get("password")
        
        validate_email(email)
        
        if not all([email, code, password]):
            return jsonify({"success": False, "message": "缺少必要参数"}), 400

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT code, expires_at FROM email_verification WHERE email=?", (email,))
            row = cursor.fetchone()

            if not row:
                return jsonify({"success": False, "message": "请先获取验证码"}), 400

            db_code, expires_at_str = row
            expires_at = datetime.fromisoformat(expires_at_str)
            
            if db_code != code or datetime.now(timezone.utc) > expires_at:
                return jsonify({"success": False, "message": "验证码错误或已过期"}), 400

            hashed_password = generate_password_hash(password)
            try:
                cursor.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, hashed_password))
                conn.commit()
                return jsonify({"success": True, "message": "注册成功"})
            except sqlite3.IntegrityError:
                return jsonify({"success": False, "message": "用户已存在"}), 400
                
    except BadRequest as e:
        return jsonify({"success": False, "message": str(e)}), 400
    except Exception as e:
        return jsonify({"success": False, "message": "服务器错误"}), 500

# 登录
@app.route("/login", methods=["POST"])
def login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "message": "缺少请求数据"}), 400
        
        email = data.get("email")
        password = data.get("password")
        
        validate_email(email)
        
        if not all([email, password]):
            return jsonify({"success": False, "message": "缺少必要参数"}), 400

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT password FROM users WHERE email=?", (email,))
            row = cursor.fetchone()

            if row and check_password_hash(row[0], password):
                access_token, refresh_token = generate_tokens(email)
                return jsonify({
                    "success": True,
                    "message": "登录成功",
                    "access_token": access_token,
                    "refresh_token": refresh_token
                })
            else:
                return jsonify({"success": False, "message": "邮箱或密码错误"}), 400
                
    except BadRequest as e:
        return jsonify({"success": False, "message": str(e)}), 400
    except Exception as e:
        return jsonify({"success": False, "message": "服务器错误"}), 500

# 刷新Token
@app.route("/refresh", methods=["POST"])
def refresh():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "message": "缺少请求数据"}), 400
        
        refresh_token = data.get("refresh_token")
        if not refresh_token:
            return jsonify({"success": False, "message": "缺少刷新 Token"}), 400

        try:
            data = jwt.decode(refresh_token, SECRET_KEY, algorithms=["HS256"])
            email = data["email"]
        except jwt.ExpiredSignatureError:
            return jsonify({"success": False, "message": "刷新 Token 已过期"}), 401
        except Exception:
            return jsonify({"success": False, "message": "无效的刷新 Token"}), 401

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT last_used FROM refresh_tokens 
                WHERE refresh_token=? AND email=?
            """, (refresh_token, email))
            row = cursor.fetchone()

            if not row:
                return jsonify({"success": False, "message": "刷新 Token 不存在或已失效"}), 401

            last_used_str = row[0]
            last_used = datetime.fromisoformat(last_used_str)
            now = datetime.utcnow()
            
            if now - last_used > REFRESH_TOKEN_SLIDING_EXP:
                # 删除该refresh_token
                cursor.execute("DELETE FROM refresh_tokens WHERE refresh_token=?", (refresh_token,))
                conn.commit()
                return jsonify({"success": False, "message": "刷新 Token 已过期"}), 401

            # 更新last_used
            cursor.execute("UPDATE refresh_tokens SET last_used=? WHERE refresh_token=?", 
                          (now.isoformat(), refresh_token))
            conn.commit()

            # 生成新的access_token, refresh_token不变
            access_token_payload = {"email": email, "exp": datetime.utcnow() + ACCESS_TOKEN_EXP}
            access_token = jwt.encode(access_token_payload, SECRET_KEY, algorithm="HS256")

            return jsonify({
                "success": True,
                "access_token": access_token,
                "refresh_token": refresh_token
            })
            
    except Exception as e:
        return jsonify({"success": False, "message": "服务器错误"}), 500

# 忘记密码
@app.route("/reset_password", methods=["POST"])
def reset_password():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "message": "缺少请求数据"}), 400
        
        email = data.get("email")
        code = data.get("code")
        new_password = data.get("new_password")
        
        validate_email(email)
        
        if not all([email, code, new_password]):
            return jsonify({"success": False, "message": "缺少必要参数"}), 400

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT code, expires_at FROM email_verification WHERE email=?", (email,))
            row = cursor.fetchone()

            if not row:
                return jsonify({"success": False, "message": "请先获取验证码"}), 400

            db_code, expires_at_str = row
            expires_at = datetime.fromisoformat(expires_at_str)
            
            if db_code != code or datetime.now(timezone.utc) > expires_at:
                return jsonify({"success": False, "message": "验证码错误或已过期"}), 400

            hashed_password = generate_password_hash(new_password)
            result = cursor.execute("UPDATE users SET password=? WHERE email=?", 
                                  (hashed_password, email))
            conn.commit()
            
            if result.rowcount == 0:
                return jsonify({"success": False, "message": "用户不存在"}), 404

            return jsonify({"success": True, "message": "密码已重置"})
            
    except BadRequest as e:
        return jsonify({"success": False, "message": str(e)}), 400
    except Exception as e:
        return jsonify({"success": False, "message": "服务器错误"}), 500

# 个人信息接口（需要登录）
@app.route("/profile", methods=["GET"])
@token_required
def profile(current_user):
    return jsonify({"success": True, "message": f"欢迎 {current_user}"})

if __name__ == "__main__":
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS email_verification (
                            email TEXT, code TEXT, expires_at TEXT)""")
        cursor.execute("""CREATE TABLE IF NOT EXISTS users (
                            email TEXT PRIMARY KEY, password TEXT)""")
        cursor.execute("""CREATE TABLE IF NOT EXISTS refresh_tokens (
                            refresh_token TEXT PRIMARY KEY, 
                            last_used TEXT, 
                            email TEXT)""")
        conn.commit()

    app.run(port=5000, debug=True)