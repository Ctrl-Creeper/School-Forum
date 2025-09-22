# /services/verification_service.py
from app.utils.config import config
from datetime import datetime, timezone
from app.utils.config import config
from app.utils.db import get_db_connection

def can_send_verification(email):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        check_minutes_ago = (datetime.now(timezone.utc) - timedelta(minutes=config["FREQUENCY_CHECK_MINUTES"])).strftime(config["TIME_FORMAT"])
        cursor.execute("SELECT 1 FROM email_send_log WHERE email=? AND sent_at>? LIMIT 1", (email, check_minutes_ago))
        return cursor.fetchone() is None

def log_email_send(email, purpose='verification'):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        sent_at = datetime.now(timezone.utc).strftime(config["TIME_FORMAT"])
        cursor.execute("INSERT INTO email_send_log (email, sent_at, purpose) VALUES (?, ?, ?)", (email, sent_at, purpose))
        conn.commit()

def store_verification_code(email, code_hash, expires_at):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM email_verification WHERE email=?", (email,))
        cursor.execute("INSERT INTO email_verification (email, code_hash, expires_at, created_at) VALUES (?, ?, ?, ?)", 
                       (email, code_hash, expires_at.strftime(config["TIME_FORMAT"]), datetime.now(timezone.utc).strftime(config["TIME_FORMAT"])))
        conn.commit()

def verify_code(email, code):
    import hashlib
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT code_hash, expires_at FROM email_verification WHERE email=?", (email,))
        row = cursor.fetchone()
        if not row:
            return False, "请先获取验证码"
        db_code_hash, expires_at_str = row
        expires_at = datetime.strptime(expires_at_str, config["TIME_FORMAT"]).replace(tzinfo=timezone.utc)
        now_utc = datetime.now(timezone.utc)
        input_hash = hashlib.sha256(code.encode()).hexdigest()
        if db_code_hash != input_hash:
            return False, "验证码错误"
        if now_utc > expires_at:
            return False, "验证码已过期"
        cursor.execute("DELETE FROM email_verification WHERE email=?", (email,))
        conn.commit()
        return True, "验证成功"