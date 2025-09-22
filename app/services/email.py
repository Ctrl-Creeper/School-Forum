# services/email_service.py
import smtplib, ssl, random, hashlib
from email.mime.text import MIMEText
from datetime import datetime, timedelta, timezone
from app.utils.config import config
from app.utils.logger import logger
from app.services.verification import log_email_send, store_verification_code

def send_verification_email(to_email, purpose='verification'):
    from app.services.verification import can_send_verification
    if not can_send_verification(to_email):
        logger.warning(f"验证码发送频率过高: {to_email}")
        return False

    # 生成验证码
    code = ''.join(random.choices(config["VERIFICATION_CODE_CHARS"], k=config["VERIFICATION_CODE_LENGTH"]))
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=config["VERIFICATION_CODE_EXPIRE_MINUTES"])
    
    # 哈希存储
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    store_verification_code(to_email, code_hash, expires_at)

    # 邮件发送
    subject = f"[YourApp] 验证码"
    body = f"您的验证码是 {code}，{config['VERIFICATION_CODE_EXPIRE_MINUTES']} 分钟内有效。"

    msg = MIMEText(body, 'plain', 'utf-8')
    msg["Subject"] = subject
    msg["From"] = config["EMAIL_ADDRESS"]
    msg["To"] = to_email

    context = ssl.create_default_context()
    try:
        if config["EMAIL_PROTOCOL"].lower() == "ssl":
            with smtplib.SMTP_SSL(config["SMTP_SERVER"], config["SMTP_PORT"], context=context, timeout=config["SMTP_TIMEOUT"]) as server:
                server.login(config["EMAIL_ADDRESS"], config["EMAIL_PASSWORD"])
                server.sendmail(config["EMAIL_ADDRESS"], to_email, msg.as_string())
        else:
            with smtplib.SMTP(config["SMTP_SERVER"], config["SMTP_PORT"], timeout=config["SMTP_TIMEOUT"]) as server:
                server.starttls(context=context)
                server.login(config["EMAIL_ADDRESS"], config["EMAIL_PASSWORD"])
                server.sendmail(config["EMAIL_ADDRESS"], to_email, msg.as_string())
        log_email_send(to_email, purpose)
        logger.info(f"验证码发送成功 [{purpose}]: {to_email}")
        return True
    except Exception as e:
        logger.error(f"邮件发送失败 [{purpose}]: {e}")
        return False