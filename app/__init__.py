# /__init__.py
from flask import Flask
from flask_session import Session
from flask_limiter import Limiter
from app.utils.config import config
from app.utils.logger import setup_logging
from app.services.session import setup_session
from app.services.rate_limit import limiter

app = Flask(__name__)
app.secret_key = config["SECRET_KEY"]

# 日志
setup_logging(config)

# Session
setup_session(app)

# 限流
limiter.init_app(app)

# CSRF Token 生成接口可以放这里或者 routes/csrf.py
from app.routes import register, login, logout, forget, health