# /services/rate_limit_service.py
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from app.utils.config import config

limiter = Limiter(key_func=get_remote_address, default_limits=config["DEFAULT_LIMITS"])