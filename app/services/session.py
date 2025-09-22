# /services/session.py
from flask_session import Session
from datetime import timedelta
from app.utils.config import config

def setup_session(app):
    app.config["SESSION_PERMANENT"] = True
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=config["SESSION_EXPIRE_DAYS"])
    # Redis 配置
    import redis
    redis_config = {
        "host": config.get("REDIS_HOST", "localhost"),
        "port": config.get("REDIS_PORT", 6379),
        "password": config.get("REDIS_PASSWORD"),
        "db": config.get("REDIS_DB", 0),
        "decode_responses": True,
        "socket_connect_timeout": config.get("REDIS_CONNECT_TIMEOUT", 5),
        "socket_timeout": config.get("REDIS_SOCKET_TIMEOUT", 5)
    }
    try:
        redis_client = redis.StrictRedis(**redis_config)
        redis_client.ping()
        app.config["SESSION_TYPE"] = "redis"
        app.config["SESSION_REDIS"] = redis_client
    except redis.ConnectionError:
        app.config["SESSION_TYPE"] = "filesystem"
    Session(app)