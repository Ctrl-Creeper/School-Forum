# app/routes/health.py
from flask import Blueprint, jsonify
from datetime import datetime, timezone
from app.utils.config import config

health_bp = Blueprint("health", __name__)

@health_bp.route("/health", methods=["GET"])
def health_check():
    redis_client = None
    try:
        import redis as redis_lib
        redis_config = {
            "host": config.get("REDIS_HOST", "localhost"),
            "port": config.get("REDIS_PORT", 6379),
            "password": config.get("REDIS_PASSWORD"),
            "db": config.get("REDIS_DB", 0)
        }
        redis_client = redis_lib.StrictRedis(**redis_config)
        redis_status = "OK" if redis_client.ping() else "Unavailable"
    except:
        redis_status = "Unavailable"

    return jsonify({
        "success": True,
        "status": "healthy",
        "redis": redis_status,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })