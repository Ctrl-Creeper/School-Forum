from flask import Blueprint, request, jsonify, current_app
from app.utils.config import config
from app.utils.db import get_db_connection
from app.utils.logger import logger
from app.auth import token_required
import redis as redis_lib
import os, uuid
from datetime import datetime, timezone
from werkzeug.utils import secure_filename
import asyncio

send_post_bp = Blueprint("send_post", __name__)

# Redis配置
redis_client = redis_lib.StrictRedis(
	host=config.get("REDIS_HOST", "localhost"),
	port=config.get("REDIS_PORT", 6379),
	password=config.get("REDIS_PASSWORD"),
	db=config.get("REDIS_DB", 0),
	decode_responses=True,
	socket_connect_timeout=config.get("REDIS_CONNECT_TIMEOUT", 5),
	socket_timeout=config.get("REDIS_SOCKET_TIMEOUT", 5)
)

# 允许的图片扩展名
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
UPLOAD_FOLDER = os.path.join(os.path.dirname(p=os.path.dirname(__file__)), "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
	return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def get_content_from_request():
	content = request.form.get("content", "").strip()
	if not content:
		raise ValueError("帖子内容不能为空")
	return content

def get_image_from_request():
	if "image" in request.files:
		image = request.files["image"]
		if image and allowed_file(image.filename):
			return image
		else:
			raise ValueError("图片格式不支持")
	return None

async def save_image_async(image):
	ext = image.filename.rsplit(".", 1)[1].lower()
	filename = f"{uuid.uuid4().hex}.{ext}"
	filepath = os.path.join(UPLOAD_FOLDER, secure_filename(filename))
	await asyncio.to_thread(image.save, filepath)
	return f"/uploads/{filename}"

def generate_post_data(user_id, content, image_url):
	post_id = uuid.uuid4().hex
	now = datetime.now(timezone.utc).strftime(config["TIME_FORMAT"])
	return {
		"post_id": post_id,
		"user_id": user_id,
		"content": content,
		"image_url": image_url,
		"created_at": now
	}

def cache_post_to_redis(post_data):
	redis_key = f"post:{post_data['post_id']}"
	redis_client.hmset(redis_key, post_data)
	redis_client.expire(redis_key, 3600 * 24)

async def persist_post_to_db_async(post_data):
	def _persist():
		with get_db_connection() as conn:
			cursor = conn.cursor()
			cursor.execute(
				"""
				INSERT INTO posts (post_id, user_id, content, image_url, created_at)
				VALUES (?, ?, ?, ?, ?)
				""",
				(
					post_data["post_id"],
					post_data["user_id"],
					post_data["content"],
					post_data["image_url"],
					post_data["created_at"]
				)
			)
			conn.commit()
	return await asyncio.to_thread(_persist)

async def post_pipeline(user_id):
	content = get_content_from_request()
	image = None
	image_url = None
	try:
		image = get_image_from_request()
	except ValueError as e:
		return {"error": str(e)}, 400

	if image:
		try:
			image_url = await save_image_async(image)
		except Exception as e:
			return {"error": "图片保存失败"}, 500

	post_data = generate_post_data(user_id, content, image_url)
	try:
		cache_post_to_redis(post_data)
	except Exception as e:
		logger.warning(f"Redis缓存失败: {e}")

	try:
		await persist_post_to_db_async(post_data)
	except Exception as e:
		logger.error(f"数据库写入失败: {e}")
		return {"error": "服务器错误"}, 500

	return {
		"success": True,
		"message": "发帖成功",
		"post_id": post_data["post_id"],
		"image_url": post_data["image_url"],
		"timestamp": post_data["created_at"]
	}, 200

@send_post_bp.route("/post", methods=["POST"])
@token_required
def send_post(user_id):
	"""
	发送帖子，支持文本和图片。存本地uploads目录
	"""
	try:
		loop = asyncio.new_event_loop()
		asyncio.set_event_loop(loop)
		result, status = loop.run_until_complete(post_pipeline(user_id))
		loop.close()
		if "error" in result:
			return jsonify({"success": False, "message": result["error"]}), status
		logger.info(f"用户{user_id}发帖成功: {result['post_id']}")
		return jsonify(result), status
	except Exception as e:
		logger.error(f"发帖异常: {e}")
		return jsonify({"success": False, "message": "服务器错误"}), 500


@send_post_bp.route("/post/<post_id>", methods=["GET"])
def get_post(post_id):
	try:
		redis_key = f"post:{post_id}"
		post = redis_client.hgetall(redis_key)
		if not post:
			# 缓存未命中，查数据库
			with get_db_connection() as conn:
				cursor = conn.cursor()
				cursor.execute("SELECT * FROM posts WHERE post_id=?", (post_id,))
				row = cursor.fetchone()
				if not row:
					return jsonify({"success": False, "message": "帖子不存在"}), 404
				post = dict(row)
				redis_client.hmset(redis_key, post)
				redis_client.expire(redis_key, 3600 * 24)
		return jsonify({"success": True, "data": post})
	except Exception as e:
		logger.error(f"获取帖子异常: {e}")
		return jsonify({"success": False, "message": "服务器错误"}), 500

