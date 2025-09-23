# run.py
from app import app
from app.routes.register import register_bp
from app.routes.login import login_bp
from app.routes.logout import logout_bp
from app.routes.forget import forget_bp
from app.routes.health import health_bp
from app.utils.config import config
from app.routes.send_post import send_post_bp
from app.routes.csrf_token import csrf_token_bp
import waitress
from app.auth import auth_bp

# 注册所有 Blueprint
app.register_blueprint(register_bp)
app.register_blueprint(login_bp)
app.register_blueprint(logout_bp)
app.register_blueprint(forget_bp)
app.register_blueprint(health_bp)
app.register_blueprint(send_post_bp)
app.register_blueprint(csrf_token_bp)


if __name__ == "__main__":
    if config.get("DEBUG", False):
        app.run(host="0.0.0.0", port=config['PORT'], debug=True)
    else:
        waitress.serve(app, host="0.0.0.0", port=config['PORT'])
