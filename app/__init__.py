from flask import Flask
from app.controllers.auth_controller import auth_bp


def create_app():
    app = Flask(__name__)
    # Register BluePrint
    app.register_blueprint(auth_bp, url_prefix='/')

    return app


# Export env variable app for Gunicorn
app = create_app()
