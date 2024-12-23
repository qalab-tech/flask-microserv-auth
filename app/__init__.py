from flask import Flask
from app.controllers.auth_controller import auth_bp
from prometheus_flask_exporter import PrometheusMetrics


def create_app():
    app = Flask(__name__)
    app.url_map.strict_slashes = False
    PrometheusMetrics(app, group_by='endpoint')
    # Register BluePrint
    app.register_blueprint(auth_bp, url_prefix='/')

    return app


# Export env variable app for Gunicorn
app = create_app()
