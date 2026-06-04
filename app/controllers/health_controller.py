from flask import Blueprint
from flask_restx import Api, Resource, Namespace
from app.logger_config import setup_logger

logger = setup_logger("health_controller")

health_bp = Blueprint('health_bp', __name__)
health_api = Api(health_bp, title='Health API', description='Health checks')

health_ns = Namespace('health', description="Health check operations")
health_api.add_namespace(health_ns)


@health_ns.route('/')
class HealthCheck(Resource):
    def get(self):
        """Health check endpoint"""
        return {
            "status": "healthy",
            "service": "auth-service",
            "version": "1.0.0",
            "timestamp": __import__('datetime').datetime.utcnow().isoformat()
        }, 200