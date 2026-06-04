from flask import Blueprint
from flask_restx import Resource, Namespace

from app.controllers.auth_controller import auth_api
from app.logger_config import setup_logger



logger = setup_logger("health_controller")

health_bp = Blueprint('health_bp', __name__)

health_api =  auth_api

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