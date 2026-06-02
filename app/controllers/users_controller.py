from flask import Blueprint, request, jsonify
from flask_restx import Api, Resource, fields, Namespace
from app.services.user_service import (
    register_user, get_user_profile, get_users_list,
    update_user_profile, remove_user
)
from app.logger_config import setup_logger

logger = setup_logger("users_controller")

# ================== Blueprint ==================
users_bp = Blueprint('users_bp', __name__)

# Используем тот же Api, что и в auth_controller
from app.controllers.auth_controller import auth_api
users_api = auth_api

users_ns = Namespace('users', description="Operations with users")
users_api.add_namespace(users_ns)

# ================== Swagger Models ==================
register_model = users_api.model('UserRegister', {
    'username': fields.String(required=True, description='Username'),
    'password': fields.String(required=True, description='Password'),
    'email': fields.String(required=False, description='Email')
})

update_model = users_api.model('UserUpdate', {          # ← Добавили!
    'email': fields.String(required=False, description='New email'),
    'password': fields.String(required=False, description='New password')
})

# ================== Routes ==================

@users_ns.route('/register')
class Register(Resource):
    @users_ns.expect(register_model)
    def post(self):
        """Register new user"""
        data = request.json
        try:
            user = register_user(
                username=data['username'],
                password=data['password'],
                email=data.get('email')
            )
            return {
                "message": "User registered successfully",
                "user_id": user['id']
            }, 201
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return {"error": str(e)}, 400


@users_ns.route('/users')
class UsersList(Resource):
    def get(self):
        """Get all users"""
        try:
            result = get_users_list(limit=50)
            for user in result.get('users', []):
                if 'created_at' in user and user['created_at']:
                    user['created_at'] = user['created_at'].isoformat()
            return result, 200
        except Exception as e:
            logger.error(f"Error getting users list: {e}")
            return {"error": str(e)}, 500


@users_ns.route('/users/<int:user_id>')
class UserDetail(Resource):
    def get(self, user_id):
        """Get user by ID"""
        try:
            user = get_user_profile(user_id)
            if user and 'created_at' in user and user['created_at']:
                user['created_at'] = user['created_at'].isoformat()
            return user, 200
        except ValueError:
            return {"error": "User not found"}, 404
        except Exception as e:
            logger.error(f"Error getting user {user_id}: {e}")
            return {"error": str(e)}, 500

    @users_ns.expect(update_model)
    def put(self, user_id):
        """Update user"""
        data = request.json or {}
        try:
            user = update_user_profile(
                user_id=user_id,
                email=data.get('email'),
                password=data.get('password')
            )

            # Преобразуем datetime в строку
            if user and 'created_at' in user and user['created_at']:
                user['created_at'] = user['created_at'].isoformat()

            return user, 200
        except Exception as e:
            logger.error(f"Error updating user {user_id}: {e}")
            return {"error": str(e)}, 400
    def delete(self, user_id):
        """Delete user"""
        try:
            remove_user(user_id)
            return {"message": "User deleted successfully"}, 200
        except Exception as e:
            logger.error(f"Error deleting user {user_id}: {e}")
            return {"error": str(e)}, 400