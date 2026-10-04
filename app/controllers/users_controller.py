from flask import Blueprint, g
from flask_restx import Resource, fields, Namespace

from app.auth_guard import ensure_owner, require_auth
from app.controllers.auth_controller import auth_api
from app.logger_config import setup_logger
from app.schemas.user_schemas import UserRegister, UserUpdate
from app.services.user_service import (
    register_user, get_user_profile, get_users_list,
    update_user_profile, remove_user
)
from app.validation import parse_body

logger = setup_logger("users_controller")

# ================== Blueprint ==================
users_bp = Blueprint('users_bp', __name__)

# Используем тот же Api, что и в auth_controller
users_api = auth_api

users_ns = Namespace('users', description="Operations with users")
users_api.add_namespace(users_ns)

# ================== Swagger Models ==================
register_model = users_api.model('UserRegister', {
    'username': fields.String(required=True, description='Username'),
    'password': fields.String(required=True, description='Password'),
    'email': fields.String(required=False, description='Email')
})

update_model = users_api.model('UserUpdate', {
    'email': fields.String(required=False, description='New email'),
    'password': fields.String(required=False, description='New password')
})


def _serialize(user: dict) -> dict:
    """Make a user row JSON-friendly (created_at → ISO 8601)."""
    data = dict(user)
    if data.get('created_at') is not None:
        data['created_at'] = data['created_at'].isoformat()
    return data


# ================== Routes ==================

@users_ns.route('/register')
class Register(Resource):
    @users_ns.expect(register_model)
    def post(self):
        """Register new user"""
        user = register_user(parse_body(UserRegister))
        return {"message": "User registered successfully", "user_id": user['id']}, 201


@users_ns.route('/me')
@users_ns.doc(security="Bearer")
class Me(Resource):
    @require_auth
    def get(self):
        """Get the profile of the token owner"""
        return _serialize(get_user_profile(g.current_user['id'])), 200


@users_ns.route('/users')
@users_ns.doc(security="Bearer")
class UsersList(Resource):
    @require_auth
    def get(self):
        """Get all users"""
        result = get_users_list(limit=50)
        return {"users": [_serialize(user) for user in result['users']], "total": result['total']}, 200


@users_ns.route('/users/<int:user_id>')
@users_ns.doc(security="Bearer")
class UserDetail(Resource):
    @require_auth
    def get(self, user_id):
        """Get own user by ID"""
        ensure_owner(user_id)
        return _serialize(get_user_profile(user_id)), 200

    @users_ns.expect(update_model)
    @require_auth
    def put(self, user_id):
        """Update own user; a password change revokes all tokens"""
        ensure_owner(user_id)
        return _serialize(update_user_profile(user_id, parse_body(UserUpdate))), 200

    @require_auth
    def delete(self, user_id):
        """Delete own user and revoke all tokens"""
        ensure_owner(user_id)
        remove_user(user_id)
        return {"message": "User deleted successfully"}, 200
