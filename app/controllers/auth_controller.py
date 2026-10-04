# app/auth_controller.py
from flask import Blueprint, g
from flask_restx import Api, Namespace, Resource, fields

from app.auth_guard import require_auth
from app.errors import InvalidCredentials, register_error_handlers
from app.hashing import DUMMY_HASH, check_password
from app.logger_config import setup_logger
from app.repositories.users_repository import get_user_credentials
from app.schemas.user_schemas import LoginRequest
from app.tokens import issue_token, revoke_token
from app.validation import parse_body

logger = setup_logger("auth_controller")

# Create auth Blueprint

auth_bp = Blueprint('auth_bp', __name__)
authorizations = {
    "Bearer": {"type": "apiKey", "in": "header", "name": "Authorization", "description": "Bearer <token>"}
}
auth_api = Api(
    auth_bp,
    title='Auth API',
    description='API for authentication',
    authorizations=authorizations,
)
register_error_handlers(auth_api)

# Create namespace

auth_ns = Namespace('auth', description="Operations related to authentication")
auth_api.add_namespace(auth_ns)

# Define models for Swagger Documentation
login_model = auth_api.model('Login', {
    'username': fields.String(required=True, description='Username of the user'),
    'password': fields.String(required=True, description='Password of the user')
})


# /login route description
@auth_ns.route('/login')
class Login(Resource):
    @auth_ns.expect(login_model)
    @auth_ns.response(200, 'Success')
    @auth_ns.response(400, 'Invalid request body')
    @auth_ns.response(401, 'Invalid credentials')
    def post(self):
        """Log in and get an access token"""
        body = parse_body(LoginRequest)
        user = get_user_credentials(body.username)
        # Unknown usernames are checked against a dummy hash so that the response
        # time does not reveal whether the username exists.
        hashed_password = user["hashed_password"] if user else DUMMY_HASH
        password_ok = check_password(body.password, hashed_password)
        if user is None or not password_ok:
            logger.warning("Invalid credentials for username %r", body.username)
            raise InvalidCredentials()
        return {"token": issue_token(user["id"], user["username"])}, 200


# /validate route description
@auth_ns.route('/validate')
@auth_ns.doc(security="Bearer")
class Validate(Resource):
    @auth_ns.response(200, 'Token is valid')
    @auth_ns.response(401, 'Token is missing, invalid, expired or revoked')
    @auth_ns.response(503, 'Token store is unavailable')
    @require_auth
    def get(self):
        """Token validation endpoint"""
        return {
            "status": "valid",
            "user": g.current_user["username"],
            "user_id": g.current_user["id"],
        }, 200


# /logout route description
@auth_ns.route('/logout')
@auth_ns.doc(security="Bearer")
class Logout(Resource):
    @auth_ns.response(204, 'Token revoked')
    @auth_ns.response(401, 'Token is missing, invalid, expired or revoked')
    @auth_ns.response(503, 'Token store is unavailable')
    @require_auth
    def post(self):
        """Revoke the current token"""
        revoke_token(g.token_claims)
        return "", 204
