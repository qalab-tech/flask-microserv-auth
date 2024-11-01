# app/auth_controller.py
import os
import bcrypt
from flask import Flask, Blueprint, request, jsonify
from app.logger_config import setup_logger
from app.repositories.auth_repository import fetch_hashed_password
import jwt
import datetime
from flask_restx import Api, Resource, fields, Namespace

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

logger = setup_logger("auth_controller")

# Create auth Blueprint

auth_bp = Blueprint('auth_bp', __name__)
auth_api = Api(auth_bp, title='Auth API', description='API for authentication')

# Create namespace

auth_ns = Namespace('auth', description="Operations related to authentication")
auth_api.add_namespace(auth_ns)

# Define models for Swagger Documentation

login_model = auth_api.model('Login', {
    'username': fields.String(required=True, description='Username of the user'),
    'password': fields.String(required=True, description='Password of the user')
})


# /login route description
@auth_bp.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    # Get hashed password from db
    hashed_password = fetch_hashed_password(username)
    # Check if the user exists
    if not hashed_password:
        logger.error("User not found. Invalid credentials")
        return jsonify({'message': 'Invalid credentials'}), 401  # User not found

    # Compare passwords
    if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
        # JWT-token generation
        token = jwt.encode({
            'username': username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
        }, app.config['SECRET_KEY'])

        return jsonify({'token': token})

    logger.error("Wrong password. Invalid credentials")
    return jsonify({'message': 'Invalid credentials'}), 401  # Incorrect password


# /validate route description
@auth_ns.route('/validate')
class Validate(Resource):
    @auth_ns.response(200, 'Token is valid')
    @auth_ns.response(401, 'Token is expired or invalid')
    @auth_ns.response(403, 'Token is missing!')
    def get(self):
        """User validation endpoint"""
        bearer_token = request.headers.get('Authorization')
        if not bearer_token:
            logger.error("Token is missing!")
            return jsonify({"message": "Token is missing!"}), 403
        try:
            token = bearer_token.split()[1]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            return jsonify({'status': 'valid', 'user': data['username']})
        except jwt.ExpiredSignatureError:
            logger.error("Token expired")
            return jsonify({'status': 'expired'}), 401
        except jwt.InvalidTokenError:
            logger.error("Token invalid")
            return jsonify({'status': 'invalid'}), 401



