# app/auth_controller.py
import os
import bcrypt
from flask import Flask, Blueprint, request, jsonify
from app.logger_config import setup_logger
from app.repositories.auth_repository import fetch_hashed_password
import jwt
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

logger = setup_logger("auth_controller")
auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    # Get hashed password from db
    hashed_password = fetch_hashed_password(username)

    if hashed_password is None:
        logger.error("User not found. Invalid credential")
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
    return jsonify({'message': 'Invalid credentials'}), 401  # Неверный пароль


@auth_bp.route('/validate', methods=['GET'])
def validate():
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
