# auth_service/auth_service.py
import os

import bcrypt
from flask import Flask, request, jsonify
from users_repository import fetch_hashed_password
import jwt
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')


@app.route('/auth/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    # Get hashed password from db
    hashed_password = fetch_hashed_password(username)

    if hashed_password is None:
        return jsonify({'message': 'Invalid credentials'}), 401  # Пользователь не найден

    # Compare passwords
    if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
        # JWT-token generation
        token = jwt.encode({
            'username': username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
        }, app.config['SECRET_KEY'])

        return jsonify({'token': token})

    return jsonify({'message': 'Invalid credentials'}), 401  # Неверный пароль


@app.route('/auth/validate', methods=['GET'])
def validate():
    """User validation endpoint"""
    token = request.headers.get('Authorization').split()[1]
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return jsonify({'status': 'valid', 'user': data['username']})
    except jwt.ExpiredSignatureError:
        return jsonify({'status': 'expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'status': 'invalid'}), 401


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
