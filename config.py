import os

SECRET_KEY = os.getenv('SECRET_KEY')
AUTH_DATABASE_URL = os.getenv("AUTH_DATABASE_URL")
REDIS_HOST = os.getenv("REDIS_HOST")
REDIS_PORT = os.getenv("REDIS_PORT")

BASE_URL = "http://localhost:5001"
HEADERS = {"Content-Type": "application/json"}

JWT_ACCESS_TOKEN_EXPIRES = os.getenv("JWT_ACCESS_TOKEN_EXPIRES")
JWT_REFRESH_TOKEN_EXPIRES = os.getenv("JWT_REFRESH_TOKEN_EXPIRES")