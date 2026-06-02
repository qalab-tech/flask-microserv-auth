import os

SECRET_KEY = os.getenv('SECRET_KEY')
AUTH_DATABASE_URL = os.getenv("AUTH_DATABASE_URL")
REDIS_HOST = os.getenv("REDIS_HOST")
REDIS_PORT = os.getenv("REDIS_PORT")