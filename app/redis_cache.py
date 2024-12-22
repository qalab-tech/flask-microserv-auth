# Redis cache
import redis
import jwt
import time
from app.logger_config import setup_logger
from app.performance_monitor import log_duration
import os
from dotenv import load_dotenv

logger = setup_logger("Redis Cache")

# Loading environment variables depending on the environment
if os.getenv("ENV") == "docker":
    load_dotenv(".env.docker")
else:
    load_dotenv(".env.local")
# Radis connection string (we can use a password to improve security)

REDIS_HOST = os.getenv("REDIS_HOST")
REDIS_PORT = os.getenv("REDIS_PORT")

if REDIS_HOST is None or REDIS_PORT is None:
    logger.error("REDIS connection is not set in the environment variables, please check the .env.docker file")
    raise ValueError("REDIS connection is not set in the environment variables.")

cache = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)


# Token generation
@log_duration
def generate_token(user_id, secret_key):
    # Get token from cache
    cached_token = cache.get(f"token:{user_id}")
    if cached_token:
        return cached_token

    # Generate token if it's not present in Redis Cache
    payload = {
        "user_id": user_id,
        "exp": int(time.time()) + 3600  # 1 hour time to live for new token
    }
    token = jwt.encode(payload, secret_key, algorithm="HS256")

    # Store token to Radis Cache for time to live
    cache.setex(f"token:{user_id}", 3600, token)
    return token


# Token verification
@log_duration
def verify_token(token, secret_key):
    # Check token in Redis cache
    cached_token = cache.get(token)
    if cached_token:
        return jwt.decode(cached_token, secret_key, algorithms=["HS256"])

    # Generate and cache token if it's valid
    try:
        decoded_payload = jwt.decode(token, secret_key, algorithms=["HS256"])
        # Save token in Redis cache
        cache.setex(token, 3600, token)
        return decoded_payload
    except jwt.ExpiredSignatureError:
        return None



