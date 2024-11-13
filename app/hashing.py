# app/hashing.py

from concurrent.futures import ThreadPoolExecutor
import bcrypt
from performance_monitor import log_duration, async_log_duration

executor = ThreadPoolExecutor(max_workers=4)


@log_duration
def hash_password(password: str) -> str:
    """Bcrypt password hashing with asynchronous execution"""
    future = executor.submit(_hash_sync, password)
    return future.result()


@log_duration
def _hash_sync(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')


@log_duration
def check_password(password: str, hashed_password: str) -> bool:
    """Compare password with a hashed value"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
