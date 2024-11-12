# app/hashing.py

from concurrent.futures import ThreadPoolExecutor
import bcrypt

executor = ThreadPoolExecutor(max_workers=4)


def hash_password(password: str) -> str:
    """Bcrypt password hashing with asynchronous execution"""
    future = executor.submit(_hash_sync, password)
    return future.result()


def _hash_sync(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')


def check_password(password: str, hashed_password: str) -> bool:
    """Compare password with a hashed value"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
