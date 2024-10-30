# auth_service/hashing.py
import bcrypt


def hash_password(password: str) -> str:
    """Bcrypt password hashing"""
    salt = bcrypt.gensalt()  # Generate salt
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')  # return hash as a string


def check_password(password: str, hashed_password: str) -> bool:
    """Compare password with a hashed value"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
