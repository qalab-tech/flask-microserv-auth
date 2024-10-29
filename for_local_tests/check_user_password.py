import bcrypt
from users_repository import fetch_hashed_password

def check_user_password(username, password):
    hashed_password = fetch_hashed_password(username)

    if hashed_password is None:
        # logger.warning("Password check failed: user not found")
        return False  # User not found

    if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
        # logger.info("Password is correct")
        return True  # Correct Password
    else:
        # logger.warning("Password is incorrect")
        return False  # Wrong Password


print(check_user_password('test', 'test'))