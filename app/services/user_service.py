from app.repositories.users_repository import (
    create_user, get_user_by_id, get_all_users,
    update_user, delete_user
)
from app.hashing import hash_password
from app.logger_config import setup_logger

logger = setup_logger("user_service")


def register_user(username: str, password: str, email: str = None):
    """Регистрация нового пользователя"""
    try:
        # Хэшируем пароль
        hashed_password = hash_password(password)

        # Создаём пользователя
        user = create_user(username=username, hashed_password=hashed_password, email=email)
        logger.info(f"User registered successfully: {username}")
        return user
    except Exception as e:
        logger.error(f"Registration failed for {username}: {e}")
        raise


def get_user_profile(user_id: int):
    """Получить профиль пользователя"""
    user = get_user_by_id(user_id)
    if not user:
        raise ValueError("User not found")
    return user


def get_users_list(limit: int = 50, offset: int = 0):
    """Получить список пользователей"""
    return get_all_users(limit=limit, offset=offset)


def update_user_profile(user_id: int, email: str = None, password: str = None):
    """Обновление профиля пользователя"""
    hashed_password = None
    if password:
        hashed_password = hash_password(password)

    user = update_user(
        user_id=user_id,
        email=email,
        hashed_password=hashed_password
    )
    if not user:
        raise ValueError("User not found")
    return user


def remove_user(user_id: int):
    """Удаление пользователя"""
    deleted = delete_user(user_id)
    if not deleted:
        raise ValueError("User not found")
    return {"message": "User deleted successfully"}