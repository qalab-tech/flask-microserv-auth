from app.errors import UserNotFound
from app.hashing import hash_password
from app.logger_config import setup_logger
from app.repositories.users_repository import (
    create_user, get_user_by_id, get_all_users,
    update_user, delete_user
)
from app.schemas.user_schemas import UserRegister, UserUpdate
from app.tokens import revoke_all_for_user

logger = setup_logger("user_service")


def register_user(data: UserRegister) -> dict:
    """Регистрация нового пользователя"""
    user = create_user(
        username=data.username,
        hashed_password=hash_password(data.password),
        email=data.email
    )
    logger.info(f"User registered successfully: {data.username}")
    return user


def get_user_profile(user_id: int) -> dict:
    """Получить профиль пользователя"""
    user = get_user_by_id(user_id)
    if not user:
        raise UserNotFound()
    return user


def get_users_list(limit: int = 50, offset: int = 0) -> dict:
    """Получить список пользователей"""
    return get_all_users(limit=limit, offset=offset)


def update_user_profile(user_id: int, data: UserUpdate) -> dict:
    """Обновление профиля; смена пароля отзывает все токены пользователя"""
    hashed_password = hash_password(data.password) if data.password is not None else None
    user = update_user(user_id=user_id, email=data.email, hashed_password=hashed_password)
    if not user:
        raise UserNotFound()
    if hashed_password is not None:
        # After the DB write: if Redis is down the client gets 503 and can safely retry.
        revoke_all_for_user(user_id)
    return user


def remove_user(user_id: int) -> None:
    """Удаление пользователя; токены отзываются до удаления"""
    # Revoke first: if Redis is down, the user is not deleted and no live tokens are left behind.
    revoke_all_for_user(user_id)
    if not delete_user(user_id):
        raise UserNotFound()
