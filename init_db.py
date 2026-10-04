import sys

import bcrypt

from app.db import get_db_connection, release_db_connection
from app.logger_config import setup_logger
from config import SEED_TEST_USERS

logger = setup_logger("init_db")

CREATE_USERS_TABLE = """
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        hashed_password TEXT NOT NULL,
        email VARCHAR(100),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
"""

# Well-known credentials for local development and autotests only (SEED_TEST_USERS=true).
TEST_USERS = [
    ("test", "test", "test@example.com"),
    ("valid_user", "correct_pass", "valid_user@example.com"),
]


def _seed_test_users(cursor) -> None:
    for username, password, email in TEST_USERS:
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12)).decode('utf-8')
        cursor.execute("DELETE FROM users WHERE username = %s", (username,))
        cursor.execute(
            "INSERT INTO users (username, hashed_password, email) VALUES (%s, %s, %s)",
            (username, hashed, email),
        )
        logger.info(f"✅ Test user '{username}' created")


def initialize_database(seed_test_users: bool) -> None:
    """Create the schema and, only when asked, the test users."""
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(CREATE_USERS_TABLE)
            if seed_test_users:
                _seed_test_users(cursor)
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        release_db_connection(connection)


def main() -> int:
    try:
        initialize_database(SEED_TEST_USERS)
    except Exception:
        logger.exception("❌ Database initialization failed")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
