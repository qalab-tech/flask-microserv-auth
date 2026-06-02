import bcrypt
from app.db import get_db_connection, release_db_connection
from app.logger_config import setup_logger

logger = setup_logger("init_db")


def init_test_user():
    """Создаёт тестового пользователя при старте сервиса"""
    connection = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        # Создаём таблицу, если её нет
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                hashed_password TEXT NOT NULL,
                email VARCHAR(100),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Удаляем старых тестовых пользователей
        cursor.execute("DELETE FROM users WHERE username = 'test'")
        cursor.execute("DELETE FROM users WHERE username = 'valid_user'")


        # Генерируем свежий хеш для пароля "test"
        password_test = "test"
        hashed_pass_test = bcrypt.hashpw(password_test.encode('utf-8'), bcrypt.gensalt(rounds=12))

        password_valid = "correct_pass"
        hashed_pass_valid = bcrypt.hashpw(password_valid.encode('utf-8'), bcrypt.gensalt(rounds=12))

        # Создаём пользователя
        cursor.execute("""
            INSERT INTO users (username, hashed_password, email)
            VALUES (%s, %s, %s)
        """, ('test', hashed_pass_test.decode('utf-8'), 'test@example.com'))

        cursor.execute("""
            INSERT INTO users (username, hashed_password, email)
            VALUES (%s, %s, %s)
        """, ('valid_user', hashed_pass_valid.decode('utf-8'), 'valid_user@example.com'))

        connection.commit()
        logger.info("✅ Test user 'test' / 'test' created successfully")
        logger.info("✅ Test user 'valid_user' / 'correct_pass' created successfully")




    except Exception as e:
        logger.error(f"❌ Error initializing test user: {e}")
    finally:
        if connection:
            release_db_connection(connection)


if __name__ == "__main__":
    init_test_user()