import psycopg2.extras
from app.db import get_db_connection, release_db_connection
from app.logger_config import setup_logger
from app.performance_monitor import log_duration

logger = setup_logger("users_repository")


@log_duration
def fetch_hashed_password(username):
    connection = get_db_connection()
    cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cursor.execute("SELECT hashed_password FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if not user:
            logger.info(f"No user found with username '{username}'")
            return None

        logger.info(f"User with username = '{username}' found in database")
        return user['hashed_password']
    except psycopg2.Error as db_err:
        logger.error(f"Database operation error: {db_err}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return None
    finally:
        cursor.close()
        release_db_connection(connection)
