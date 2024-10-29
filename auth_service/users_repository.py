import psycopg2
import psycopg2.extras
from db import get_db_connection, release_db_connection
import os
from logger_config import setup_logger

logger = setup_logger("users_repository")


def fetch_hashed_password(username):
    connection = get_db_connection()
    cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cursor.execute("SELECT hashed_password FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if not user:
            logger.info(f"No user found with username {username}")
            return None

        logger.info(f"User with username = {username} found in database")
        return user['hashed_password']
    except Exception as e:
        logger.error(f"Database error: {e}")
        return None
    finally:
        cursor.close()
        release_db_connection(connection)
