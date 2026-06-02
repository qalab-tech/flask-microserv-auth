import psycopg2.extras
from app.db import get_db_connection, release_db_connection
from app.logger_config import setup_logger
from app.performance_monitor import log_duration

logger = setup_logger("users_repository")


@log_duration
def create_user(username: str, hashed_password: str, email: str = None):
    connection = get_db_connection()
    cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cursor.execute("""
            INSERT INTO users (username, hashed_password, email)
            VALUES (%s, %s, %s)
            RETURNING id, username, email, created_at
        """, (username, hashed_password, email))

        user = cursor.fetchone()
        connection.commit()
        logger.info(f"User created: {username}")
        return user
    except Exception as e:
        connection.rollback()
        logger.error(f"Error creating user {username}: {e}")
        raise
    finally:
        cursor.close()
        release_db_connection(connection)


@log_duration
def get_user_by_id(user_id: int):
    connection = get_db_connection()
    cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cursor.execute("SELECT id, username, email, created_at FROM users WHERE id = %s", (user_id,))
        return cursor.fetchone()
    finally:
        cursor.close()
        release_db_connection(connection)


@log_duration
def get_all_users(limit: int = 50, offset: int = 0):
    connection = get_db_connection()
    cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cursor.execute("""
            SELECT id, username, email, created_at 
            FROM users 
            ORDER BY id 
            LIMIT %s OFFSET %s
        """, (limit, offset))
        users = cursor.fetchall()

        cursor.execute("SELECT COUNT(*) FROM users")
        total = cursor.fetchone()['count']

        return {"users": users, "total": total}
    finally:
        cursor.close()
        release_db_connection(connection)


@log_duration
def update_user(user_id: int, email: str = None, hashed_password: str = None):
    connection = get_db_connection()
    cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        updates = []
        params = []
        if email is not None:
            updates.append("email = %s")
            params.append(email)
        if hashed_password is not None:
            updates.append("hashed_password = %s")
            params.append(hashed_password)

        if not updates:
            return None

        query = f"UPDATE users SET {', '.join(updates)} WHERE id = %s RETURNING id, username, email, created_at"
        params.append(user_id)

        cursor.execute(query, params)
        user = cursor.fetchone()
        connection.commit()
        return user
    except Exception as e:
        connection.rollback()
        logger.error(f"Error updating user {user_id}: {e}")
        raise
    finally:
        cursor.close()
        release_db_connection(connection)


@log_duration
def delete_user(user_id: int):
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        deleted = cursor.rowcount > 0
        connection.commit()
        return deleted
    finally:
        cursor.close()
        release_db_connection(connection)