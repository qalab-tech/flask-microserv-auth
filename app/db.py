import os

import psycopg2
from psycopg2 import pool  # noqa: F401  (makes psycopg2.pool available)

from app.logger_config import setup_logger

logger = setup_logger("db_connection")

# Created on first use, so importing the app (e.g. in unit tests) needs no database.
_connection_pool = None


def _get_pool():
    global _connection_pool
    if _connection_pool is None:
        database_url = os.getenv("AUTH_DATABASE_URL")
        if database_url is None:
            logger.error("AUTH_DATABASE_URL is not set in the environment variables")
            raise ValueError("AUTH_DATABASE_URL is not set in the environment variables.")
        try:
            _connection_pool = psycopg2.pool.SimpleConnectionPool(1, 20, database_url)
            logger.info("Connection pool created successfully")
        except Exception as e:
            logger.error(f"Error creating connection pool: {str(e)}")
            raise
    return _connection_pool


def get_db_connection():
    """Get connection from pool"""
    try:
        connection = _get_pool().getconn()
        logger.info("Successfully connected to the database")
        return connection
    except Exception as e:
        logger.error(f"Error getting connection from pool: {str(e)}")
        raise


def release_db_connection(connection):
    """Return connection to pool"""
    try:
        if connection:
            _get_pool().putconn(connection)
            logger.info("Connection returned to pool")
    except Exception as e:
        logger.error(f"Error releasing connection: {str(e)}")


def close_all_connections():
    """Close all connections from pool"""
    try:
        if _connection_pool:
            _connection_pool.closeall()
            logger.info("All connections in the pool closed")
    except Exception as e:
        logger.error(f"Error closing all connections: {str(e)}")
