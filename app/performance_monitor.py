# performance_monitor.py
from datetime import datetime
from functools import wraps
import asyncio
from app.logger_config import setup_logger

logger = setup_logger("performance_monitor")


# for sync functions
def log_duration(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = datetime.now()
        # Execute target function
        result = func(*args, **kwargs)
        # Measure time of execution
        end_time = datetime.now()
        duration = end_time - start_time
        logger.info(f"Function '{func.__name__}' executed in {duration.total_seconds()} seconds")
        return result

    return wrapper


# for async functions
def async_log_duration(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        start_time = datetime.now()
        # Execute async function
        result = await func(*args, **kwargs)
        end_time = datetime.now()
        duration = end_time - start_time
        logger.info(f"Async function '{func.__name__}' executed in {duration.total_seconds()} seconds")

        return result

    return wrapper
