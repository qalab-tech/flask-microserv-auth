import logging
import sys


def setup_logger(name="my_app"):
    # Create logger with the name
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    # Create console handler for stdout logs
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)

    # Format output
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)

    # Add handler to logger
    logger.addHandler(console_handler)

    return logger
