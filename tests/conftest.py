import os
import sys

# Добавляем корень проекта в PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Defaults for running tests outside Docker; real environment variables take precedence.
os.environ.setdefault("SECRET_KEY", "test-secret-key-that-is-long-enough-0123")
os.environ.setdefault("AUTH_DATABASE_URL", "postgresql://postgres:postgres@localhost:5433/authdb")
os.environ.setdefault("REDIS_HOST", "localhost")
os.environ.setdefault("REDIS_PORT", "6379")
