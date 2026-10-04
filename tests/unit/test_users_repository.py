import psycopg2.errors
import pytest

from app.errors import UserAlreadyExists
from app.repositories import users_repository


class FailingCursor:
    def __init__(self, error):
        self.error = error

    def execute(self, sql, params=None):
        raise self.error

    def close(self):
        pass


class FakeConnection:
    def __init__(self, error):
        self.error = error
        self.rolled_back = False

    def cursor(self, cursor_factory=None):
        return FailingCursor(self.error)

    def rollback(self):
        self.rolled_back = True

    def commit(self):
        raise AssertionError("must not commit after a failed INSERT")


@pytest.fixture
def connection_failing_with(monkeypatch):
    def _make(error):
        connection = FakeConnection(error)
        monkeypatch.setattr(users_repository, "get_db_connection", lambda: connection)
        monkeypatch.setattr(users_repository, "release_db_connection", lambda c: None)
        return connection
    return _make


def test_duplicate_username_raises_domain_error(connection_failing_with):
    connection = connection_failing_with(psycopg2.errors.UniqueViolation("duplicate key value"))

    with pytest.raises(UserAlreadyExists):
        users_repository.create_user("alice", "hash")
    assert connection.rolled_back


def test_other_database_errors_propagate_unchanged(connection_failing_with):
    connection_failing_with(RuntimeError("connection lost"))

    with pytest.raises(RuntimeError, match="connection lost"):
        users_repository.create_user("alice", "hash")
