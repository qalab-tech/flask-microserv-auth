import pytest

import init_db


class FakeCursor:
    def __init__(self, fail: bool):
        self.fail = fail
        self.executed: list[str] = []

    def execute(self, sql, params=None):
        if self.fail:
            raise RuntimeError("permission denied for schema public")
        self.executed.append(" ".join(sql.split()))

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


class FakeConnection:
    def __init__(self, fail: bool):
        self.cursor_obj = FakeCursor(fail)
        self.committed = False
        self.rolled_back = False

    def cursor(self):
        return self.cursor_obj

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True


@pytest.fixture
def connection(monkeypatch):
    def _make(fail: bool = False) -> FakeConnection:
        conn = FakeConnection(fail)
        monkeypatch.setattr(init_db, "get_db_connection", lambda: conn)
        monkeypatch.setattr(init_db, "release_db_connection", lambda c: None)
        return conn
    return _make


def _inserts(conn):
    return [sql for sql in conn.cursor_obj.executed if sql.startswith("INSERT")]


def test_without_seed_flag_only_creates_schema(connection):
    conn = connection()
    init_db.initialize_database(seed_test_users=False)

    assert conn.cursor_obj.executed[0].startswith("CREATE TABLE IF NOT EXISTS users")
    assert _inserts(conn) == []
    assert conn.committed


def test_with_seed_flag_creates_both_test_users(connection):
    conn = connection()
    init_db.initialize_database(seed_test_users=True)

    assert len(_inserts(conn)) == 2
    assert conn.committed


def test_main_reads_seed_flag_from_config(connection, monkeypatch):
    conn = connection()
    monkeypatch.setattr(init_db, "SEED_TEST_USERS", False)

    assert init_db.main() == 0
    assert _inserts(conn) == []


def test_main_returns_error_code_when_schema_creation_fails(connection):
    conn = connection(fail=True)

    assert init_db.main() == 1
    assert conn.rolled_back
    assert not conn.committed
