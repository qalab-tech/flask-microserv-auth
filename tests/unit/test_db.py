import pytest

import app.db as db


class FakePool:
    created = 0

    def __init__(self, minconn, maxconn, dsn):
        FakePool.created += 1
        self.dsn = dsn

    def getconn(self):
        return "connection"

    def putconn(self, connection):
        pass

    def closeall(self):
        pass


@pytest.fixture
def fake_pool(monkeypatch):
    FakePool.created = 0
    monkeypatch.setattr(db, "_connection_pool", None)
    monkeypatch.setattr(db.psycopg2.pool, "SimpleConnectionPool", FakePool)
    return FakePool


def test_pool_is_created_lazily_and_only_once(fake_pool, monkeypatch):
    monkeypatch.setenv("AUTH_DATABASE_URL", "postgresql://u:p@db/authdb")
    assert fake_pool.created == 0

    assert db.get_db_connection() == "connection"
    assert db.get_db_connection() == "connection"

    assert fake_pool.created == 1


def test_missing_database_url_fails_on_first_use(fake_pool, monkeypatch):
    monkeypatch.delenv("AUTH_DATABASE_URL", raising=False)
    with pytest.raises(ValueError, match="AUTH_DATABASE_URL"):
        db.get_db_connection()
