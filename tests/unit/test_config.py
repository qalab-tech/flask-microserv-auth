import os
import subprocess
import sys
from pathlib import Path

import pytest

import config
from config import MIN_SECRET_KEY_LENGTH, load_secret_key, parse_bool

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_missing_secret_key_fails_fast():
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        load_secret_key({})


def test_short_secret_key_fails_fast():
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        load_secret_key({"SECRET_KEY": "x" * (MIN_SECRET_KEY_LENGTH - 1)})


def test_long_enough_secret_key_is_accepted():
    key = "x" * MIN_SECRET_KEY_LENGTH
    assert load_secret_key({"SECRET_KEY": key}) == key


@pytest.mark.parametrize("raw, expected", [
    (None, False), ("", False), ("false", False), ("0", False), ("no", False),
    ("true", True), ("TRUE", True), (" yes ", True), ("1", True), ("on", True),
])
def test_parse_bool(raw, expected):
    assert parse_bool(raw) is expected


def test_numeric_settings_are_ints():
    assert isinstance(config.JWT_ACCESS_TOKEN_EXPIRES, int)
    assert isinstance(config.REDIS_PORT, int)


def test_importing_config_without_secret_key_fails():
    env = {k: v for k, v in os.environ.items() if k != "SECRET_KEY"}
    result = subprocess.run(
        [sys.executable, "-c", "import config"],
        cwd=PROJECT_ROOT, env=env, capture_output=True, text=True,
    )
    assert result.returncode != 0
    assert "SECRET_KEY" in result.stderr
