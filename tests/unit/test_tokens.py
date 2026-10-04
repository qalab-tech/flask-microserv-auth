import jwt
import pytest

import config
from app import tokens
from app.errors import ServiceUnavailable, TokenExpired, TokenInvalid, TokenRevoked

OTHER_KEY = "another-secret-key-that-is-long-enough-42"


def test_issued_token_round_trips(fake_redis, clock):
    claims = tokens.decode_token(tokens.issue_token(42, "alice"))

    assert claims["sub"] == "42"
    assert claims["username"] == "alice"
    assert claims["iat"] == clock.now
    assert claims["exp"] == clock.now + config.JWT_ACCESS_TOKEN_EXPIRES
    assert len(claims["jti"]) == 32


def test_each_token_gets_its_own_jti(fake_redis, clock):
    first = tokens.decode_token(tokens.issue_token(1, "alice"))
    second = tokens.decode_token(tokens.issue_token(1, "alice"))
    assert first["jti"] != second["jti"]


def test_expired_token_is_rejected(fake_redis, clock):
    clock.now -= config.JWT_ACCESS_TOKEN_EXPIRES + 10
    token = tokens.issue_token(1, "alice")

    with pytest.raises(TokenExpired):
        tokens.decode_token(token)


@pytest.mark.parametrize("overrides", [
    {"key": OTHER_KEY},
    {"jti": None},
    {"username": None},
    {"sub": None},
    {"sub": "abc"},
], ids=["foreign-signature", "no-jti", "no-username", "no-sub", "non-numeric-sub"])
def test_invalid_tokens_are_rejected(fake_redis, forge_token, overrides):
    with pytest.raises(TokenInvalid):
        tokens.decode_token(forge_token(**overrides))


@pytest.mark.parametrize("overrides", [
    {"iat": "1"},
    {"iat": 1.5},
    {"exp": "9999999999"},
    {"exp": 9999999999.5},
], ids=["string-iat", "float-iat", "string-exp", "float-exp"])
def test_non_integer_timestamps_are_rejected(fake_redis, forge_token, clock, overrides):
    tokens.revoke_all_for_user(1)  # makes decode_token compare iat with valid_after

    with pytest.raises(TokenInvalid):
        tokens.decode_token(forge_token(**overrides))


@pytest.mark.filterwarnings("ignore:The HMAC key is:Warning")
def test_unsigned_and_hs512_tokens_are_rejected(fake_redis, clock):
    claims = {"sub": "1", "username": "alice", "iat": clock.now, "exp": clock.now + 600, "jti": "f" * 32}
    unsigned = jwt.encode(claims, None, algorithm="none")
    hs512 = jwt.encode(claims, config.SECRET_KEY, algorithm="HS512")

    for token in (unsigned, hs512):
        with pytest.raises(TokenInvalid):
            tokens.decode_token(token)


def test_garbage_is_rejected(fake_redis):
    with pytest.raises(TokenInvalid):
        tokens.decode_token("not-a-jwt")


def test_revoked_token_is_rejected(fake_redis, clock):
    token = tokens.issue_token(1, "alice")
    tokens.revoke_token(tokens.decode_token(token))

    with pytest.raises(TokenRevoked):
        tokens.decode_token(token)


def test_revoking_one_token_keeps_the_others(fake_redis, clock):
    first = tokens.issue_token(1, "alice")
    second = tokens.issue_token(1, "alice")
    tokens.revoke_token(tokens.decode_token(first))

    assert tokens.decode_token(second)["sub"] == "1"


def test_revocation_key_lives_only_as_long_as_the_token(fake_redis, clock):
    claims = tokens.decode_token(tokens.issue_token(1, "alice"))
    clock.advance(100)
    tokens.revoke_token(claims)

    ttl = fake_redis.ttl(f"revoked:{claims['jti']}")
    assert 0 < ttl <= config.JWT_ACCESS_TOKEN_EXPIRES - 100


def test_revoke_all_rejects_tokens_issued_earlier(fake_redis, clock):
    old = tokens.issue_token(1, "alice")
    clock.advance(5)
    tokens.revoke_all_for_user(1)

    with pytest.raises(TokenRevoked):
        tokens.decode_token(old)


def test_revoke_all_keeps_tokens_issued_in_the_same_second(fake_redis, clock):
    tokens.revoke_all_for_user(1)
    fresh = tokens.issue_token(1, "alice")

    assert tokens.decode_token(fresh)["sub"] == "1"


def test_revoke_all_inclusive_rejects_tokens_issued_in_the_same_second(fake_redis, clock):
    same_second = tokens.issue_token(1, "alice")
    tokens.revoke_all_for_user(1, include_current_second=True)

    with pytest.raises(TokenRevoked):
        tokens.decode_token(same_second)
    clock.advance(1)
    assert tokens.decode_token(tokens.issue_token(1, "alice"))["sub"] == "1"


def test_revoke_all_inclusive_key_still_covers_every_earlier_token(fake_redis, clock):
    tokens.revoke_all_for_user(1, include_current_second=True)
    assert 0 < fake_redis.ttl("valid_after:1") <= config.JWT_ACCESS_TOKEN_EXPIRES + 1


def test_revoke_all_affects_only_that_user(fake_redis, clock):
    bob = tokens.issue_token(2, "bob")
    clock.advance(5)
    tokens.revoke_all_for_user(1)

    assert tokens.decode_token(bob)["sub"] == "2"


def test_revoke_all_key_lives_as_long_as_a_token(fake_redis, clock):
    tokens.revoke_all_for_user(1)
    assert 0 < fake_redis.ttl("valid_after:1") <= config.JWT_ACCESS_TOKEN_EXPIRES


def test_decode_fails_closed_when_redis_is_down(clock, break_redis):
    token = tokens.issue_token(1, "alice")
    break_redis()

    with pytest.raises(ServiceUnavailable):
        tokens.decode_token(token)


def test_revocations_report_redis_outage(clock, break_redis):
    break_redis()
    with pytest.raises(ServiceUnavailable):
        tokens.revoke_token({"jti": "f" * 32, "exp": clock.now + 600})
    with pytest.raises(ServiceUnavailable):
        tokens.revoke_all_for_user(1)
