import pytest
from flask import Flask
from flask_restx import Api, Resource
from werkzeug.exceptions import HTTPException, MethodNotAllowed, NotFound

from app.errors import (
    Forbidden, InvalidCredentials, RequestValidationError, ServiceUnavailable,
    TokenExpired, TokenInvalid, TokenMissing, TokenRevoked, UserAlreadyExists,
    UserNotFound, register_error_handlers,
)


def _client_raising(exc):
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.config["RESTX_ERROR_404_HELP"] = False
    api = Api(app)
    register_error_handlers(api)

    @api.route("/boom")
    class Boom(Resource):
        def get(self):
            raise exc

    return app.test_client()


@pytest.mark.parametrize("exc, status, body", [
    (RequestValidationError([{"field": "x", "msg": "bad"}]), 400,
     {"message": "Validation failed", "errors": [{"field": "x", "msg": "bad"}]}),
    (TokenMissing(), 401, {"message": "Unauthorized", "status": "missing"}),
    (TokenInvalid(), 401, {"message": "Unauthorized", "status": "invalid"}),
    (TokenExpired(), 401, {"message": "Unauthorized", "status": "expired"}),
    (TokenRevoked(), 401, {"message": "Unauthorized", "status": "revoked"}),
    (InvalidCredentials(), 401, {"message": "Invalid credentials"}),
    (Forbidden(), 403, {"message": "Forbidden"}),
    (UserNotFound(), 404, {"message": "User not found"}),
    (UserAlreadyExists(), 409, {"message": "Username already taken"}),
    (ServiceUnavailable(), 503, {"message": "Service temporarily unavailable"}),
    (RuntimeError("db password is hunter2"), 500, {"message": "Internal server error"}),
], ids=lambda v: type(v).__name__ if isinstance(v, Exception) else None)
def test_exception_maps_to_response(exc, status, body):
    resp = _client_raising(exc).get("/boom")
    assert resp.status_code == status
    assert resp.json == body


def test_http_exceptions_keep_their_status():
    resp = _client_raising(NotFound()).get("/boom")
    assert resp.status_code == 404


def test_http_exceptions_keep_their_headers():
    resp = _client_raising(MethodNotAllowed(valid_methods=["GET", "POST"])).get("/boom")
    assert resp.status_code == 405
    allow = resp.headers["Allow"]
    assert "GET" in allow and "POST" in allow


def test_http_exception_without_code_returns_500():
    resp = _client_raising(HTTPException()).get("/boom")
    assert resp.status_code == 500
    assert "message" in resp.json
