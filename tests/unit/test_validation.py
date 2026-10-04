import pytest
from flask import Flask

from app.errors import RequestValidationError
from app.schemas.user_schemas import LoginRequest, UserUpdate
from app.validation import parse_body

app = Flask(__name__)

NOT_AN_OBJECT = [{"field": "body", "msg": "Request body must be a JSON object"}]


def test_parse_body_returns_model():
    with app.test_request_context(method="POST", json={"username": "alice", "password": "pw"}):
        body = parse_body(LoginRequest)
    assert body.username == "alice"
    assert body.password == "pw"


@pytest.mark.parametrize("kwargs", [
    {"data": "username=alice", "content_type": "application/x-www-form-urlencoded"},
    {"data": "{broken", "content_type": "application/json"},
    {"json": ["alice", "pw"]},
    {"json": "alice"},
    {},
], ids=["form", "broken-json", "array", "string", "empty"])
def test_parse_body_rejects_non_object_body(kwargs):
    with app.test_request_context(method="POST", **kwargs):
        with pytest.raises(RequestValidationError) as exc_info:
            parse_body(LoginRequest)
    assert exc_info.value.details == NOT_AN_OBJECT


def test_parse_body_reports_field_errors():
    with app.test_request_context(method="POST", json={"username": "alice"}):
        with pytest.raises(RequestValidationError) as exc_info:
            parse_body(LoginRequest)
    assert exc_info.value.details == [{"field": "password", "msg": "Field required"}]


def test_parse_body_reports_model_level_errors_as_body():
    with app.test_request_context(method="POST", json={}):
        with pytest.raises(RequestValidationError) as exc_info:
            parse_body(UserUpdate)
    assert [d["field"] for d in exc_info.value.details] == ["body"]
