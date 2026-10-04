from typing import TypeVar

from flask import request
from pydantic import BaseModel, ValidationError

from app.errors import RequestValidationError

ModelT = TypeVar("ModelT", bound=BaseModel)


def parse_body(model: type[ModelT]) -> ModelT:
    """Validate the JSON request body against a pydantic model."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise RequestValidationError([{"field": "body", "msg": "Request body must be a JSON object"}])
    try:
        return model.model_validate(data)
    except ValidationError as e:
        details = [
            {"field": ".".join(str(part) for part in err["loc"]) or "body", "msg": err["msg"]}
            for err in e.errors()
        ]
        raise RequestValidationError(details) from e
