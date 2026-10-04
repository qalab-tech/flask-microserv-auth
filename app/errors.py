"""Domain exceptions and the single place that turns them into HTTP responses."""
from werkzeug.exceptions import HTTPException


class RequestValidationError(Exception):
    """Request body is not a JSON object or does not match the schema."""

    def __init__(self, details: list[dict]):
        super().__init__("Validation failed")
        self.details = details


class AuthError(Exception):
    """Bearer token is missing or unusable; `status` goes to the response body."""
    status = "invalid"


class TokenMissing(AuthError):
    status = "missing"


class TokenInvalid(AuthError):
    status = "invalid"


class TokenExpired(AuthError):
    status = "expired"


class TokenRevoked(AuthError):
    status = "revoked"


class InvalidCredentials(Exception):
    """Wrong username or password."""


class Forbidden(Exception):
    """Authenticated, but not allowed to touch this resource."""


class UserNotFound(Exception):
    pass


class UserAlreadyExists(Exception):
    pass


class ServiceUnavailable(Exception):
    """A dependency (Redis) is unreachable; the client may retry."""


def register_error_handlers(api) -> None:
    """Register handlers on a flask-restx Api. The first matching handler wins, so Exception goes last."""

    @api.errorhandler(RequestValidationError)
    def handle_validation_error(e):
        return {"message": "Validation failed", "errors": e.details}, 400

    @api.errorhandler(AuthError)
    def handle_auth_error(e):
        return {"message": "Unauthorized", "status": e.status}, 401

    @api.errorhandler(InvalidCredentials)
    def handle_invalid_credentials(e):
        return {"message": "Invalid credentials"}, 401

    @api.errorhandler(Forbidden)
    def handle_forbidden(e):
        return {"message": "Forbidden"}, 403

    @api.errorhandler(UserNotFound)
    def handle_user_not_found(e):
        return {"message": "User not found"}, 404

    @api.errorhandler(UserAlreadyExists)
    def handle_user_already_exists(e):
        return {"message": "Username already taken"}, 409

    @api.errorhandler(ServiceUnavailable)
    def handle_service_unavailable(e):
        return {"message": "Service temporarily unavailable"}, 503

    @api.errorhandler(Exception)
    def handle_unexpected_error(e):
        if isinstance(e, HTTPException):
            # Keep protocol headers (e.g. Allow on 405); the body is JSON, so drop Content-Type.
            headers = {k: v for k, v in e.get_headers() if k.lower() != "content-type"}
            return {"message": e.description}, e.code or 500, headers
        # flask-restx logs the traceback for 5xx responses; the client gets no details.
        return {"message": "Internal server error"}, 500
