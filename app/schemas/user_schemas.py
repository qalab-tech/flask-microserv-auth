from typing import Annotated

from pydantic import AfterValidator, BaseModel, EmailStr, Field, model_validator

from app.hashing import BCRYPT_MAX_BYTES


# Must match the width of the `email` column in init_db.py (VARCHAR(100)).
EMAIL_MAX_LENGTH = 100


def _reject_nul(value: str) -> str:
    if "\x00" in value:
        raise ValueError("Must not contain NUL characters")  # PostgreSQL cannot store them
    return value


def _check_email_length(email: str) -> str:
    if len(email) > EMAIL_MAX_LENGTH:
        raise ValueError(f"Email must be at most {EMAIL_MAX_LENGTH} characters")
    return email


def _check_password_bytes(password: str) -> str:
    if len(password.encode("utf-8")) > BCRYPT_MAX_BYTES:
        raise ValueError(f"Password must be at most {BCRYPT_MAX_BYTES} bytes in UTF-8")
    return password


# At least 6 characters; at most 72 bytes because bcrypt ignores everything after that.
Password = Annotated[str, Field(min_length=6), AfterValidator(_check_password_bytes)]
Email = Annotated[EmailStr, AfterValidator(_check_email_length)]


class UserRegister(BaseModel):
    username: Annotated[str, Field(min_length=3, max_length=50), AfterValidator(_reject_nul)]
    email: Email | None = None
    password: Password


class UserUpdate(BaseModel):
    email: Email | None = None
    password: Password | None = None

    @model_validator(mode="after")
    def check_not_empty(self):
        if self.email is None and self.password is None:
            raise ValueError("At least one of 'email' or 'password' must be provided")
        return self


class LoginRequest(BaseModel):
    username: Annotated[str, Field(min_length=1), AfterValidator(_reject_nul)]
    password: str = Field(min_length=1)
