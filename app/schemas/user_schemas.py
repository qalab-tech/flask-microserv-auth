from typing import Annotated

from pydantic import AfterValidator, BaseModel, EmailStr, Field, model_validator

from app.hashing import BCRYPT_MAX_BYTES


def _check_password_bytes(password: str) -> str:
    if len(password.encode("utf-8")) > BCRYPT_MAX_BYTES:
        raise ValueError(f"Password must be at most {BCRYPT_MAX_BYTES} bytes in UTF-8")
    return password


# At least 6 characters; at most 72 bytes because bcrypt ignores everything after that.
Password = Annotated[str, Field(min_length=6), AfterValidator(_check_password_bytes)]


class UserRegister(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: EmailStr | None = None
    password: Password


class UserUpdate(BaseModel):
    email: EmailStr | None = None
    password: Password | None = None

    @model_validator(mode="after")
    def check_not_empty(self):
        if self.email is None and self.password is None:
            raise ValueError("At least one of 'email' or 'password' must be provided")
        return self


class LoginRequest(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)
