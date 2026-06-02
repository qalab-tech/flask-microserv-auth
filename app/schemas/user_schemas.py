from datetime import datetime

from pydantic import BaseModel, EmailStr, Field
from typing import Optional

class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: Optional[EmailStr] = None

class UserRegister(UserBase):
    password: str = Field(..., min_length=6)

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    password: Optional[str] = Field(None, min_length=6)

class UserResponse(BaseModel):
    id: int
    username: str
    email: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True
        json_encoders = {
            datetime: lambda v: v.isoformat()   # ← вот это главное
        }


class UserListResponse(BaseModel):
    users: list[UserResponse]
    total: int