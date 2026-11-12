from pydantic import BaseModel, Field
from typing import Optional

class UserCreateSchema(BaseModel):
    email: str = Field(..., min_length=3, max_length=120)
    password: str = Field(..., min_length=6)
    full_name: Optional[str] = ""
    role: Optional[str] = "Analyst"

class UserLoginSchema(BaseModel):
    email: str
    password: str

class TokenSchema(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: str
    email: str
    full_name: str
    role: str

class UserResponseSchema(BaseModel):
    id: str
    email: str
    full_name: str
    role: str
    is_active: bool

