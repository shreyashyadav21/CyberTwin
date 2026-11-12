from typing import Optional
from pydantic import BaseModel, Field

class OrganizationSchema(BaseModel):
    id: str
    name: str
    industry: str
    description: str
    created_at: str

class OrganizationCreateSchema(BaseModel):
    name: str
    industry: Optional[str] = "Higher Education"
    description: Optional[str] = ""

