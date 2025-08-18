from pydantic import BaseModel
from typing import Optional

class UserBase(BaseModel):
    first_name: str
    last_name: str
    middle_name: Optional[str] = None
    ad_account_id: Optional[str] = None
    rsa_token_id: str
    home_location: str
    question_1: str
    answer_1: str
    question_2: str
    answer_2: str
    question_3: str
    answer_3: str

class UserCreate(UserBase):
    pass

class UserOut(UserBase):
    id: int
    is_approved: bool

    class Config:
        orm_mode = True
