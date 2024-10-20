from pydantic import BaseModel, EmailStr, Field
from typing import Annotated
from datetime import datetime

class UserAuth(BaseModel):
    email: EmailStr
    countryCode: Annotated[str, Field(pattern=r'^\+?[0-9]{1,3}$')]
    phone: Annotated[str, Field(pattern=r'^[0-9]{6,14}$')]  # E.164 phone number format
    password: Annotated[str, Field(min_length=8)]  # Minimum length for password

class UserProfile(BaseModel):
    user_id: str
    gender: str
    age: int
    location: str
    social_class: str

class SurveyResponse(BaseModel):
    user_id: str
    survey_id: str
    answers: dict

class Token(BaseModel):
    access_token: str
    token_type: str