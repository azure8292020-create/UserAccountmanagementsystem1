from sqlalchemy import Column, Integer, String, Boolean
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String)
    last_name = Column(String)
    middle_name = Column(String, nullable=True)
    ad_account_id = Column(String, unique=True, index=True)
    rsa_token_id = Column(String)
    home_location = Column(String)
    question_1 = Column(String)
    answer_1 = Column(String)
    question_2 = Column(String)
    answer_2 = Column(String)
    question_3 = Column(String)
    answer_3 = Column(String)
    is_approved = Column(Boolean, default=False)


from sqlalchemy import DateTime, ForeignKey
from datetime import datetime
import secrets

class RegistrationCode(Base):
    __tablename__ = "registration_codes"
    id = Column(Integer, primary_key=True, index=True)
    code = Column(String, unique=True, index=True, nullable=False, default=lambda: secrets.token_urlsafe(16))
    ad_account_id = Column(String, nullable=False)  # Now required
    used = Column(Boolean, default=False)
    used_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    used_at = Column(DateTime, nullable=True)
    created_by = Column(String, nullable=False)  # Store admin username who generated the code
    notes = Column(String, nullable=True)  # Optional notes about the code generation
