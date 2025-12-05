import enum
from sqlalchemy import Column, Integer, String, Boolean, func, Enum
from sqlalchemy.orm import relationship
from sqlalchemy.sql.sqltypes import DateTime
from src.conf.base import Base


class Role(enum.Enum):
    admin: str = "admin"
    user: str = "user"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    created_at = Column(DateTime, default=func.now())
    avatar = Column(String, nullable=True)
    refresh_token = Column(String, nullable=True)
    confirmed = Column(Boolean, default=False)
    role = Column(Enum(Role), default=Role.user)
    contacts = relationship("Contact", back_populates="owner")
