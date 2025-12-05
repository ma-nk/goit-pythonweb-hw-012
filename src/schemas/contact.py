from pydantic import BaseModel, EmailStr, ConfigDict
from datetime import date
from src.schemas.user import UserDb

class ContactBase(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    phone_number: str
    birthday: date
    additional_data: str | None = None

class ContactCreate(ContactBase):
    pass

class ContactUpdate(ContactBase):
    pass

class Contact(ContactBase):
    id: int
    owner: UserDb

    model_config = ConfigDict(from_attributes=True)
