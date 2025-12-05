from sqlalchemy.orm import Session
from src.models.contact import Contact
from src.schemas.contact import ContactCreate, ContactUpdate
from datetime import date, timedelta
from src.models.user import User


def get_contact(db: Session, contact_id: int, current_user: User):
    """
    Retrieves a single contact by its ID for a specific user.

    :param db: The database session.
    :type db: Session
    :param contact_id: The ID of the contact to retrieve.
    :type contact_id: int
    :param current_user: The currently authenticated user.
    :type current_user: User
    :return: The contact object if found, otherwise None.
    :rtype: Contact | None
    """
    return db.query(Contact).filter(Contact.id == contact_id, Contact.user_id == current_user.id).first()

def get_contacts(db: Session, skip: int, limit: int, first_name: str | None, last_name: str | None, email: str | None, current_user: User):
    """
    Retrieves a list of contacts for a specific user, with optional filtering and pagination.

    :param db: The database session.
    :type db: Session
    :param skip: The number of contacts to skip (for pagination).
    :type skip: int
    :param limit: The maximum number of contacts to return (for pagination).
    :type limit: int
    :param first_name: Optional filter by first name.
    :type first_name: str | None
    :param last_name: Optional filter by last name.
    :type last_name: str | None
    :param email: Optional filter by email.
    :type email: str | None
    :param current_user: The currently authenticated user.
    :type current_user: User
    :return: A list of contacts.
    :rtype: list[Contact]
    """
    query = db.query(Contact).filter(Contact.user_id == current_user.id)
    if first_name:
        query = query.filter(Contact.first_name.contains(first_name))
    if last_name:
        query = query.filter(Contact.last_name.contains(last_name))
    if email:
        query = query.filter(Contact.email.contains(email))
    return query.offset(skip).limit(limit).all()

def create_contact(db: Session, contact: ContactCreate, current_user: User):
    """
    Creates a new contact for the current user.

    :param db: The database session.
    :type db: Session
    :param contact: The contact data to create.
    :type contact: ContactCreate
    :param current_user: The currently authenticated user.
    :type current_user: User
    :return: The newly created contact.
    :rtype: Contact
    """
    db_contact = Contact(**contact.model_dump(), user_id=current_user.id)
    db.add(db_contact)
    db.commit()
    db.refresh(db_contact)
    return db_contact

def update_contact(db: Session, contact_id: int, contact: ContactUpdate, current_user: User):
    """
    Updates an existing contact by its ID for the current user.

    :param db: The database session.
    :type db: Session
    :param contact_id: The ID of the contact to update.
    :type contact_id: int
    :param contact: The updated contact data.
    :type contact: ContactUpdate
    :param current_user: The currently authenticated user.
    :type current_user: User
    :return: The updated contact object if found, otherwise None.
    :rtype: Contact | None
    """
    db_contact = db.query(Contact).filter(Contact.id == contact_id, Contact.user_id == current_user.id).first()
    if db_contact:
        for key, value in contact.model_dump().items():
            setattr(db_contact, key, value)
        db.commit()
        db.refresh(db_contact)
    return db_contact

def delete_contact(db: Session, contact_id: int, current_user: User):
    """
    Deletes a contact by its ID for the current user.

    :param db: The database session.
    :type db: Session
    :param contact_id: The ID of the contact to delete.
    :type contact_id: int
    :param current_user: The currently authenticated user.
    :type current_user: User
    :return: The deleted contact object if found, otherwise None.
    :rtype: Contact | None
    """
    db_contact = db.query(Contact).filter(Contact.id == contact_id, Contact.user_id == current_user.id).first()
    if db_contact:
        db.delete(db_contact)
        db.commit()
    return db_contact

def get_upcoming_birthdays(db: Session, current_user: User):
    """
    Retrieves a list of contacts with upcoming birthdays for the current user.

    This function calculates birthdays within the next 7 days, considering leap years.

    :param db: The database session.
    :type db: Session
    :param current_user: The currently authenticated user.
    :type current_user: User
    :return: A list of contacts with upcoming birthdays.
    :rtype: list[Contact]
    """
    today = date.today()
    end_date = today + timedelta(days=7)
    return db.query(Contact).filter(
        Contact.birthday.between(today, end_date),
        Contact.user_id == current_user.id
    ).all()
