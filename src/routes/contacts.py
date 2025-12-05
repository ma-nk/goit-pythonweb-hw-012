from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from src.repository import contacts as repository_contacts
from src.schemas.contact import Contact, ContactCreate, ContactUpdate
from src.conf.db import get_db
from src.services.auth import auth_service
from src.models.user import User

router = APIRouter(prefix="/contacts", tags=["contacts"])

@router.post("/", response_model=Contact, status_code=status.HTTP_201_CREATED)
def create_contact(contact: ContactCreate, db: Session = Depends(get_db), current_user: User = Depends(auth_service.get_current_user)):
    """
    Create a new contact for the current user.

    :param contact: The contact data to create.
    :type contact: ContactCreate
    :param db: The database session.
    :type db: Session
    :param current_user: The currently authenticated user.
    :type current_user: User
    :return: The newly created contact.
    :rtype: Contact
    """
    return repository_contacts.create_contact(db=db, contact=contact, current_user=current_user)

@router.get("/", response_model=list[Contact])
def read_contacts(skip: int = 0, limit: int = 100, first_name: str | None = None, last_name: str | None = None, email: str | None = None, db: Session = Depends(get_db), current_user: User = Depends(auth_service.get_current_user)):
    """
    Retrieve a list of contacts for the current user, with optional filtering and pagination.

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
    :param db: The database session.
    :type db: Session
    :param current_user: The currently authenticated user.
    :type current_user: User
    :return: A list of contacts.
    :rtype: list[Contact]
    """
    contacts = repository_contacts.get_contacts(db, skip=skip, limit=limit, first_name=first_name, last_name=last_name, email=email, current_user=current_user)
    return contacts

@router.get("/birthdays", response_model=list[Contact])
def upcoming_birthdays(db: Session = Depends(get_db), current_user: User = Depends(auth_service.get_current_user)):
    """
    Retrieve a list of contacts with upcoming birthdays for the current user.

    :param db: The database session.
    :type db: Session
    :param current_user: The currently authenticated user.
    :type current_user: User
    :return: A list of contacts with upcoming birthdays.
    :rtype: list[Contact]
    """
    contacts = repository_contacts.get_upcoming_birthdays(db, current_user=current_user)
    return contacts

@router.get("/{contact_id}", response_model=Contact)
def read_contact(contact_id: int, db: Session = Depends(get_db), current_user: User = Depends(auth_service.get_current_user)):
    """
    Retrieve a single contact by its ID for the current user.

    :param contact_id: The ID of the contact to retrieve.
    :type contact_id: int
    :param db: The database session.
    :type db: Session
    :param current_user: The currently authenticated user.
    :type current_user: User
    :raises HTTPException: 404 Not Found if the contact does not exist.
    :return: The retrieved contact.
    :rtype: Contact
    """
    db_contact = repository_contacts.get_contact(db, contact_id=contact_id, current_user=current_user)
    if db_contact is None:
        raise HTTPException(status_code=404, detail="Contact not found")
    return db_contact

@router.put("/{contact_id}", response_model=Contact)
def update_contact(contact_id: int, contact: ContactUpdate, db: Session = Depends(get_db), current_user: User = Depends(auth_service.get_current_user)):
    """
    Update an existing contact by its ID for the current user.

    :param contact_id: The ID of the contact to update.
    :type contact_id: int
    :param contact: The updated contact data.
    :type contact: ContactUpdate
    :param db: The database session.
    :type db: Session
    :param current_user: The currently authenticated user.
    :type current_user: User
    :raises HTTPException: 404 Not Found if the contact does not exist.
    :return: The updated contact.
    :rtype: Contact
    """
    db_contact = repository_contacts.update_contact(db, contact_id=contact_id, contact=contact, current_user=current_user)
    if db_contact is None:
        raise HTTPException(status_code=404, detail="Contact not found")
    return db_contact

@router.delete("/{contact_id}", response_model=Contact)
def delete_contact(contact_id: int, db: Session = Depends(get_db), current_user: User = Depends(auth_service.get_current_user)):
    """
    Delete a contact by its ID for the current user.

    :param contact_id: The ID of the contact to delete.
    :type contact_id: int
    :param db: The database session.
    :type db: Session
    :param current_user: The currently authenticated user.
    :type current_user: User
    :raises HTTPException: 404 Not Found if the contact does not exist.
    :return: The deleted contact.
    :rtype: Contact
    """
    db_contact = repository_contacts.delete_contact(db, contact_id=contact_id, current_user=current_user)
    if db_contact is None:
        raise HTTPException(status_code=404, detail="Contact not found")
    return db_contact