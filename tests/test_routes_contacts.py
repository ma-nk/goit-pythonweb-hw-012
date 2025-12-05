import pytest
import pytest_asyncio
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from datetime import date

from src.main import app
from src.models.user import User, Role
from src.schemas.contact import Contact, ContactCreate, ContactUpdate
from src.schemas.user import UserDb
from src.services.auth import auth_service

client = TestClient(app)


@pytest.fixture()
def mock_secret_key():
    with patch("src.services.auth.auth_service.SECRET_KEY", "super_secret_key") as mock_key:
        yield mock_key


@pytest.fixture()
def mock_algorithm():
    with patch("src.services.auth.auth_service.ALGORITHM", "HS256") as mock_algo:
        yield mock_algo


@pytest.fixture()
def token(mock_secret_key, mock_algorithm, user):
    return "test_access_token"


@pytest_asyncio.fixture()
async def user():
    return User(id=1, username="test_user", email="test@example.com", password="hashed_password", confirmed=True, role=Role.user, avatar="http://example.com/avatar.jpg")


@pytest.fixture()
def session():
    return MagicMock(spec=Session)


@pytest.fixture()
def contact_create_body():
    return ContactCreate(first_name="John", last_name="Doe", email="john.doe@example.com", phone_number="1234567890", birthday=date(2000, 1, 1).isoformat())


@pytest.fixture()
def contact_update_body():
    return ContactUpdate(first_name="Jane", last_name="Doe", email="jane.doe@example.com", phone_number="0987654321", birthday=date(2001, 1, 1).isoformat())


@pytest.fixture()
def contact(user):
    return Contact(id=1, first_name="John", last_name="Doe", email="john.doe@example.com", phone_number="1234567890", birthday=date(2000, 1, 1).isoformat(), user_id=user.id, owner=UserDb(id=user.id, username=user.username, email=user.email, avatar=user.avatar, role=user.role))


@pytest.mark.asyncio
async def test_create_contact(session, user, contact_create_body, contact, token):
    app.dependency_overrides[auth_service.get_current_user] = lambda: user
    try:
        with patch("src.repository.contacts.create_contact", return_value=contact):
            response = client.post(
                "/api/contacts/",
                json=contact_create_body.model_dump(mode='json'),
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 201
            data = response.json()
            assert data["first_name"] == contact_create_body.first_name
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_read_contacts(session, user, contact, token):
    app.dependency_overrides[auth_service.get_current_user] = lambda: user
    try:
        with patch("src.repository.contacts.get_contacts", return_value=[contact]):
            response = client.get(
                "/api/contacts/",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 200
            data = response.json()
            assert len(data) == 1
            assert data[0]["first_name"] == contact.first_name
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_read_contact_found(session, user, contact, token):
    app.dependency_overrides[auth_service.get_current_user] = lambda: user
    try:
        with patch("src.repository.contacts.get_contact", return_value=contact):
            response = client.get(
                f"/api/contacts/{contact.id}",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 200
            data = response.json()
            assert data["first_name"] == contact.first_name
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_read_contact_not_found(session, user, token):
    app.dependency_overrides[auth_service.get_current_user] = lambda: user
    try:
        with patch("src.repository.contacts.get_contact", return_value=None):
            response = client.get(
                "/api/contacts/999",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 404
            assert response.json() == {"detail": "Contact not found"}
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_update_contact(session, user, contact_update_body, contact, token):
    app.dependency_overrides[auth_service.get_current_user] = lambda: user
    try:
        with patch("src.repository.contacts.update_contact", return_value=Contact(id=contact.id, **contact_update_body.model_dump(), user_id=user.id, owner=UserDb(id=user.id, username=user.username, email=user.email, avatar=user.avatar, role=user.role))):
            response = client.put(
                f"/api/contacts/{contact.id}",
                json=contact_update_body.model_dump(mode='json'),
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 200
            data = response.json()
            assert data["first_name"] == contact_update_body.first_name
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_update_contact_not_found(session, user, contact_update_body, token):
    app.dependency_overrides[auth_service.get_current_user] = lambda: user
    try:
        with patch("src.repository.contacts.update_contact", return_value=None):
            response = client.put(
                "/api/contacts/999",
                json=contact_update_body.model_dump(mode='json'),
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 404
            assert response.json() == {"detail": "Contact not found"}
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_delete_contact(session, user, contact, token):
    app.dependency_overrides[auth_service.get_current_user] = lambda: user
    try:
        with patch("src.repository.contacts.delete_contact", return_value=contact):
            response = client.delete(
                f"/api/contacts/{contact.id}",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 200
            data = response.json()
            assert data["first_name"] == contact.first_name
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_delete_contact_not_found(session, user, token):
    app.dependency_overrides[auth_service.get_current_user] = lambda: user
    try:
        with patch("src.repository.contacts.delete_contact", return_value=None):
            response = client.delete(
                "/api/contacts/999",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 404
            assert response.json() == {"detail": "Contact not found"}
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_upcoming_birthdays(session, user, contact, token):
    app.dependency_overrides[auth_service.get_current_user] = lambda: user
    try:
        with patch("src.repository.contacts.get_upcoming_birthdays", return_value=[contact]):
            response = client.get(
                "/api/contacts/birthdays",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 200
            data = response.json()
            assert len(data) == 1
            assert data[0]["first_name"] == contact.first_name
    finally:
        app.dependency_overrides.clear()