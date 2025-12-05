import pytest
import pytest_asyncio
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from src.main import app
from src.conf.db import get_db
from src.models.user import User, Role
from src.services.auth import auth_service

client = TestClient(app)


@pytest.fixture()
def session():
    return MagicMock(spec=Session)


@pytest_asyncio.fixture()
async def user():
    return User(id=1, username="test_user", email="test@example.com", password="hashed_password", confirmed=True, role=Role.user, avatar="http://example.com/avatar.jpg")


@pytest.fixture()
def token():
    # This fixture now returns a static access token string for direct use in headers
    return "test_access_token"


@pytest.mark.asyncio
async def test_read_root():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Hello World"}


@pytest.mark.asyncio
async def test_signup_user(session, user):
    with patch("src.repository.users.get_user_by_email", return_value=None):
        with patch("src.repository.users.create_user", return_value=User(id=1, email="test@example.com", username="test_user", avatar="http://example.com/avatar.jpg", role=Role.user)):
            with patch("src.services.email.send_email", return_value=None):
                with patch("src.services.auth.auth_service.get_password_hash", return_value="hashed_password"):
                    response = client.post(
                        "/api/auth/signup",
                        json={"username": "test_user", "email": "test@example.com", "password": "testpass"},
                    )
                    assert response.status_code == 201
                    data = response.json()
                    assert data["user"]["email"] == "test@example.com"
                    assert data["detail"] == "User successfully created"


@pytest.mark.asyncio
async def test_login_user(session, user):
    with patch("src.repository.users.get_user_by_email", return_value=user):
        with patch("src.services.auth.auth_service.verify_password", return_value=True):
            with patch("src.services.auth.auth_service.create_access_token", return_value="mock_access_token"):
                with patch("src.services.auth.auth_service.create_refresh_token", return_value="mock_refresh_token"):
                    with patch("src.repository.users.update_token", return_value=None):
                        response = client.post(
                            "/api/auth/login",
                            data={"username": "test@example.com", "password": "testpass"},
                        )
                        assert response.status_code == 200
                        data = response.json()
                        assert data["access_token"] == "mock_access_token"
                        assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_login_wrong_password(session, user):
    with patch("src.repository.users.get_user_by_email", return_value=user):
        with patch("src.services.auth.auth_service.verify_password", return_value=False):
            response = client.post(
                "/api/auth/login",
                data={"username": "test@example.com", "password": "wrong_pass"},
            )
            assert response.status_code == 401
            assert response.json() == {"detail": "Invalid password"}


@pytest.mark.asyncio
async def test_login_unconfirmed_email(session, user):
    user.confirmed = False
    with patch("src.repository.users.get_user_by_email", return_value=user):
        with patch("src.services.auth.auth_service.verify_password", return_value=True):
            response = client.post(
                "/api/auth/login",
                data={"username": "test@example.com", "password": "testpass"},
            )
            assert response.status_code == 401
            assert response.json() == {"detail": "Email not confirmed"}


@pytest.mark.asyncio
async def test_refresh_token(session, user):
    refresh_token_string = "mock_refresh_token"
    with patch("src.services.auth.oauth2_scheme", return_value="new_mock_access_token"):
        with patch("src.services.auth.auth_service.decode_refresh_token", return_value=user.email):
            with patch("src.repository.users.get_user_by_email", return_value=user):
                user.refresh_token = refresh_token_string  # User's stored refresh token matches the one in the cookie
                with patch("src.services.auth.auth_service.create_access_token", return_value="new_mock_access_token"):
                    with patch("src.services.auth.auth_service.create_refresh_token", return_value="new_mock_refresh_token"):
                        with patch("src.repository.users.update_token", return_value=None):
                            response = client.get(
                                "/api/auth/refresh_token",
                                cookies={'refresh_token': refresh_token_string},
                            )
                            assert response.status_code == 200
                            data = response.json()
                            assert data["access_token"] == "new_mock_access_token"
                            assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_confirmed_email_success(session, user):
    with patch("src.services.auth.auth_service.get_email_from_token", return_value=user.email):
        with patch("src.repository.users.get_user_by_email", return_value=user):
            user.confirmed = False  # Ensure user is not confirmed initially
            with patch("src.repository.users.confirmed_email", return_value=None):
                response = client.get(f"/api/auth/confirmed_email/some_token")
                assert response.status_code == 200
                assert response.json() == {"message": "Email confirmed"}


@pytest.mark.asyncio
async def test_confirmed_email_already_confirmed(session, user):
    with patch("src.services.auth.auth_service.get_email_from_token", return_value=user.email):
        with patch("src.repository.users.get_user_by_email", return_value=user):
            user.confirmed = True  # Ensure user is already already confirmed
            response = client.get(f"/api/auth/confirmed_email/some_token")
            assert response.status_code == 200
            assert response.json() == {"message": "Your email is already confirmed"}


@pytest.mark.asyncio
async def test_request_reset_password(session, user):
    with patch("src.repository.users.get_user_by_email", return_value=user):
        with patch("src.services.email.send_email", return_value=None):
            response = client.post(
                "/api/auth/request_reset_password",
                json={"email": user.email},
            )
            assert response.status_code == 200
            assert response.json() == {"message": "Check your email for password reset instructions."}


@pytest.mark.asyncio
async def test_reset_password(session, user):
    with patch("src.services.auth.auth_service.get_email_from_token", return_value=user.email):
        with patch("src.repository.users.get_user_by_email", return_value=user):
            with patch("src.services.auth.auth_service.get_password_hash", return_value="new_hashed_password"):
                with patch("src.repository.users.update_password", return_value=None):
                    response = client.post(
                        "/api/auth/reset_password",
                        json={"token": "some_token", "new_password": "new_passwo"},
                    )
                    assert response.status_code == 200
                    assert response.json() == {"message": "Password successfully updated."}
