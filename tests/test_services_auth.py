import unittest
from unittest.mock import MagicMock, patch
from datetime import datetime, timedelta, timezone
import json

from jose import JWTError, jwt
from fastapi import HTTPException, status, Depends
from passlib.context import CryptContext
from sqlalchemy.orm import Session
import redis

from src.services.auth import Auth, auth_service
from src.models.user import User, Role
from src.conf.config import settings
from src.repository import users as repository_users
from src.schemas.user import UserDb


class TestAuthService(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        # Patch Auth.pwd_context to ensure bcrypt backend is used correctly
        with patch('src.services.auth.Auth.pwd_context', self.pwd_context):
            self.auth = Auth()
            # Generate a bcrypt-compatible hashed password
            hashed_password = self.auth.get_password_hash("testpass")
            self.user = User(id=1, username="test_user", email="test@example.com", password=hashed_password,
                             confirmed=True, role=Role.user, avatar="http://example.com/avatar.jpg",
                             refresh_token="test_refresh_token")
            self.session = MagicMock(spec=Session)

            # Patch settings for JWT
            patcher_secret = patch('src.services.auth.settings.secret_key', "super_secret_key")
            patcher_algorithm = patch('src.services.auth.settings.algorithm', "HS256")
            patcher_redis_host = patch('src.services.auth.settings.redis_host', "localhost")
            patcher_redis_port = patch('src.services.auth.settings.redis_port', 6379)

            self.mock_secret = patcher_secret.start()
            self.mock_algorithm = patcher_algorithm.start()
            self.mock_redis_host = patcher_redis_host.start()
            self.mock_redis_port = patcher_redis_port.start()

            self.addCleanup(patcher_secret.stop)
            self.addCleanup(patcher_algorithm.stop)
            self.addCleanup(patcher_redis_host.stop)
            self.addCleanup(patcher_redis_port.stop)

            # Patch Redis methods
            self.patch_redis_get = patch('src.services.auth.Auth.r.get', return_value=None)
            self.mock_redis_get = self.patch_redis_get.start()
            self.addCleanup(self.patch_redis_get.stop)

            self.patch_redis_set = patch('src.services.auth.Auth.r.set', return_value=None)
            self.mock_redis_set = self.patch_redis_set.start()
            self.addCleanup(self.patch_redis_set.stop)

    def test_verify_password(self):
        plain_password = "testpass"
        hashed_password = self.auth.get_password_hash(plain_password)
        self.assertTrue(self.auth.verify_password(plain_password, hashed_password))
        self.assertFalse(self.auth.verify_password("wrongpass", hashed_password))

    def test_get_password_hash(self):
        password = "testpass"
        hashed_password = self.auth.get_password_hash(password)
        self.assertIsNotNone(hashed_password)
        self.assertTrue(self.auth.verify_password(password, hashed_password))

    async def test_create_access_token(self):
        data = {"sub": self.user.email, "scope": "access_token"}
        token = await self.auth.create_access_token(data)
        self.assertIsNotNone(token)
        # Verify if the token can be decoded (basic check)
        decoded = jwt.decode(token, self.auth.SECRET_KEY, algorithms=[self.auth.ALGORITHM])
        self.assertEqual(decoded["sub"], self.user.email)
        self.assertEqual(decoded["scope"], "access_token")

    async def test_create_refresh_token(self):
        data = {"sub": self.user.email, "scope": "refresh_token"}
        token = await self.auth.create_refresh_token(data)
        self.assertIsNotNone(token)
        # Verify if the token can be decoded (basic check)
        decoded = jwt.decode(token, self.auth.SECRET_KEY, algorithms=[self.auth.ALGORITHM])
        self.assertEqual(decoded["sub"], self.user.email)
        self.assertEqual(decoded["scope"], "refresh_token")

    async def test_decode_refresh_token_valid(self):
        refresh_token = await self.auth.create_refresh_token({"sub": self.user.email, "scope": "refresh_token"})
        email = await self.auth.decode_refresh_token(refresh_token)
        self.assertEqual(email, self.user.email)

    async def test_decode_refresh_token_invalid_scope(self):
        access_token = await self.auth.create_access_token({"sub": self.user.email, "scope": "access_token"})
        with self.assertRaises(HTTPException) as cm:
            await self.auth.decode_refresh_token(access_token)
        self.assertEqual(cm.exception.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(cm.exception.detail, 'Invalid scope for token')

    async def test_decode_refresh_token_expired(self):
        expired_token = jwt.encode({"sub": self.user.email, "scope": "refresh_token", "exp": datetime.now(timezone.utc) - timedelta(days=1)}, self.auth.SECRET_KEY, algorithm=self.auth.ALGORITHM)
        with self.assertRaises(HTTPException) as cm:
            await self.auth.decode_refresh_token(expired_token)
        self.assertEqual(cm.exception.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(cm.exception.detail, 'Could not validate credentials')

    @patch('src.repository.users.get_user_by_email')
    async def test_get_current_user_valid_token(self, mock_get_user_by_email):
        mock_get_user_by_email.return_value = self.user
        access_token = await self.auth.create_access_token({"sub": self.user.email, "scope": "access_token"})

        result = await self.auth.get_current_user(token=access_token, db=self.session)
        self.assertEqual(result.email, self.user.email)
        self.mock_redis_get.assert_called_with(f"user:{self.user.email}")
        self.mock_redis_set.assert_called_with(f"user:{self.user.email}", json.dumps(UserDb.model_validate(self.user).model_dump(), default=str), ex=3600)

    @patch('src.repository.users.get_user_by_email')
    async def test_get_current_user_invalid_scope(self, mock_get_user_by_email):
        refresh_token = await self.auth.create_refresh_token({"sub": self.user.email, "scope": "refresh_token"})
        with self.assertRaises(HTTPException) as cm:
            await self.auth.get_current_user(token=refresh_token, db=self.session)
        self.assertEqual(cm.exception.status_code, status.HTTP_401_UNAUTHORIZED)

    @patch('src.repository.users.get_user_by_email')
    async def test_get_current_user_user_not_found(self, mock_get_user_by_email):
        mock_get_user_by_email.return_value = None
        access_token = await self.auth.create_access_token({"sub": "nonexistent@example.com", "scope": "access_token"})

        with self.assertRaises(HTTPException) as cm:
            await self.auth.get_current_user(token=access_token, db=self.session)
        self.assertEqual(cm.exception.status_code, status.HTTP_401_UNAUTHORIZED)

    @patch('src.repository.users.get_user_by_email')
    async def test_allowed_roles_admin_success(self, mock_get_user_by_email):
        admin_user = User(id=1, username="admin_user", email="admin@example.com", password="hashed_password",
                          confirmed=True, role=Role.admin, avatar="http://example.com/avatar.jpg")
        mock_get_user_by_email.return_value = admin_user

        @self.auth.allowed_roles([Role.admin])
        async def protected_route(current_user: User = Depends(self.auth.get_current_user), db: Session = Depends()):
            return {"message": "Access granted"}
        
        # Mock get_current_user directly for the decorator's internal call
        with patch('src.services.auth.auth_service.get_current_user', return_value=admin_user):
            result = await protected_route(current_user=admin_user, db=self.session)
            self.assertEqual(result, {"message": "Access granted"})

    @patch('src.repository.users.get_user_by_email')
    async def test_allowed_roles_user_forbidden(self, mock_get_user_by_email):
        user_obj = User(id=1, username="user_user", email="user@example.com", password="hashed_password",
                        confirmed=True, role=Role.user, avatar="http://example.com/avatar.jpg")
        mock_get_user_by_email.return_value = user_obj

        @self.auth.allowed_roles([Role.admin])
        async def protected_route(current_user: User = Depends(self.auth.get_current_user), db: Session = Depends()):
            return {"message": "Access granted"}
        
        with patch('src.services.auth.auth_service.get_current_user', return_value=user_obj):
            with self.assertRaises(HTTPException) as cm:
                await protected_route(current_user=user_obj, db=self.session)
            self.assertEqual(cm.exception.status_code, status.HTTP_403_FORBIDDEN)
            self.assertEqual(cm.exception.detail, "Operation forbidden")

    async def test_create_email_token(self):
        data = {"sub": self.user.email}
        token = self.auth.create_email_token(data)
        self.assertIsNotNone(token)
        decoded = jwt.decode(token, self.auth.SECRET_KEY, algorithms=[self.auth.ALGORITHM])
        self.assertEqual(decoded["sub"], self.user.email)
        self.assertEqual(decoded["scope"], "email_token")

    async def test_get_email_from_token_valid(self):
        email_token = self.auth.create_email_token({"sub": self.user.email})
        email = await self.auth.get_email_from_token(email_token)
        self.assertEqual(email, self.user.email)

    async def test_get_email_from_token_invalid_scope(self):
        access_token = await self.auth.create_access_token({"sub": self.user.email, "scope": "access_token"})
        with self.assertRaises(HTTPException) as cm:
            await self.auth.get_email_from_token(access_token)
        self.assertEqual(cm.exception.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(cm.exception.detail, "Invalid scope for token")

    async def test_get_email_from_token_expired(self):
        expired_token = jwt.encode({"sub": self.user.email, "scope": "email_token", "exp": datetime.now(timezone.utc) - timedelta(days=1)}, self.auth.SECRET_KEY, algorithm=self.auth.ALGORITHM)
        with self.assertRaises(HTTPException) as cm:
            await self.auth.get_email_from_token(expired_token)
        self.assertEqual(cm.exception.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertEqual(cm.exception.detail, "Invalid token for email verification")
