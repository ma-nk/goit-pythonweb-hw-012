import unittest
from unittest.mock import MagicMock
from sqlalchemy.orm import Session
from src.repository.users import (
    get_user_by_email,
    create_user,
    update_token,
    confirmed_email,
    update_email,
    update_avatar,
    update_password
)
from src.schemas.user import UserModel
from src.models.user import User


class TestUsers(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.session = MagicMock(spec=Session)
        self.user = User(id=1, username="test_user", email="test@example.com", password="password", avatar="avatar_url")

    async def test_get_user_by_email(self):
        self.session.query().filter().first.return_value = self.user
        result = await get_user_by_email(self.user.email, self.session)
        self.assertEqual(result, self.user)

    async def test_create_user(self):
        body = UserModel(username="new_user", email="new@example.com", password="new_passwo")
        self.session.query().filter().first.return_value = None
        self.session.add.return_value = None
        self.session.commit.return_value = None
        self.session.refresh.return_value = None
        result = await create_user(body, self.session)
        self.assertEqual(result.username, body.username)
        self.assertEqual(result.email, body.email)
        self.assertTrue(hasattr(result, "id"))

    async def test_update_token(self):
        token = "new_refresh_token"
        await update_token(self.user, token, self.session)
        self.assertEqual(self.user.refresh_token, token)
        self.session.commit.assert_called_once()

    async def test_confirmed_email(self):
        self.session.query().filter().first.return_value = self.user
        await confirmed_email(self.user.email, self.session)
        self.assertTrue(self.user.confirmed)
        self.session.commit.assert_called_once()

    async def test_update_email(self):
        new_email = "new_test@example.com"
        await update_email(self.user, new_email, self.session)
        self.assertEqual(self.user.email, new_email)
        self.assertFalse(self.user.confirmed)
        self.session.commit.assert_called_once()
    
    async def test_update_avatar(self):
        new_avatar_url = "new_avatar_url"
        self.session.query().filter().first.return_value = self.user
        result = await update_avatar(self.user.email, new_avatar_url, self.session)
        self.assertEqual(result.avatar, new_avatar_url)
        self.session.commit.assert_called_once()

    async def test_update_password(self):
        new_password = "new_hashed_password"
        await update_password(self.user, new_password, self.session)
        self.assertEqual(self.user.password, new_password)
        self.session.commit.assert_called_once()
