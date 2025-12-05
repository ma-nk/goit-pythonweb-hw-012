import unittest
from unittest.mock import MagicMock
from datetime import date, timedelta

from sqlalchemy.orm import Session

from src.repository.contacts import (
    get_contact,
    get_contacts,
    create_contact,
    update_contact,
    delete_contact,
    get_upcoming_birthdays
)
from src.schemas.contact import ContactCreate, ContactUpdate
from src.models.contact import Contact
from src.models.user import User


class TestContacts(unittest.TestCase):

    def setUp(self):
        self.session = MagicMock(spec=Session)
        self.user = User(id=1, username="test_user", email="test@example.com", password="password", confirmed=True)
        self.contact = Contact(id=1, first_name="John", last_name="Doe", email="john.doe@example.com",
                               phone_number="1234567890", birthday=date(2000, 1, 1), user_id=self.user.id)

        # Mock SQLAlchemy query chain
        self.mock_query = MagicMock()
        self.mock_filter = MagicMock()
        self.mock_offset = MagicMock()
        self.mock_limit = MagicMock()

        self.session.query.return_value = self.mock_query
        self.mock_query.filter.return_value = self.mock_filter
        self.mock_filter.first.return_value = None  # Default
        self.mock_filter.all.return_value = []      # Default
        self.mock_filter.offset.return_value = self.mock_offset
        self.mock_offset.limit.return_value = self.mock_limit
        self.mock_limit.all.return_value = []        # Default


    def test_get_contact_found(self):
        self.mock_filter.first.return_value = self.contact
        result = get_contact(self.session, self.contact.id, self.user)
        self.assertEqual(result, self.contact)

    def test_get_contact_not_found(self):
        self.mock_filter.first.return_value = None
        result = get_contact(self.session, 999, self.user)
        self.assertIsNone(result)

    def test_get_contacts(self):
        self.mock_limit.all.return_value = [self.contact]
        result = get_contacts(self.session, skip=0, limit=10, first_name=None, last_name=None, email=None, current_user=self.user)
        self.assertEqual(result, [self.contact])

    def test_create_contact(self):
        body = ContactCreate(first_name="Jane", last_name="Smith", email="jane.smith@example.com",
                             phone_number="0987654321", birthday=date(2001, 2, 2))
        self.session.add.return_value = None
        self.session.commit.return_value = None
        self.session.refresh.return_value = None
        result = create_contact(self.session, body, self.user)
        self.assertEqual(result.first_name, body.first_name)
        self.assertEqual(result.email, body.email)
        self.assertTrue(hasattr(result, "id"))

    def test_update_contact_found(self):
        body = ContactUpdate(first_name="UpdatedJohn", last_name="Doe", email="updated.john.doe@example.com",
                             phone_number="1112223333", birthday=date(2000, 1, 1))
        self.mock_filter.first.return_value = self.contact
        self.session.commit.return_value = None
        self.session.refresh.return_value = None
        result = update_contact(self.session, self.contact.id, body, self.user)
        self.assertEqual(result.first_name, body.first_name)
        self.assertEqual(result.email, body.email)

    def test_update_contact_not_found(self):
        self.mock_filter.first.return_value = None
        body = ContactUpdate(first_name="UpdatedJohn", last_name="Doe", email="updated.john.doe@example.com",
                             phone_number="1112223333", birthday=date(2000, 1, 1))
        result = update_contact(self.session, 999, body, self.user)
        self.assertIsNone(result)

    def test_delete_contact_found(self):
        self.mock_filter.first.return_value = self.contact
        self.session.delete.return_value = None
        self.session.commit.return_value = None
        result = delete_contact(self.session, self.contact.id, self.user)
        self.assertEqual(result, self.contact)

    def test_delete_contact_not_found(self):
        self.mock_filter.first.return_value = None
        result = delete_contact(self.session, 999, self.user)
        self.assertIsNone(result)

    def test_get_upcoming_birthdays(self):
        today = date.today()
        upcoming_contact = Contact(id=2, first_name="Upcoming", last_name="Birthday", email="upcoming@example.com",
                                   phone_number="1234567890", birthday=today + timedelta(days=5), user_id=self.user.id)
        self.mock_filter.all.return_value = [upcoming_contact]
        result = get_upcoming_birthdays(self.session, self.user)
        self.assertEqual(result, [upcoming_contact])