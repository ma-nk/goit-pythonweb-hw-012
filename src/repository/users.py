from sqlalchemy.orm import Session

from src.models.user import User
from src.schemas.user import UserModel
from libgravatar import Gravatar

async def get_user_by_email(email: str, db: Session) -> User:
    """
    Retrieves a user by their email address.

    :param email: The email address of the user to retrieve.
    :type email: str
    :param db: The database session.
    :type db: Session
    :return: The user object if found, otherwise None.
    :rtype: User
    """
    return db.query(User).filter(User.email == email).first()


async def create_user(body: UserModel, db: Session) -> User:
    """
    Creates a new user in the database.

    :param body: The user data to create.
    :type body: UserModel
    :param db: The database session.
    :type db: Session
    :return: The newly created user object.
    :rtype: User
    """
    try:
        g = Gravatar(body.email)
        avatar = g.get_image()
    except Exception as e:
        print(e)
        avatar = None
    new_user = User(**body.dict(), avatar=avatar)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


async def update_token(user: User, token: str | None, db: Session) -> None:
    """
    Updates the refresh token for a user.

    :param user: The user object to update.
    :type user: User
    :param token: The new refresh token, or None to clear it.
    :type token: str | None
    :param db: The database session.
    :type db: Session
    :return: None
    """
    user.refresh_token = token
    db.commit()


async def confirmed_email(email: str, db: Session) -> None:
    """
    Marks a user's email as confirmed.

    :param email: The email address of the user to confirm.
    :type email: str
    :param db: The database session.
    :type db: Session
    :return: None
    """
    user = await get_user_by_email(email, db)
    user.confirmed = True
    db.commit()


async def update_email(user: User, new_email: str, db: Session) -> None:
    """
    Updates a user's email address and sets their confirmation status to False.

    :param user: The user object to update.
    :type user: User
    :param new_email: The new email address.
    :type new_email: str
    :param db: The database session.
    :type db: Session
    :return: None
    """
    user.email = new_email
    user.confirmed = False
    db.commit()


async def update_avatar(email, url: str, db: Session) -> User:
    """
    Updates a user's avatar URL.

    :param email: The email address of the user.
    :type email: str
    :param url: The new avatar URL.
    :type url: str
    :param db: The database session.
    :type db: Session
    :return: The updated user object.
    :rtype: User
    """
    user = await get_user_by_email(email, db)
    user.avatar = url
    db.commit()
    return user


async def update_password(user: User, password: str, db: Session) -> None:
    """
    Updates a user's password.

    :param user: The user object to update.
    :type user: User
    :param password: The new hashed password.
    :type password: str
    :param db: The database session.
    :type db: Session
    :return: None
    """
    user.password = password
    db.commit()
