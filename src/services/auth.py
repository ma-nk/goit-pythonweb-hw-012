from typing import Optional
import json

from jose import JWTError, jwt
from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
import redis

from src.conf.config import settings
from src.repository import users as repository_users
from src.conf.db import get_db
from src.models.user import Role, User
from src.schemas.user import UserDb

# Defined globally to avoid circular dependency in Auth class
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


class Auth:
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    SECRET_KEY = settings.secret_key
    ALGORITHM = settings.algorithm
    # Removed oauth2_scheme from here
    r = redis.Redis(host=settings.redis_host, port=settings.redis_port, db=0)

    def verify_password(self, plain_password, hashed_password):
        """
        Verifies a plain-text password against a hashed password.

        :param plain_password: The plain-text password.
        :type plain_password: str
        :param hashed_password: The hashed password.
        :type hashed_password: str
        :return: True if the passwords match, False otherwise.
        :rtype: bool
        """
        return self.pwd_context.verify(plain_password, hashed_password)

    def get_password_hash(self, password: str):
        """
        Hashes a plain-text password.

        :param password: The plain-text password.
        :type password: str
        :return: The hashed password.
        :rtype: str
        """
        return self.pwd_context.hash(password)

    async def create_access_token(self, data: dict, expires_delta: Optional[float] = None):
        """
        Creates a new access token.

        :param data: The data to encode into the token (e.g., user email, scope).
        :type data: dict
        :param expires_delta: Optional expiry time in seconds. Defaults to 10 minutes.
        :type expires_delta: Optional[float]
        :return: The encoded access token.
        :rtype: str
        """
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.now(timezone.utc) + timedelta(seconds=expires_delta)
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=10)
        to_encode.update({"exp": expire})
        encoded_access_token = jwt.encode(to_encode, self.SECRET_KEY, algorithm=self.ALGORITHM)
        return encoded_access_token

    async def create_refresh_token(self, data: dict, expires_delta: Optional[float] = None):
        """
        Creates a new refresh token.

        :param data: The data to encode into the token (e.g., user email, scope).
        :type data: dict
        :param expires_delta: Optional expiry time in seconds. Defaults to 7 days.
        :type expires_delta: Optional[float]
        :return: The encoded refresh token.
        :rtype: str
        """
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.now(timezone.utc) + timedelta(seconds=expires_delta)
        else:
            expire = datetime.now(timezone.utc) + timedelta(days=7)
        to_encode.update({"exp": expire})
        encoded_refresh_token = jwt.encode(to_encode, self.SECRET_KEY, algorithm=self.ALGORITHM)
        return encoded_refresh_token

    async def decode_refresh_token(self, refresh_token: str):
        """
        Decodes a refresh token and returns the user's email.

        :param refresh_token: The refresh token to decode.
        :type refresh_token: str
        :raises HTTPException: 401 Unauthorized if the token is invalid or has an invalid scope.
        :return: The email extracted from the token.
        :rtype: str
        """
        try:
            payload = jwt.decode(refresh_token, self.SECRET_KEY, algorithms=[self.ALGORITHM])
            if payload['scope'] == 'refresh_token':
                email = payload['sub']
                return email
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid scope for token')
        except JWTError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Could not validate credentials')

    async def get_current_user(self, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
        """
        Retrieves the current authenticated user from the access token.

        :param token: The access token from the request header.
        :type token: str
        :param db: The database session.
        :type db: Session
        :raises HTTPException: 401 Unauthorized if credentials cannot be validated.
        :return: The authenticated user object.
        :rtype: User
        """
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

        try:
            payload = jwt.decode(token, self.SECRET_KEY, algorithms=[self.ALGORITHM])
            if payload['scope'] == 'access_token':
                email = payload["sub"]
                if email is None:
                    raise credentials_exception
            else:
                raise credentials_exception
        except JWTError as e:
            raise credentials_exception
        
        user = self.r.get(f"user:{email}")
        if user is None:
            user = await repository_users.get_user_by_email(email, db)
            if user is None:
                raise credentials_exception
            self.r.set(f"user:{email}", json.dumps(UserDb.model_validate(user).model_dump(), default=str), ex=3600)
        else:
            user = User(**json.loads(user))

        return user

    def allowed_roles(self, roles: list[Role]):
        """
        Decorator to restrict access to an endpoint based on user roles.

        :param roles: A list of roles allowed to access the endpoint.
        :type roles: list[Role]
        :raises HTTPException: 403 Forbidden if the user's role is not in the allowed roles.
        :return: A decorator that enforces role-based access control.
        :rtype: Callable
        """
        def wrapper(func):
            async def inner(current_user: User = Depends(self.get_current_user), db: Session = Depends(get_db), *args, **kwargs):
                if current_user.role not in roles:
                    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Operation forbidden")
                return await func(current_user, db, *args, **kwargs)
            return inner
        return wrapper
    
    def create_email_token(self, data: dict):
        """
        Creates an email verification token.

        :param data: The data to encode into the token (e.g., user email).
        :type data: dict
        :return: The encoded email verification token.
        :rtype: str
        """
        to_encode = data.copy()
        expire = datetime.now(timezone.utc) + timedelta(days=7)
        to_encode.update({"iat": datetime.now(timezone.utc), "exp": expire, "scope": "email_token"})
        token = jwt.encode(to_encode, self.SECRET_KEY, algorithm=self.ALGORITHM)
        return token

    async def get_email_from_token(self, token: str):
        """
        Decodes an email verification token and returns the user's email.

        :param token: The email verification token to decode.
        :type token: str
        :raises HTTPException: 401 Unauthorized if the token is invalid or has an invalid scope.
        :raises HTTPException: 422 Unprocessable Entity if the token is invalid.
        :return: The email extracted from the token.
        :rtype: str
        """
        try:
            payload = jwt.decode(token, self.SECRET_KEY, algorithms=[self.ALGORITHM])
            if payload["scope"] == "email_token":
                email = payload["sub"]
                return email
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid scope for token")
        except JWTError as e:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Invalid token for email verification",
            )

auth_service = Auth()