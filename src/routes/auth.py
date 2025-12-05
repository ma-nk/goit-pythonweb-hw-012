from fastapi import APIRouter, HTTPException, Depends, status, Security, BackgroundTasks, Request, Response, Cookie
from fastapi.security import OAuth2PasswordRequestForm, HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from src.conf.db import get_db
from src.schemas.user import UserModel, UserResponse, TokenModel, RequestEmail, UpdateEmailModel, RequestResetPassword, ResetPassword
from src.repository import users as repository_users
from src.services.auth import auth_service
from src.services.email import send_email

router = APIRouter(prefix="/auth", tags=["auth"])
security = HTTPBearer()


@router.post("/signup", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def signup(body: UserModel, background_tasks: BackgroundTasks, request: Request, db: Session = Depends(get_db)):
    """
    Registers a new user.

    :param body: The user registration data.
    :type body: UserModel
    :param background_tasks: Background tasks for sending email.
    :type background_tasks: BackgroundTasks
    :param request: The incoming request object.
    :type request: Request
    :param db: The database session.
    :type db: Session
    :raises HTTPException: 409 Conflict if an account with the given email already exists.
    :return: A message confirming user creation and the user object.
    :rtype: UserResponse
    """
    exist_user = await repository_users.get_user_by_email(body.email, db)
    if exist_user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Account already exists")
    body.password = auth_service.get_password_hash(body.password)
    new_user = await repository_users.create_user(body, db)
    background_tasks.add_task(send_email, new_user.email, new_user.username, str(request.base_url))
    return {"user": new_user, "detail": "User successfully created"}


@router.post("/login")
async def login(response: Response, body: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """
    Authenticates a user and returns access and refresh tokens.

    :param response: The response object to set cookies.
    :type response: Response
    :param body: The OAuth2 form data containing username (email) and password.
    :type body: OAuth2PasswordRequestForm
    :param db: The database session.
    :type db: Session
    :raises HTTPException: 401 Unauthorized if email is invalid, password is invalid, or email is not confirmed.
    :return: A dictionary containing access token and token type.
    :rtype: dict
    """
    user = await repository_users.get_user_by_email(body.username, db)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email")
    if not auth_service.verify_password(body.password, user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password")
    if not user.confirmed:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Email not confirmed")
    # Generate JWT
    access_token = await auth_service.create_access_token(data={"sub": user.email, "scope": "access_token"})
    refresh_token = await auth_service.create_refresh_token(data={"sub": user.email, "scope": "refresh_token"})
    await repository_users.update_token(user, refresh_token, db)
    response.set_cookie(key="refresh_token", value=refresh_token, httponly=True)
    return {"access_token": access_token, "token_type": "bearer"}


@router.get('/refresh_token')
async def refresh_token(response: Response, refresh_token: str = Cookie(...), db: Session = Depends(get_db)):
    """
    Refreshes the access token using a refresh token.

    :param response: The response object to set new cookies.
    :type response: Response
    :param refresh_token: The refresh token from the cookie.
    :type refresh_token: str
    :param db: The database session.
    :type db: Session
    :raises HTTPException: 401 Unauthorized if the refresh token is invalid or does not match.
    :return: A dictionary containing a new access token and token type.
    :rtype: dict
    """
    email = await auth_service.decode_refresh_token(refresh_token)
    user = await repository_users.get_user_by_email(email, db)
    if user.refresh_token != refresh_token:
        await repository_users.update_token(user, None, db)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    access_token = await auth_service.create_access_token(data={"sub": email, "scope": "access_token"})
    new_refresh_token = await auth_service.create_refresh_token(data={"sub": email, "scope": "refresh_token"})
    await repository_users.update_token(user, new_refresh_token, db)
    response.set_cookie(key="refresh_token", value=new_refresh_token, httponly=True)
    return {"access_token": access_token, "token_type": "bearer"}


@router.get('/confirmed_email/{token}')
async def confirmed_email(token: str, db: Session = Depends(get_db)):
    """
    Confirms a user's email address using a verification token.

    :param token: The email verification token.
    :type token: str
    :param db: The database session.
    :type db: Session
    :raises HTTPException: 400 Bad Request if the token is invalid or verification fails.
    :return: A message confirming email verification or that it's already confirmed.
    :rtype: dict
    """
    email = await auth_service.get_email_from_token(token)
    user = await repository_users.get_user_by_email(email, db)
    if user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Verification error")
    if user.confirmed:
        return {"message": "Your email is already confirmed"}
    await repository_users.confirmed_email(email, db)
    return {"message": "Email confirmed"}


@router.post('/request_email')
async def request_email(body: RequestEmail, background_tasks: BackgroundTasks, request: Request,
                        db: Session = Depends(get_db)):
    """
    Requests a new email verification link for a user.

    :param body: The request body containing the user's email.
    :type body: RequestEmail
    :param background_tasks: Background tasks for sending email.
    :type background_tasks: BackgroundTasks
    :param request: The incoming request object.
    :type request: Request
    :param db: The database session.
    :type db: Session
    :raises HTTPException: 404 Not Found if the user does not exist.
    :return: A message indicating that a confirmation email has been sent.
    :rtype: dict
    """
    user = await repository_users.get_user_by_email(body.email, db)

    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if user.confirmed:
        return {"message": "Your email is already confirmed"}
    if user:
        background_tasks.add_task(send_email, user.email, user.username, str(request.base_url))
    return {"message": "Check your email for confirmation."}


@router.post("/request_reset_password")
async def request_reset_password(
    body: RequestResetPassword,
    background_tasks: BackgroundTasks,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Initiates the password reset process by sending a reset email to the user.

    :param body: The request body containing the user's email.
    :type body: RequestResetPassword
    :param background_tasks: Background tasks for sending email.
    :type background_tasks: BackgroundTasks
    :param request: The incoming request object.
    :type request: Request
    :param db: The database session.
    :type db: Session
    :raises HTTPException: 404 Not Found if the user does not exist.
    :return: A message indicating that password reset instructions have been sent.
    :rtype: dict
    """
    user = await repository_users.get_user_by_email(body.email, db)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    background_tasks.add_task(
        send_email,
        user.email,
        user.username,
        str(request.base_url),
        "reset_password",
    )
    return {"message": "Check your email for password reset instructions."}


@router.post("/reset_password")
async def reset_password(
    body: ResetPassword,
    db: Session = Depends(get_db),
):
    """
    Resets the user's password using a valid reset token.

    :param body: The request body containing the reset token and new password.
    :type body: ResetPassword
    :param db: The database session.
    :type db: Session
    :raises HTTPException: 400 Bad Request if the token is invalid or verification fails.
    :return: A message confirming successful password update.
    :rtype: dict
    """
    email = await auth_service.get_email_from_token(body.token)
    user = await repository_users.get_user_by_email(email, db)
    if user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token or email")

    hashed_password = auth_service.get_password_hash(body.new_password)
    await repository_users.update_password(user, hashed_password, db)
    return {"message": "Password successfully updated."}
