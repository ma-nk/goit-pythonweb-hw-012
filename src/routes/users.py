from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, status, Request
from sqlalchemy.orm import Session
import cloudinary
import cloudinary.uploader

from src.conf.db import get_db
from src.schemas.user import UserDb, UpdateEmailModel
from src.services.auth import auth_service
from src.repository import users as repository_users
from src.conf.config import settings
from src.models.user import Role
from src.services import email as email_service

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me/", response_model=UserDb)
async def read_users_me(current_user: UserDb = Depends(auth_service.get_current_user)):
    """
    Retrieve information about the current authenticated user.

    :param current_user: The currently authenticated user.
    :type current_user: UserDb
    :return: The current user's information.
    :rtype: UserDb
    """
    return current_user


@router.patch('/avatar', response_model=UserDb, dependencies=[Depends(auth_service.allowed_roles([Role.admin]))])
async def update_avatar_user(file: UploadFile = File(), current_user: UserDb = Depends(auth_service.get_current_user),
                             db: Session = Depends(get_db)):
    """
    Update the avatar of the current user. This endpoint is restricted to users with 'admin' role.

    :param file: The avatar image file to upload.
    :type file: UploadFile
    :param current_user: The currently authenticated user.
    :type current_user: UserDb
    :param db: The database session.
    :type db: Session
    :return: The updated user with the new avatar URL.
    :rtype: UserDb
    :raises HTTPException: 403 Forbidden if the user does not have the 'admin' role.
    """
    cloudinary.config(
        cloud_name=settings.cloudinary_name,
        api_key=settings.cloudinary_api_key,
        api_secret=settings.cloudinary_api_secret,
        secure=True
    )

    r = cloudinary.uploader.upload(file.file, public_id=f'contacts/{current_user.username}', overwrite=True)
    src_url = cloudinary.CloudinaryImage(f'contacts/{current_user.username}')\
                        .build_url(width=250, height=250, crop='fill', version=r.get('version'))
    user = await repository_users.update_avatar(current_user.email, src_url, db)
    return user


@router.patch('/me/email', response_model=UserDb)
async def update_user_email(body: UpdateEmailModel, request: Request, current_user: UserDb = Depends(auth_service.get_current_user),
                          db: Session = Depends(get_db)):
    """
    Update the email address of the current user.

    :param body: The request body containing the new email and current password.
    :type body: UpdateEmailModel
    :param request: The incoming request object.
    :type request: Request
    :param current_user: The currently authenticated user.
    :type current_user: UserDb
    :param db: The database session.
    :type db: Session
    :raises HTTPException: 401 Unauthorized if the provided password is invalid.
    :raises HTTPException: 409 Conflict if the new email is already registered.
    :return: The user with the updated email information.
    :rtype: UserDb
    """
    if not auth_service.verify_password(body.new_password, current_user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password")
    
    # Check if the new email is already taken
    existing_user = await repository_users.get_user_by_email(body.new_email, db)
    if existing_user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    await repository_users.update_email(current_user, body.new_email, db)
    await email_service.send_email(body.new_email, current_user.username, str(request.base_url), "verify_email")
    return await repository_users.get_user_by_email(body.new_email, db)

