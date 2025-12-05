from pathlib import Path

from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType
from fastapi_mail.errors import ConnectionErrors
from pydantic import EmailStr

from src.services.auth import auth_service
from src.conf.config import settings

conf = ConnectionConfig(
    MAIL_USERNAME=settings.mail_username,
    MAIL_PASSWORD=settings.mail_password,
    MAIL_FROM=settings.mail_from,
    MAIL_PORT=settings.mail_port,
    MAIL_SERVER=settings.mail_server,
    MAIL_FROM_NAME="Desire application",
    MAIL_STARTTLS=False,
    MAIL_SSL_TLS=True,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True,
    TEMPLATE_FOLDER=Path(__file__).parent / 'templates',
)


async def send_email(email: EmailStr, username: str, host: str, type_email: str = "verify_email"):
    """
    Sends an email for either email verification or password reset.

    If there's a connection error, it prints the relevant token to the console for debugging.

    :param email: The recipient's email address.
    :type email: EmailStr
    :param username: The username of the recipient.
    :type username: str
    :param host: The host URL for generating verification/reset links.
    :type host: str
    :param type_email: The type of email to send, either "verify_email" or "reset_password". Defaults to "verify_email".
    :type type_email: str
    :raises ConnectionErrors: If there is a problem connecting to the email server.
    :return: None
    """
    try:
        if type_email == "verify_email":
            token_verification = auth_service.create_email_token({"sub": email})
            message = MessageSchema(
                subject="Confirm your email ",
                recipients=[email],
                template_body={"host": host, "username": username, "token": token_verification},
                subtype=MessageType.html
            )
            fm = FastMail(conf)
            await fm.send_message(message, template_name="email_template.html")
        elif type_email == "reset_password":
            token_reset_password = auth_service.create_email_token({"sub": email})
            message = MessageSchema(
                subject="Reset your password",
                recipients=[email],
                template_body={"host": host, "username": username, "token": token_reset_password},
                subtype=MessageType.html
            )
            fm = FastMail(conf)
            await fm.send_message(message, template_name="reset_password_template.html")
    except ConnectionErrors as err:
        print(f"Failed to send email: {err}")
        if type_email == "verify_email":
            print(f"Verification token for {email}: {token_verification}")
        elif type_email == "reset_password":
            print(f"Password reset token for {email}: {token_reset_password}")
