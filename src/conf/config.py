from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Database settings
    sqlalchemy_database_url: str

    # JWT settings
    secret_key: str
    algorithm: str
    mail_username: str
    mail_password: str
    mail_from: str
    mail_port: int
    mail_server: str
    
    # Cloudinary settings
    cloudinary_name: str
    cloudinary_api_key: str
    cloudinary_api_secret: str

    # Redis settings
    redis_host: str = 'localhost'
    redis_port: int = 6379


settings = Settings()
