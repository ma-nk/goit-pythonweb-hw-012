from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from src.conf.config import settings
from src.conf.base import Base
import src.models

engine = create_engine(settings.sqlalchemy_database_url)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
