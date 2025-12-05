import cloudinary
import cloudinary.uploader
from src.conf.config import settings

cloudinary.config(
    cloud_name=settings.cloudinary_name,
    api_key=settings.cloudinary_api_key,
    api_secret=settings.cloudinary_api_secret
)

def upload_avatar(file, public_id):
    r = cloudinary.uploader.upload(file, public_id=public_id, overwrite=True)
    return r['secure_url']
