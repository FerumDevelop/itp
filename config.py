"""
Configuration file for the "итп" social network.
Contains all application settings and constants.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

SECRET_KEY = os.environ.get('SECRET_KEY', os.urandom(32).hex())
DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'

DATA_DIR = BASE_DIR / 'data'
DATA_DIR.mkdir(exist_ok=True)

UPLOAD_DIR = BASE_DIR / 'uploads'
UPLOAD_DIR.mkdir(exist_ok=True)

AVATAR_DIR = UPLOAD_DIR / 'avatars'
AVATAR_DIR.mkdir(exist_ok=True)

BANNER_DIR = UPLOAD_DIR / 'banners'
BANNER_DIR.mkdir(exist_ok=True)

APPLICATION_MEDIA_DIR = UPLOAD_DIR / 'application_media'
APPLICATION_MEDIA_DIR.mkdir(exist_ok=True)

POST_MEDIA_DIR = UPLOAD_DIR / 'post_media'
POST_MEDIA_DIR.mkdir(exist_ok=True)

MAX_CONTENT_LENGTH = 16 * 1024 * 1024
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'mp4', 'webm', 'mov', 'pdf', 'doc', 'docx'}
AVATAR_SIZE = (200, 200)
BANNER_SIZE = (1200, 400)
POST_IMAGE_SIZE = (1200, 1200)

THEMES = ['light', 'dark']

ROLES = ['user', 'helper', 'coder', 'designer', 'moderator', 'admin', 'creator']
ADMIN_ROLES = ['moderator', 'admin', 'creator']

POSTS_PER_PAGE = 20
COMMENTS_PER_PAGE = 50

RATELIMIT_DEFAULT = "200 per day"
RATELIMIT_STORAGE_URL = "memory://"

POSTS_PER_HOUR = 5
COMMENTS_PER_HOUR = 20
REACTIONS_PER_HOUR = 50

PROHIBITED_WORDS = [
]

USER_ROLES = [
    'user',
    'helper',
    'coder',
    'designer',
    'moderator',
    'admin',
    'creator'
]

ADMIN_ROLES = ['moderator', 'admin', 'creator']

SESSION_COOKIE_NAME = 'itp_session'
PERMANENT_SESSION_LIFETIME = 86400 * 7

MAX_APPLICATION_PHOTOS = 3

LOG_FILE = BASE_DIR / 'logs' / 'app.log'
LOG_DIR = LOG_FILE.parent
LOG_DIR.mkdir(exist_ok=True)
LOG_LEVEL = 'INFO'

RESEND_API_KEY = os.environ.get('RESEND_API_KEY', 're_M9RrfYLx_MhuUjsUg9MeSXj2nhFRgXwxN')
SITE_URL = os.environ.get('SITE_URL', 'https://xn--h1aoi.site')
SITE_NAME = 'итп'
