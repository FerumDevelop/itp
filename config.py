"""
Configuration file for the "итп" social network.
Contains all application settings and constants.
"""
import os
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).resolve().parent

# Application configuration
SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
DEBUG = os.environ.get('DEBUG', 'True').lower() == 'true'

# JSON data directory
DATA_DIR = BASE_DIR / 'data'
DATA_DIR.mkdir(exist_ok=True)

# Uploads directory
UPLOAD_DIR = BASE_DIR / 'uploads'
UPLOAD_DIR.mkdir(exist_ok=True)

# Upload subdirectories
AVATAR_DIR = UPLOAD_DIR / 'avatars'
AVATAR_DIR.mkdir(exist_ok=True)

BANNER_DIR = UPLOAD_DIR / 'banners'
BANNER_DIR.mkdir(exist_ok=True)

APPLICATION_MEDIA_DIR = UPLOAD_DIR / 'application_media'
APPLICATION_MEDIA_DIR.mkdir(exist_ok=True)

POST_MEDIA_DIR = UPLOAD_DIR / 'post_media'
POST_MEDIA_DIR.mkdir(exist_ok=True)

# File upload settings
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'mp4', 'webm', 'mov', 'pdf', 'doc', 'docx'}
AVATAR_SIZE = (200, 200)
BANNER_SIZE = (1200, 400)
POST_IMAGE_SIZE = (1200, 1200)

# Theme settings
THEMES = ['light', 'dark', 'black-yellow']

# User roles
ROLES = ['user', 'helper', 'coder', 'designer', 'moderator', 'admin', 'creator']
ADMIN_ROLES = ['moderator', 'admin', 'creator']

# Pagination
POSTS_PER_PAGE = 20
COMMENTS_PER_PAGE = 50

# Rate limiting
RATELIMIT_DEFAULT = "200 per day"
RATELIMIT_STORAGE_URL = "memory://"

# Rate limits per user
POSTS_PER_HOUR = 5
COMMENTS_PER_HOUR = 20
REACTIONS_PER_HOUR = 50

# Content filtering
PROHIBITED_WORDS = [
    # Add prohibited words list here
]

# User roles hierarchy (higher index = more permissions)
USER_ROLES = [
    'user',
    'helper',
    'coder',
    'designer',
    'moderator',
    'admin',
    'creator'
]

# Admin role names
ADMIN_ROLES = ['moderator', 'admin', 'creator']

# Session settings
SESSION_COOKIE_NAME = 'itp_session'
PERMANENT_SESSION_LIFETIME = 86400 * 7  # 7 days

# Verification settings
MAX_APPLICATION_PHOTOS = 3

# Logging
LOG_FILE = BASE_DIR / 'logs' / 'app.log'
LOG_DIR = LOG_FILE.parent
LOG_DIR.mkdir(exist_ok=True)
LOG_LEVEL = 'INFO'
