"""
Authentication module for user management.
Handles password hashing, user authentication, and session management.
"""
import hashlib
import secrets
from datetime import datetime
from functools import wraps
from typing import Optional

import bcrypt
from flask import current_app, session, request
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

import config
from data_manager import get_user_by_id, get_user_by_username, get_user_by_email, update_user

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

class User(UserMixin):
    def __init__(self, user_data: dict):
        self.id = user_data.get('id')
        self.username = user_data.get('username')
        self.email = user_data.get('email')
        self.display_name = user_data.get('display_name', user_data.get('username', 'User'))
        self.avatar = user_data.get('avatar', 'default_avatar.png')
        self.banner = user_data.get('banner', 'default_banner.png')
        self.bio = user_data.get('bio', '')
        self.role = user_data.get('role', 'user')
        self.is_verified = user_data.get('is_verified', False)
        self.verification_badge = user_data.get('verification_badge')
        self.is_banned = user_data.get('is_banned', False)
        self.ban_reason = user_data.get('ban_reason')
        self.read_only_mode = user_data.get('read_only_mode', False)
        self.badges = user_data.get('badges', [])
        self._user_data = user_data
    
    def get_id(self):
        return str(self.id)
    
    @property
    def password_hash(self):
        return self._user_data.get('password_hash', '')
    
    @password_hash.setter
    def password_hash(self, value):
        pass
    
    @property
    def is_admin(self):
        return self.role in config.ADMIN_ROLES
    
    @property
    def can_post(self):
        return not self.is_banned and not self.read_only_mode
    
    @property
    def can_comment(self):
        return not self.is_banned and not self.read_only_mode
    
    @property
    def can_react(self):
        return not self.is_banned
    
    def to_dict(self):
        return self._user_data

@login_manager.user_loader
def load_user(user_id: int) -> Optional[User]:
    user_data = get_user_by_id(int(user_id))
    if user_data:
        # Allow banned users to stay logged in but with restricted capabilities
        return User(user_data)
    return None

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

def generate_captcha() -> tuple:
    import random
    num1 = random.randint(1, 20)
    num2 = random.randint(1, 20)
    operators = ['+', '-', '*']
    operator = random.choice(operators)
    
    if operator == '+':
        answer = num1 + num2
    elif operator == '-':
        answer = num1 - num2
    else:
        answer = num1 * num2
    
    question = f"{num1} {operator} {num2}"
    return question, answer

def validate_username(username: str) -> tuple:
    if not username:
        return False, "Username is required"
    
    if len(username) < 3:
        return False, "Username must be at least 3 characters"
    
    if len(username) > 30:
        return False, "Username must be less than 30 characters"
    
    if not username.replace('_', '').isalnum():
        return False, "Username can only contain letters, numbers, and underscores"
    
    if username.startswith('_'):
        return False, "Username cannot start with underscore"
    
    return True, None

def validate_email(email: str) -> tuple:
    import re
    
    if not email:
        return False, "Email is required"
    
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, email):
        return False, "Invalid email format"
    
    return True, None

def validate_password(password: str) -> tuple:
    if not password:
        return False, "Password is required"
    
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    
    if len(password) > 128:
        return False, "Password must be less than 128 characters"
    
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    
    if not (has_upper and has_lower and has_digit):
        return False, "Password must contain uppercase, lowercase, and numbers"
    
    return True, None

def register_user(username: str, email: str, password: str, display_name: str = None) -> tuple:
    valid, error = validate_username(username)
    if not valid:
        return None, error
    
    valid, error = validate_email(email)
    if not valid:
        return None, error
    
    valid, error = validate_password(password)
    if not valid:
        return None, error
    
    if get_user_by_username(username):
        return None, "Username already exists"
    
    if get_user_by_email(email):
        return None, "Email already exists"
    
    user_data = {
        'username': username.lower(),
        'email': email.lower(),
        'display_name': display_name or username,
        'password_hash': hash_password(password)
    }
    
    from data_manager import create_user
    user = create_user(user_data)
    
    if user:
        return user, None
    
    return None, "Failed to create user"

def authenticate_user(username: str, password: str) -> tuple:
    user_data = get_user_by_username(username)
    
    if not user_data:
        user_data = get_user_by_email(username)
    
    if not user_data:
        return None, "Invalid username or password"
    
    if user_data.get('is_banned', False):
        return None, "Account is banned"
    
    if not verify_password(password, user_data.get('password_hash', '')):
        return None, "Invalid username or password"
    
    update_user(user_data['id'], {'last_login': datetime.utcnow().isoformat()})
    
    return user_data, None

def login_user_session(user_data: dict) -> None:
    user = User(user_data)
    login_user(user)
    session['user_id'] = user.id
    session['username'] = user.username
    session['role'] = user.role
    session.permanent = True

def logout_user_session() -> None:
    logout_user()
    session.clear()

def require_role(allowed_roles: list):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return {'error': 'Authentication required'}, 401
            
            if current_user.role not in allowed_roles:
                return {'error': 'Insufficient permissions'}, 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def init_auth(app):
    login_manager.init_app(app)
