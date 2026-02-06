"""
Authentication module for user management.
Handles password hashing, user authentication, and session management.
"""
import hashlib
import secrets
import random
import re
from datetime import datetime
from functools import wraps
from typing import Optional

import bcrypt
from flask import current_app, session, request
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

import config
from data_manager import get_user_by_id, get_user_by_username, get_user_by_email, update_user
from email_service import send_verification_email

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

class User(UserMixin):
    def __init__(self, user_data: dict):
        self.id = user_data.get('id')
        self.username = user_data.get('username')
        self.email = user_data.get('email')
        self.email_verified = user_data.get('email_verified', False)
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
        return User(user_data)
    return None

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

def generate_captcha() -> tuple:
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
        return False, "Имя пользователя обязательно"
    
    if len(username) < 3:
        return False, "Имя пользователя должно содержать минимум 3 символа"
    
    if len(username) > 30:
        return False, "Имя пользователя должно быть менее 30 символов"
    
    if not username.replace('_', '').isalnum():
        return False, "Имя пользователя может содержать только буквы, цифры и нижнее подчёркивание"
    
    if username.startswith('_'):
        return False, "Имя пользователя не может начинаться с нижнего подчёркивания"
    
    return True, None

def validate_email(email: str) -> tuple:
    if not email:
        return False, "Email обязателен"
    
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, email):
        return False, "Некорректный формат email"
    
    return True, None

def check_email_exists(email: str) -> bool:
    return get_user_by_email(email.lower()) is not None

def check_username_exists(username: str) -> bool:
    return get_user_by_username(username.lower()) is not None

def validate_password(password: str) -> tuple:
    if not password:
        return False, "Пароль обязателен", 0
    
    if len(password) < 8:
        return False, "Пароль должен содержать минимум 8 символов", 20
    
    if len(password) > 128:
        return False, "Пароль должен быть менее 128 символов", 40
    
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
    
    score = 20
    if has_upper:
        score += 20
    if has_lower:
        score += 20
    if has_digit:
        score += 20
    if has_special:
        score += 20
    
    if not (has_upper and has_lower and has_digit):
        return False, "Пароль должен содержать заглавные, строчные буквы и цифры", score
    
    return True, None, score

def generate_verification_code() -> str:
    return ''.join(str(random.randint(0, 9)) for _ in range(5))

def validate_registration(username: str, email: str, password: str) -> tuple:
    valid, error = validate_username(username)
    if not valid:
        return None, error
    
    valid, error = validate_email(email)
    if not valid:
        return None, error
    
    valid, error, _ = validate_password(password)
    if not valid:
        return None, error
    
    if get_user_by_username(username.lower()):
        return None, "Имя пользователя уже занято"
    
    if get_user_by_email(email.lower()):
        return None, "Email уже используется"
    
    return True, None

def register_user(username: str, email: str, password: str, display_name: str = None) -> tuple:
    valid, error = validate_username(username)
    if not valid:
        return None, error
    
    valid, error = validate_email(email)
    if not valid:
        return None, error
    
    valid, error, _ = validate_password(password)
    if not valid:
        return None, error
    
    if get_user_by_username(username.lower()):
        return None, "Имя пользователя уже занято"
    
    if get_user_by_email(email.lower()):
        return None, "Email уже используется"
    
    verification_code = generate_verification_code()
    
    user_data = {
        'username': username.lower(),
        'email': email.lower(),
        'display_name': display_name or username,
        'password_hash': hash_password(password),
        'email_verified': False,
        'verification_code': verification_code,
        'is_verified': False,
        'is_banned': False,
        'ban_reason': None,
        'read_only_mode': False,
        'role': 'user',
        'post_count': 0,
        'comment_count': 0,
        'avatar': 'default_avatar.png',
        'banner': 'default_banner.png',
        'badges': [],
        'is_deleted': False
    }
    
    from data_manager import create_user
    user = create_user(user_data)
    
    if user:
        send_verification_email(user['email'], user['username'], verification_code)
        return user, None
    
    return None, "Ошибка создания пользователя"

def authenticate_user(identifier: str, password: str) -> tuple:
    user_data = None
    
    if '@' in identifier:
        user_data = get_user_by_email(identifier.lower())
    else:
        user_data = get_user_by_username(identifier.lower())
    
    if not user_data:
        return None, "Неверное имя пользователя или пароль"
    
    if user_data.get('is_banned', False):
        return None, "Аккаунт заблокирован"
    
    if not user_data.get('email_verified', False):
        return None, "Сначала подтвердите email. Проверьте почту или запросите код повторно."
    
    if not verify_password(password, user_data.get('password_hash', '')):
        return None, "Неверное имя пользователя или пароль"
    
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
                return {'error': 'Требуется авторизация'}, 401
            
            if current_user.role not in allowed_roles:
                return {'error': 'Недостаточно прав'}, 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def init_auth(app):
    login_manager.init_app(app)
