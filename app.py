"""
Main Flask application for "итп" social network.
"""
import os
import re
import json
import logging
import secrets
from datetime import datetime
from functools import wraps
from werkzeug.utils import secure_filename
from PIL import Image
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort, send_from_directory, session
from flask_login import login_required, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash

import config
from data_manager import (
    data_manager, get_user_by_id, get_user_by_username, get_user_by_email,
    create_user, update_user, get_posts, get_post_by_id, create_post,
    get_comments_by_post, create_comment, create_reaction, remove_reaction,
    get_reaction, create_application, get_applications_by_user, get_pending_applications,
    process_application, create_ban, remove_ban, get_active_ban, create_report,
    get_statistics, get_top_users, get_posts_count,
    create_notification, get_notifications_by_user, mark_all_notifications_read,
    create_subscription, remove_subscription, get_subscriptions, get_subscribers, is_subscribed,
    create_admin_log, get_admin_logs, get_admin_logs_by_admin
)
from auth import (
    init_auth, load_user, register_user, authenticate_user,
    login_user_session, logout_user_session, generate_captcha
)

app = Flask(__name__)
app.config.from_object(config)

init_auth(app)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri="memory://"
)

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(config.LOG_FILE),
        logging.StreamHandler()
    ]
)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in config.ALLOWED_EXTENSIONS

def get_extension(filename):
    return filename.rsplit('.', 1)[1].lower() if '.' in filename else ''

def save_image(file, folder, prefix, size=None):
    if file and file.filename:
        original_filename = file.filename
        filename = secure_filename(original_filename)
        ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else 'jpg'
        unique_name = f"{prefix}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{secrets.token_hex(6)}.{ext}"
        filepath = str(folder / unique_name)
        
        try:
            img = Image.open(file)
            if size:
                img.thumbnail(size, Image.Resampling.LANCZOS)
            img.save(filepath, quality=85)
            return unique_name
        except Exception as e:
            print(f"Error saving image: {e}")
            return None
    return None

def content_filter(text):
    for word in config.PROHIBITED_WORDS:
        pattern = re.compile(re.escape(word), re.IGNORECASE)
        text = pattern.sub('*' * len(word), text)
    return text

def is_admin():
    return current_user.is_authenticated and current_user.role in config.ADMIN_ROLES

@app.context_processor
def inject_config():
    theme = session.get('theme', 'light')
    return {
        'config': config,
        'is_admin': is_admin(),
        'current_user': current_user,
        'theme': theme,
        'BADGES': BADGES
    }

TRANSLATIONS = {
    'ru': {
        'welcome': 'Добро пожаловать',
        'login': 'Вход',
        'register': 'Регистрация',
        'logout': 'Выход',
        'profile': 'Профиль',
        'settings': 'Настройки',
        'create': 'Создать',
        'admin': 'Админ',
        'search': 'Поиск...',
    },
}

# Badges system
BADGES = {
    'creator': {'name': 'Создатель', 'color': 'purple', 'icon': '👑'},
    'verified': {'name': 'Верифицирован', 'color': 'blue', 'icon': '✓'},
    'scammer': {'name': 'Мошенник', 'color': 'red', 'icon': '⚠️'},
    'banned': {'name': 'Заблокирован', 'color': 'red', 'icon': '🚫'},
    'helper': {'name': 'Помощник', 'color': 'green', 'icon': '🤝'},
    'coder': {'name': 'Разработчик', 'color': 'yellow', 'icon': '💻'},
    'designer': {'name': 'Дизайнер', 'color': 'pink', 'icon': '🎨'},
    'moderator': {'name': 'Модератор', 'color': 'orange', 'icon': '🛡️'},
}

@app.route('/search')
def search():
    query = request.args.get('q', '').strip()
    type_filter = request.args.get('type', 'all')
    
    if not query:
        return render_template('search.html', results=None, query='', type_filter=type_filter)
    
    results = {'users': [], 'posts': []}
    
    if type_filter in ['all', 'users']:
        users = data_manager.get_all('users')
        users = [u for u in users if not u.get('is_banned', False)]
        for user in users:
            if query.lower() in user.get('username', '').lower() or query.lower() in user.get('display_name', '').lower():
                user['avatar'] = user.get('avatar', 'default_avatar.png')
                results['users'].append(user)
    
    if type_filter in ['all', 'posts']:
        posts = data_manager.get_all('posts')
        posts = [p for p in posts if not p.get('is_deleted', False)]
        for post in posts:
            if query.lower() in post.get('content', '').lower():
                author = get_user_by_id(post['user_id'])
                post['author'] = author
                results['posts'].append(post)
    
    # Return only filtered results
    if type_filter == 'users':
        results = {'users': results['users'], 'posts': []}
    elif type_filter == 'posts':
        results = {'users': [], 'posts': results['posts']}
    
    return render_template('search.html', results=results, query=query, type_filter=type_filter)

@app.route('/team')
def team():
    users = data_manager.get_all('users')
    users = [u for u in users if u.get('role', 'user') != 'user' and not u.get('is_banned', False)]
    users.sort(key=lambda x: config.ROLES.index(x.get('role', 'user')))
    
    for user in users:
        user['avatar'] = user.get('avatar', 'default_avatar.png')
    
    return render_template('team.html', team_members=users)

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    password = request.form.get('password', '')
    
    from werkzeug.security import check_password_hash
    if not check_password_hash(current_user.password_hash, password):
        flash('Неверный пароль', 'error')
        return redirect(url_for('settings'))
    
    # Soft delete user
    update_user(current_user.id, {'is_deleted': True, 'is_banned': True})
    
    logout_user_session()
    flash('Аккаунт удалён', 'info')
    return redirect(url_for('index'))

@app.route('/toggle_theme', methods=['POST'])
def toggle_theme():
    if 'theme' not in session:
        session['theme'] = 'light'
    
    themes = ['light', 'dark', 'black-yellow']
    current_idx = themes.index(session.get('theme', 'light'))
    next_idx = (current_idx + 1) % len(themes)
    session['theme'] = themes[next_idx]
    
    return redirect(request.referrer or url_for('index'))

@app.route('/privacy')
def privacy():
    return render_template('errors/privacy.html')

@app.route('/terms')
def terms():
    return render_template('errors/terms.html')

@app.route('/notifications')
@login_required
def notifications():
    notifications = get_notifications_by_user(current_user.id)
    return render_template('profile/notifications.html', notifications=notifications)

@app.route('/mark_notifications_read', methods=['POST'])
@login_required
def mark_notifications_read():
    count = mark_all_notifications_read(current_user.id)
    flash(f'{count} уведомлений отмечено как прочитанные', 'success')
    return redirect(url_for('notifications'))

@app.route('/')
def index():
    page = request.args.get('page', 1, type=int)
    posts = get_posts(limit=config.POSTS_PER_PAGE, offset=(page - 1) * config.POSTS_PER_PAGE)
    posts_count = get_posts_count()
    pages = (posts_count + config.POSTS_PER_PAGE - 1) // config.POSTS_PER_PAGE
    
    for post in posts:
        user = get_user_by_id(post['user_id'])
        post['author'] = user
        if user:
            post['author_avatar'] = user.get('avatar', 'default_avatar.png')
            post['author_name'] = user.get('display_name', user.get('username', 'Unknown'))
    
    return render_template('index.html', posts=posts, page=page, pages=pages)

@app.route('/post/<int:post_id>')
def view_post(post_id):
    post = get_post_by_id(post_id)
    if not post or post.get('is_deleted', False):
        abort(404)
    
    user = get_user_by_id(post['user_id'])
    post['author'] = user
    
    comments = get_comments_by_post(post_id)
    for comment in comments:
        comment_user = get_user_by_id(comment['user_id'])
        comment['author'] = comment_user
    
    user_reaction = None
    if current_user.is_authenticated:
        user_reaction = get_reaction(post_id, current_user.id)
        if user_reaction:
            user_reaction = user_reaction.get('reaction_type')
    
    return render_template('post.html', post=post, comments=comments, user_reaction=user_reaction)

@app.route('/profile/<username>')
def profile(username):
    user = get_user_by_username(username.lower())
    if not user:
        abort(404)
    
    user['avatar'] = user.get('avatar', 'default_avatar.png')
    user['banner'] = user.get('banner', 'default_banner.png')
    
    posts = get_posts(limit=10, user_id=user['id'])
    for post in posts:
        post['author'] = user
    
    subscriber_count = len(get_subscribers(user['id']))
    subscription_count = len(get_subscriptions(user['id']))
    is_subscribed_value = False
    if current_user.is_authenticated:
        is_subscribed_value = is_subscribed(current_user.id, user['id'])
    
    return render_template('profile/view.html', profile_user=user, posts=posts, 
                           subscriber_count=subscriber_count, 
                           subscription_count=subscription_count,
                           is_subscribed=is_subscribed_value)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    # Generate captcha only on GET or if not in session
    if 'captcha_answer' not in session:
        captcha_question, captcha_answer = generate_captcha()
        session['captcha_answer'] = captcha_answer
        session['captcha_question'] = captcha_question
    else:
        captcha_question = session.get('captcha_question', '')
        captcha_answer = session.get('captcha_answer', 0)
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        display_name = request.form.get('display_name', '').strip() or username
        captcha_input = request.form.get('captcha', '')
        
        # Check language for messages
        lang = session.get('lang', 'ru')
        
        if str(session.get('captcha_answer', 0)) != str(captcha_input).strip():
            # Generate new captcha for next attempt
            captcha_question, captcha_answer = generate_captcha()
            session['captcha_answer'] = captcha_answer
            session['captcha_question'] = captcha_question
            
            msg = 'Неверный ответ на капчу' if lang == 'ru' else 'Invalid captcha answer'
            flash(msg, 'error')
            return render_template('auth/register.html', captcha_question=captcha_question)
        
        user, error = register_user(username, email, password, display_name)
        
        if error:
            # Generate new captcha
            captcha_question, captcha_answer = generate_captcha()
            session['captcha_answer'] = captcha_answer
            session['captcha_question'] = captcha_question
            
            flash(error, 'error')
            return render_template('auth/register.html', captcha_question=captcha_question)
        
        login_user_session(user)
        
        msg = 'Регистрация успешна! Добро пожаловать в итп!' if lang == 'ru' else 'Registration successful! Welcome to итп!'
        flash(msg, 'success')
        return redirect(url_for('index'))
    
    # Clear captcha from session on GET to generate fresh one
    session.pop('captcha_answer', None)
    session.pop('captcha_question', None)
    captcha_question, captcha_answer = generate_captcha()
    session['captcha_answer'] = captcha_answer
    session['captcha_question'] = captcha_question
    
    return render_template('auth/register.html', captcha_question=captcha_question)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        lang = session.get('lang', 'ru')
        
        user, error = authenticate_user(username, password)
        
        if error:
            msg = 'Неверный username или пароль' if lang == 'ru' else 'Invalid username or password'
            flash(msg, 'error')
            return render_template('auth/login.html')
        
        login_user_session(user)
        
        msg = 'С возвращением!' if lang == 'ru' else 'Welcome back!'
        flash(msg, 'success')
        next_page = request.args.get('next')
        return redirect(next_page or url_for('index'))
    
    return render_template('auth/login.html')

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user_session()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('index'))

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'update_profile':
            updates = {
                'display_name': request.form.get('display_name', '').strip(),
                'bio': content_filter(request.form.get('bio', '').strip())
            }
            update_user(current_user.id, updates)
            flash('Profile updated successfully', 'success')
        
        elif action == 'update_password':
            current_password = request.form.get('current_password', '')
            new_password = request.form.get('new_password', '')
            
            if not check_password_hash(current_user.password_hash, current_password):
                flash('Неверный текущий пароль', 'error')
                return redirect(url_for('settings'))
            
            valid, error = False, "Invalid password"
            from auth import validate_password
            valid, error = validate_password(new_password)
            if valid:
                update_user(current_user.id, {'password_hash': generate_password_hash(new_password)})
                flash('Пароль успешно изменён', 'success')
            else:
                flash(error, 'error')
        
        return redirect(url_for('settings'))
    
    return render_template('profile/settings.html')

@app.route('/upload_avatar', methods=['POST'])
@login_required
def upload_avatar():
    if 'avatar' not in request.files:
        flash('No file uploaded', 'error')
        return redirect(url_for('settings'))
    
    file = request.files['avatar']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('settings'))
    
    filename = save_image(file, config.AVATAR_DIR, f'avatar_{current_user.id}', config.AVATAR_SIZE)
    if filename:
        update_user(current_user.id, {'avatar': filename})
        flash('Avatar updated successfully', 'success')
    else:
        flash('Invalid file type', 'error')
    
    return redirect(url_for('settings'))

@app.route('/upload_banner', methods=['POST'])
@login_required
def upload_banner():
    if 'banner' not in request.files:
        flash('No file uploaded', 'error')
        return redirect(url_for('settings'))
    
    file = request.files['banner']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('settings'))
    
    filename = save_image(file, config.BANNER_DIR, f'banner_{current_user.id}', config.BANNER_SIZE)
    if filename:
        update_user(current_user.id, {'banner': filename})
        flash('Banner updated successfully', 'success')
    else:
        flash('Invalid file type', 'error')
    
    return redirect(url_for('settings'))

@app.route('/create_post', methods=['GET', 'POST'])
@login_required
def create_post_route():
    if not current_user.can_post:
        flash('You cannot create posts at this time', 'error')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        content = content_filter(request.form.get('content', '').strip())
        
        if not content and 'files' not in request.files:
            flash('Post must have content or images', 'error')
            return redirect(url_for('create_post_route'))
        
        media_files = []
        if 'media' in request.files:
            files = request.files.getlist('media')
            for file in files:
                if file.filename and len(media_files) < 5:
                    filename = save_image(file, config.POST_MEDIA_DIR, f'post_{current_user.id}_{len(media_files)}', config.POST_IMAGE_SIZE)
                    if filename:
                        media_files.append(filename)
        
        post = create_post({
            'user_id': current_user.id,
            'content': content,
            'media': media_files
        })
        
        if post:
            flash('Post created successfully', 'success')
            return redirect(url_for('view_post', post_id=post['id']))
        else:
            flash('Failed to create post', 'error')
    
    return render_template('post/create.html')

@app.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = get_post_by_id(post_id)
    if not post:
        abort(404)
    
    if post['user_id'] != current_user.id and not is_admin():
        abort(403)
    
    if request.method == 'POST':
        content = content_filter(request.form.get('content', '').strip())
        data_manager.update('posts', post_id, {
            'content': content,
            'is_edited': True
        })
        flash('Post updated successfully', 'success')
        return redirect(url_for('view_post', post_id=post_id))
    
    return render_template('post/edit.html', post=post)

@app.route('/delete_post/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    post = get_post_by_id(post_id)
    if not post:
        abort(404)
    
    if post['user_id'] != current_user.id and not is_admin():
        abort(403)
    
    data_manager.soft_delete('posts', post_id)
    flash('Post deleted', 'success')
    return redirect(url_for('index'))

@app.route('/comment/<int:post_id>', methods=['POST'])
@login_required
def add_comment(post_id):
    if not current_user.can_comment:
        flash('Вы не можете комментировать в данное время', 'error')
        return redirect(url_for('view_post', post_id=post_id))
    
    content = content_filter(request.form.get('content', '').strip())
    if not content:
        flash('Комментарий не может быть пустым', 'error')
        return redirect(url_for('view_post', post_id=post_id))
    
    media_files = []
    if 'media' in request.files:
        file = request.files['media']
        if file.filename:
            filename = save_image(file, config.POST_MEDIA_DIR, f'comment_{current_user.id}', config.POST_IMAGE_SIZE)
            if filename:
                media_files.append(filename)
    
    comment = create_comment({
        'post_id': post_id,
        'user_id': current_user.id,
        'content': content,
        'media': media_files
    })
    
    if comment:
        flash('Comment added', 'success')
    else:
        flash('Failed to add comment', 'error')
    
    return redirect(url_for('view_post', post_id=post_id))

@app.route('/edit_comment/<int:comment_id>', methods=['POST'])
@login_required
def edit_comment(comment_id):
    comment = data_manager.get_by_id('comments', comment_id)
    if not comment:
        abort(404)
    
    if comment['user_id'] != current_user.id and not is_admin():
        abort(403)
    
    content = content_filter(request.form.get('content', '').strip())
    data_manager.update('comments', comment_id, {
        'content': content,
        'is_edited': True
    })
    flash('Comment updated', 'success')
    return redirect(url_for('view_post', post_id=comment['post_id']))

@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = data_manager.get_by_id('comments', comment_id)
    if not comment:
        abort(404)
    
    if comment['user_id'] != current_user.id and not is_admin():
        abort(403)
    
    data_manager.soft_delete('comments', comment_id)
    flash('Comment deleted', 'success')
    return redirect(url_for('view_post', post_id=comment['post_id']))

@app.route('/react/<int:post_id>', methods=['POST'])
@login_required
def react_to_post(post_id):
    post = get_post_by_id(post_id)
    if not post:
        abort(404)
    
    if not current_user.can_react:
        flash('You cannot react at this time', 'error')
        return redirect(url_for('view_post', post_id=post_id))
    
    reaction_type = request.form.get('reaction_type', 'like')
    
    existing = get_reaction(post_id, current_user.id)
    if existing and existing.get('reaction_type') == reaction_type:
        remove_reaction(post_id, current_user.id)
        flash(f'{reaction_type} removed', 'info')
    else:
        create_reaction({
            'post_id': post_id,
            'user_id': current_user.id,
            'reaction_type': reaction_type
        })
        flash(f'{reaction_type} added', 'success')
    
    return redirect(url_for('view_post', post_id=post_id))

@app.route('/report/<type>/<int:id>', methods=['POST'])
@login_required
def report_content(type, id):
    content_type = 'post' if type == 'post' else 'comment'
    reason = request.form.get('reason', '')
    
    report = create_report({
        'user_id': current_user.id,
        'content_type': content_type,
        'content_id': id,
        'reason': reason
    })
    
    if report:
        flash('Report submitted', 'success')
    else:
        flash('Failed to submit report', 'error')
    
    if type == 'post':
        return redirect(url_for('view_post', post_id=id))
    else:
        comment = data_manager.get_by_id('comments', id)
        if comment:
            return redirect(url_for('view_post', post_id=comment['post_id']))
        return redirect(url_for('index'))

@app.route('/apply_verification', methods=['GET', 'POST'])
@login_required
def apply_verification():
    if current_user.is_verified:
        flash('You are already verified', 'info')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        message = request.form.get('message', '').strip()
        
        if not message:
            flash('Message is required', 'error')
            return redirect(url_for('apply_verification'))
        
        photos = []
        if 'photos' in request.files:
            files = request.files.getlist('photos')
            for file in files:
                if file.filename and len(photos) < config.MAX_APPLICATION_PHOTOS:
                    filename = save_image(file, config.APPLICATION_MEDIA_DIR, f'app_{current_user.id}_{len(photos)}')
                    if filename:
                        photos.append(filename)
        
        app_data = create_application({
            'user_id': current_user.id,
            'message': message,
            'photos': photos
        })
        
        if app_data:
            flash('Application submitted successfully', 'success')
        else:
            flash('Failed to submit application', 'error')
        
        return redirect(url_for('index'))
    
    return render_template('auth/apply_verification.html')

@app.route('/my_applications')
@login_required
def my_applications():
    applications = get_applications_by_user(current_user.id)
    return render_template('profile/applications.html', applications=applications)

@app.route('/admin')
@login_required
def admin_dashboard():
    if not is_admin():
        abort(403)
    
    stats = get_statistics()
    top_users = get_top_users(10)
    pending_apps = get_pending_applications()
    
    return render_template('admin/dashboard.html', stats=stats, top_users=top_users, pending_apps=pending_apps)

@app.route('/admin/users')
@login_required
def admin_users():
    if not is_admin():
        abort(403)
    
    users = data_manager.get_all('users')
    return render_template('admin/users.html', users=users)

@app.route('/admin/change_role/<int:user_id>', methods=['POST'])
@login_required
def admin_change_role(user_id):
    if current_user.role != 'creator':
        abort(403)
    
    new_role = request.form.get('role')
    if new_role not in config.ROLES:
        flash('Invalid role', 'error')
        return redirect(url_for('admin_users'))
    
    user = get_user_by_id(user_id)
    if not user:
        abort(404)
    
    update_user(user_id, {'role': new_role})
    flash(f'Role for {user["username"]} changed to {new_role}', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/statistics')
@login_required
def admin_statistics():
    if not is_admin():
        abort(403)
    
    stats = get_statistics()
    return render_template('admin/statistics.html', stats=stats)

@app.route('/admin/applications')
@login_required
def admin_applications():
    if not is_admin():
        abort(403)
    
    status = request.args.get('status', 'pending')
    if status == 'all':
        apps = data_manager.get_all('applications')
    else:
        apps = data_manager.get_all_by_field('applications', 'status', status)
    
    apps.sort(key=lambda x: x.get('created_at', ''), reverse=True)
    
    for app in apps:
        user = get_user_by_id(app['user_id'])
        app['user'] = user
    
    return render_template('admin/applications.html', applications=apps, status=status)

@app.route('/admin/application/<int:app_id>')
@login_required
def admin_view_application(app_id):
    if not is_admin():
        abort(403)
    
    app_data = data_manager.get_by_id('applications', app_id)
    if not app_data:
        abort(404)
    
    user = get_user_by_id(app_data['user_id'])
    app_data['user'] = user
    
    return render_template('admin/view_application.html', application=app_data)

@app.route('/admin/approve_application/<int:app_id>')
@login_required
def admin_approve_application(app_id):
    if not is_admin():
        abort(403)
    
    process_application(app_id, 'approved', current_user.id)
    app_data = data_manager.get_by_id('applications', app_id)
    
    # Log admin action
    create_admin_log({
        'admin_id': current_user.id,
        'action': 'approve_application',
        'application_id': app_id
    })
    
    if app_data:
        user = get_user_by_id(app_data['user_id'])
        create_notification({
            'user_id': app_data['user_id'],
            'type': 'verification_approved',
            'message': 'Ваша заявка на верификацию одобрена!',
            'link': url_for('profile', username=user['username'] if user else '')
        })
    flash('Заявка одобрена', 'success')
    return redirect(url_for('admin_applications'))

@app.route('/admin/reject_application/<int:app_id>')
@login_required
def admin_reject_application(app_id):
    if not is_admin():
        abort(403)
    
    process_application(app_id, 'rejected', current_user.id)
    
    # Log admin action
    create_admin_log({
        'admin_id': current_user.id,
        'action': 'reject_application',
        'application_id': app_id
    })
    
    app_data = data_manager.get_by_id('applications', app_id)
    if app_data:
        create_notification({
            'user_id': app_data['user_id'],
            'type': 'verification_rejected',
            'message': 'Ваша заявка на верификацию отклонена.',
            'link': url_for('my_applications')
        })
    flash('Заявка отклонена', 'success')
    return redirect(url_for('admin_applications'))

@app.route('/admin/ban_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def admin_ban_user(user_id):
    if not is_admin():
        abort(403)
    
    user = get_user_by_id(user_id)
    if not user:
        abort(404)
    
    if request.method == 'POST':
        ban_type = request.form.get('ban_type', 'ban')
        reason = request.form.get('reason', '')
        expires_at = request.form.get('expires_at', '')
        
        ban_data = {
            'user_id': user_id,
            'admin_id': current_user.id,
            'reason': reason,
            'ban_type': 'read_only' if ban_type == 'readonly' else 'ban',
            'expires_at': expires_at if expires_at else None
        }
        
        create_ban(ban_data)
        
        # Log admin action
        create_admin_log({
            'admin_id': current_user.id,
            'action': 'ban_user',
            'target_user_id': user_id,
            'ban_type': ban_data['ban_type'],
            'reason': reason
        })
        
        flash(f'Пользователь {user["username"]} заблокирован', 'success')
        return redirect(url_for('admin_users'))
    
    return render_template('admin/ban_user.html', user=user)

@app.route('/admin/unban_user/<int:user_id>')
@login_required
def admin_unban_user(user_id):
    if not is_admin():
        abort(403)
    
    remove_ban(user_id)
    
    # Log admin action
    create_admin_log({
        'admin_id': current_user.id,
        'action': 'unban_user',
        'target_user_id': user_id
    })
    
    flash('Пользователь разблокирован', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/toggle_readonly/<int:user_id>', methods=['POST'])
@login_required
def admin_toggle_readonly(user_id):
    if not is_admin():
        abort(403)
    
    user = get_user_by_id(user_id)
    if not user:
        abort(404)
    
    new_state = not user.get('read_only_mode', False)
    update_user(user_id, {'read_only_mode': new_state})
    flash(f'Read-only mode {"enabled" if new_state else "disabled"} for user', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/manage_badges/<int:user_id>', methods=['POST'])
@login_required
def admin_manage_badges(user_id):
    if current_user.role != 'creator':
        abort(403)
    
    user = get_user_by_id(user_id)
    if not user:
        abort(404)
    
    badge = request.form.get('badge')
    action = request.form.get('action')
    
    badges = user.get('badges', [])
    
    if action == 'add' and badge and badge not in badges:
        badges.append(badge)
    elif action == 'remove' and badge in badges:
        badges.remove(badge)
    
    update_user(user_id, {'badges': badges})
    flash('Badges updated', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/delete_content/<type>/<int:id>')
@login_required
def admin_delete_content(type, id):
    if not is_admin():
        abort(403)
    
    if type == 'post':
        data_manager.soft_delete('posts', id)
    elif type == 'comment':
        data_manager.soft_delete('comments', id)
    
    # Log admin action
    create_admin_log({
        'admin_id': current_user.id,
        'action': 'delete_content',
        'content_type': type,
        'content_id': id
    })
    
    flash('Контент удалён', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reports')
@login_required
def admin_reports():
    if not is_admin():
        abort(403)
    
    status = request.args.get('status', 'pending')
    if status == 'all':
        reports = data_manager.get_all('reports')
    else:
        reports = data_manager.get_all_by_field('reports', 'status', status)
    
    reports.sort(key=lambda x: x.get('created_at', ''), reverse=True)
    
    for report in reports:
        user = get_user_by_id(report['user_id'])
        report['reporter'] = user
        if report['content_type'] == 'post':
            content = get_post_by_id(report['content_id'])
        else:
            content = data_manager.get_by_id('comments', report['content_id'])
        report['content'] = content
    
    return render_template('admin/reports.html', reports=reports, status=status)

@app.route('/admin/reports/<int:report_id>', methods=['GET', 'POST'])
@login_required
def admin_view_report(report_id):
    if not is_admin():
        abort(403)
    
    report = data_manager.get_by_id('reports', report_id)
    if not report:
        abort(404)
    
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'resolve':
            data_manager.update('reports', report_id, {'status': 'resolved'})
            flash('Жалоба отмечена как решённая', 'success')
        elif action == 'dismiss':
            data_manager.update('reports', report_id, {'status': 'dismissed'})
            flash('Жалоба отклонена', 'success')
        return redirect(url_for('admin_reports'))
    
    user = get_user_by_id(report['user_id'])
    report['reporter'] = user
    if report['content_type'] == 'post':
        content = get_post_by_id(report['content_id'])
        if content:
            author = get_user_by_id(content['user_id'])
            content['author'] = author
    else:
        content = data_manager.get_by_id('comments', report['content_id'])
        if content:
            author = get_user_by_id(content['user_id'])
            content['author'] = author
    report['content'] = content
    
    return render_template('admin/view_report.html', report=report)

@app.route('/admin/logs')
@login_required
def admin_logs():
    if current_user.role != 'creator':
        abort(403)
    
    logs = get_admin_logs(100)
    for log in logs:
        admin = get_user_by_id(log.get('admin_id', 0))
        log['admin'] = admin
    
    return render_template('admin/logs.html', logs=logs)

# Subscription routes
@app.route('/subscribe/<int:user_id>', methods=['POST'])
@login_required
def subscribe(user_id):
    if current_user.is_banned:
        flash('Вы не можете подписываться', 'error')
        return redirect(request.referrer or url_for('index'))
    
    user = get_user_by_id(user_id)
    if not user:
        abort(404)
    
    if is_subscribed(current_user.id, user_id):
        remove_subscription(current_user.id, user_id)
        flash(f'Вы отписались от {user["display_name"]}', 'info')
    else:
        create_subscription(current_user.id, user_id)
        # Notify the user
        create_notification({
            'user_id': user_id,
            'type': 'new_subscriber',
            'message': f'{current_user.display_name} подписался на вас',
            'link': url_for('profile', username=current_user.username)
        })
        flash(f'Вы подписались на {user["display_name"]}', 'success')
    
    return redirect(request.referrer or url_for('profile', username=user['username']))

@app.route('/subscribers/<username>')
def subscribers(username):
    user = get_user_by_username(username.lower())
    if not user:
        abort(404)
    
    subs = get_subscribers(user['id'])
    subscribers_list = []
    for sub in subs:
        follower = get_user_by_id(sub['follower_id'])
        if follower:
            follower['is_subscribed'] = is_subscribed(current_user.id, follower['id']) if current_user.is_authenticated else False
            subscribers_list.append(follower)
    
    return render_template('profile/subscribers.html', profile_user=user, subscribers=subscribers_list)

@app.route('/subscriptions/<username>')
def subscriptions(username):
    user = get_user_by_username(username.lower())
    if not user:
        abort(404)
    
    subs = get_subscriptions(user['id'])
    subscriptions_list = []
    for sub in subs:
        following = get_user_by_id(sub['following_id'])
        if following:
            following['is_subscribed'] = is_subscribed(current_user.id, following['id']) if current_user.is_authenticated else False
            subscriptions_list.append(following)
    
    return render_template('profile/subscriptions.html', profile_user=user, subscriptions=subscriptions_list)

# Maintenance mode - global setting
maintenance_mode = False

@app.route('/admin/maintenance', methods=['POST'])
@login_required
def admin_toggle_maintenance():
    global maintenance_mode
    if current_user.role != 'creator':
        abort(403)
    
    enabled = request.form.get('enabled', 'false') == 'true'
    maintenance_mode = enabled
    
    # Log the action
    logging.info(f'Maintenance mode {"enabled" if enabled else "disabled"} by user {current_user.username}')
    
    flash(f'Режим обслуживания {"включён" if enabled else "выключен"}', 'success')
    return redirect(url_for('admin_dashboard'))

@app.before_request
def check_maintenance_mode():
    global maintenance_mode
    if maintenance_mode and not current_user.is_authenticated:
        return render_template('errors/maintenance.html'), 503
    if maintenance_mode and current_user.role != 'creator':
        return render_template('errors/maintenance.html'), 503

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(config.UPLOAD_DIR, filename)

# Exclude uploaded_file from rate limiting
limiter.exempt(uploaded_file)

@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('errors/403.html'), 403

@app.errorhandler(500)
def internal_error(error):
    return render_template('errors/500.html'), 500

if __name__ == '__main__':
    app.run(debug=config.DEBUG, host='0.0.0.0', port=5000)
