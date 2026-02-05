"""
Data manager module for handling JSON file operations.
Provides CRUD operations for all data types.
"""
import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional
from pathlib import Path

import config


class DataManager:
    """Manages all JSON data file operations."""
    
    def __init__(self):
        self.data_files = {
            'users': config.DATA_DIR / 'users.json',
            'posts': config.DATA_DIR / 'posts.json',
            'comments': config.DATA_DIR / 'comments.json',
            'reactions': config.DATA_DIR / 'reactions.json',
            'applications': config.DATA_DIR / 'applications.json',
            'bans': config.DATA_DIR / 'bans.json',
            'reports': config.DATA_DIR / 'reports.json',
            'notifications': config.DATA_DIR / 'notifications.json',
            'subscriptions': config.DATA_DIR / 'subscriptions.json',
            'admin_logs': config.DATA_DIR / 'admin_logs.json'
        }
        self._ensure_files_exist()
    
    def _ensure_files_exist(self):
        """Create empty data files if they don't exist."""
        for key, path in self.data_files.items():
            if not path.exists():
                self._save_data(key, [])
    
    def _load_data(self, key: str) -> List[Dict]:
        """Load data from JSON file."""
        try:
            path = self.data_files[key]
            if path.exists():
                with open(path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            return []
        except (json.JSONDecodeError, FileNotFoundError):
            return []
    
    def _save_data(self, key: str, data: List[Dict]) -> bool:
        """Save data to JSON file."""
        try:
            path = self.data_files[key]
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2, default=str)
            return True
        except Exception:
            return False
    
    def get_all(self, key: str) -> List[Dict]:
        """Get all records from a collection."""
        return self._load_data(key)
    
    def get_by_id(self, key: str, record_id: int) -> Optional[Dict]:
        """Get a record by ID."""
        data = self._load_data(key)
        return next((item for item in data if item.get('id') == record_id), None)
    
    def get_by_field(self, key: str, field: str, value: Any) -> Optional[Dict]:
        """Get a record by a specific field value."""
        data = self._load_data(key)
        return next((item for item in data if item.get(field) == value), None)
    
    def get_all_by_field(self, key: str, field: str, value: Any) -> List[Dict]:
        """Get all records matching a field value."""
        data = self._load_data(key)
        return [item for item in data if item.get(field) == value]
    
    def create(self, key: str, record: Dict) -> Optional[Dict]:
        """Create a new record."""
        data = self._load_data(key)
        
        # Generate new ID
        existing_ids = [item.get('id', 0) for item in data]
        record['id'] = max(existing_ids, default=0) + 1
        
        # Set timestamps
        now = datetime.utcnow().isoformat()
        record['created_at'] = now
        record['updated_at'] = now
        
        data.append(record)
        if self._save_data(key, data):
            return record
        return None
    
    def update(self, key: str, record_id: int, updates: Dict) -> Optional[Dict]:
        """Update a record by ID."""
        data = self._load_data(key)
        for i, item in enumerate(data):
            if item.get('id') == record_id:
                updates['updated_at'] = datetime.utcnow().isoformat()
                data[i].update(updates)
                if self._save_data(key, data):
                    return data[i]
                break
        return None
    
    def delete(self, key: str, record_id: int) -> bool:
        """Delete a record by ID (hard delete)."""
        data = self._load_data(key)
        original_len = len(data)
        data = [item for item in data if item.get('id') != record_id]
        if len(data) < original_len:
            return self._save_data(key, data)
        return False
    
    def soft_delete(self, key: str, record_id: int) -> Optional[Dict]:
        """Mark a record as deleted (soft delete)."""
        return self.update(key, record_id, {'is_deleted': True})
    
    def count(self, key: str) -> int:
        """Count records in a collection."""
        return len(self._load_data(key))
    
    def count_by_field(self, key: str, field: str, value: Any) -> int:
        """Count records matching a field value."""
        data = self._load_data(key)
        return sum(1 for item in data if item.get(field) == value)


# Singleton instance
data_manager = DataManager()


# User-specific methods
def get_user_by_id(user_id: int) -> Optional[Dict]:
    """Get user by ID."""
    return data_manager.get_by_id('users', user_id)


def get_user_by_username(username: str) -> Optional[Dict]:
    """Get user by username."""
    return data_manager.get_by_field('users', 'username', username)


def get_user_by_email(email: str) -> Optional[Dict]:
    """Get user by email."""
    return data_manager.get_by_field('users', 'email', email)


def create_user(user_data: Dict) -> Optional[Dict]:
    """Create a new user."""
    # Check if this is the first user - they get creator role
    users = data_manager.get_all('users')
    if len(users) == 0:
        user_data['role'] = 'creator'
    else:
        user_data['role'] = 'user'
    user_data['is_verified'] = False
    user_data['verification_badge'] = None
    user_data['is_banned'] = False
    user_data['ban_reason'] = None
    user_data['ban_until'] = None
    user_data['read_only_mode'] = False
    user_data['post_count'] = 0
    user_data['comment_count'] = 0
    user_data['avatar'] = 'default_avatar.png'
    user_data['banner'] = 'default_banner.png'
    user_data['badges'] = []
    return data_manager.create('users', user_data)


def update_user(user_id: int, updates: Dict) -> Optional[Dict]:
    """Update user data."""
    return data_manager.update('users', user_id, updates)


# Post-specific methods
def get_post_by_id(post_id: int) -> Optional[Dict]:
    """Get post by ID."""
    return data_manager.get_by_id('posts', post_id)


def get_posts(limit: int = 20, offset: int = 0, user_id: Optional[int] = None) -> List[Dict]:
    """Get posts with pagination."""
    posts = data_manager.get_all('posts')
    
    # Filter by user if specified
    if user_id:
        posts = [p for p in posts if p.get('user_id') == user_id]
    
    # Exclude deleted posts
    posts = [p for p in posts if not p.get('is_deleted', False)]
    
    # Sort by creation date (newest first)
    posts.sort(key=lambda x: x.get('created_at', ''), reverse=True)
    
    return posts[offset:offset + limit]


def create_post(post_data: Dict) -> Optional[Dict]:
    """Create a new post."""
    post_data['reaction_count'] = {'like': 0, 'dislike': 0}
    post_data['comment_count'] = 0
    post_data['is_edited'] = False
    post_data['is_deleted'] = False
    post_data['visibility'] = 'public'
    post_data['media'] = post_data.get('media', [])
    
    post = data_manager.create('posts', post_data)
    
    if post:
        # Update user post count
        user = get_user_by_id(post_data['user_id'])
        if user:
            update_user(user['id'], {'post_count': user.get('post_count', 0) + 1})
    
    return post


def get_posts_count(user_id: Optional[int] = None) -> int:
    """Count posts."""
    posts = data_manager.get_all('posts')
    posts = [p for p in posts if not p.get('is_deleted', False)]
    if user_id:
        posts = [p for p in posts if p.get('user_id') == user_id]
    return len(posts)


# Comment-specific methods
def get_comments_by_post(post_id: int) -> List[Dict]:
    """Get all comments for a post."""
    comments = data_manager.get_all_by_field('comments', 'post_id', post_id)
    comments = [c for c in comments if not c.get('is_deleted', False)]
    comments.sort(key=lambda x: x.get('created_at', ''))
    return comments


def create_comment(comment_data: Dict) -> Optional[Dict]:
    """Create a new comment."""
    comment = data_manager.create('comments', comment_data)
    
    if comment:
        # Update post comment count
        post = get_post_by_id(comment_data['post_id'])
        if post:
            data_manager.update('posts', post['id'], {
                'comment_count': post.get('comment_count', 0) + 1
            })
        
        # Update user comment count
        user = get_user_by_id(comment_data['user_id'])
        if user:
            update_user(user['id'], {'comment_count': user.get('comment_count', 0) + 1})
    
    return comment


# Reaction-specific methods
def get_reaction(post_id: int, user_id: int) -> Optional[Dict]:
    """Get user's reaction to a post."""
    reactions = data_manager.get_all_by_field('reactions', 'post_id', post_id)
    return next((r for r in reactions if r.get('user_id') == user_id), None)


def create_reaction(reaction_data: Dict) -> Optional[Dict]:
    """Create or update a reaction."""
    existing = get_reaction(reaction_data['post_id'], reaction_data['user_id'])
    
    if existing:
        # Update existing reaction
        data_manager.update('reactions', existing['id'], {
            'reaction_type': reaction_data['reaction_type']
        })
        return data_manager.get_by_id('reactions', existing['id'])
    else:
        # Create new reaction
        reaction = data_manager.create('reactions', reaction_data)
        
        if reaction:
            post = get_post_by_id(reaction_data['post_id'])
            if post:
                counts = post.get('reaction_count', {'like': 0, 'dislike': 0})
                reaction_type = reaction_data['reaction_type']
                if reaction_type in counts:
                    counts[reaction_type] = counts.get(reaction_type, 0) + 1
                data_manager.update('posts', post['id'], {'reaction_count': counts})
        
        return reaction


def remove_reaction(post_id: int, user_id: int) -> bool:
    """Remove a reaction."""
    reaction = get_reaction(post_id, user_id)
    if reaction:
        post = get_post_by_id(post_id)
        if post:
            counts = post.get('reaction_count', {'like': 0, 'dislike': 0})
            reaction_type = reaction.get('reaction_type')
            if reaction_type in counts:
                counts[reaction_type] = max(0, counts[reaction_type] - 1)
            data_manager.update('posts', post['id'], {'reaction_count': counts})
        
        return data_manager.delete('reactions', reaction['id'])
    return False


# Application (verification) methods
def create_application(application_data: Dict) -> Optional[Dict]:
    """Create a verification application."""
    application_data['status'] = 'pending'
    application_data['reviewed_by'] = None
    application_data['reviewed_at'] = None
    application_data['decision'] = None
    application_data['photos'] = application_data.get('photos', [])
    return data_manager.create('applications', application_data)


def get_applications_by_user(user_id: int) -> List[Dict]:
    """Get all applications by a user."""
    apps = data_manager.get_all_by_field('applications', 'user_id', user_id)
    apps.sort(key=lambda x: x.get('created_at', ''), reverse=True)
    return apps


def get_pending_applications() -> List[Dict]:
    """Get all pending applications."""
    apps = data_manager.get_all_by_field('applications', 'status', 'pending')
    apps.sort(key=lambda x: x.get('created_at', ''))
    return apps


def process_application(app_id: int, decision: str, reviewer_id: int) -> Optional[Dict]:
    """Process a verification application."""
    now = datetime.utcnow().isoformat()
    app = data_manager.update('applications', app_id, {
        'status': decision,
        'reviewed_by': reviewer_id,
        'reviewed_at': now,
        'decision': decision
    })
    
    if app and decision == 'approved':
        # Give user verification badge
        user = get_user_by_id(app['user_id'])
        if user:
            update_user(user['id'], {'is_verified': True, 'verification_badge': 'verified'})
    
    return app


# Ban methods
def get_active_ban(user_id: int) -> Optional[Dict]:
    """Get active ban for a user."""
    bans = data_manager.get_all_by_field('bans', 'user_id', user_id)
    now = datetime.utcnow().isoformat()
    
    for ban in bans:
        if ban.get('is_active', False):
            expires_at = ban.get('expires_at')
            if expires_at is None or expires_at > now:
                return ban
            else:
                # Ban expired, mark as inactive
                data_manager.update('bans', ban['id'], {'is_active': False})
    
    return None


def create_ban(ban_data: Dict) -> Optional[Dict]:
    """Create a ban record."""
    ban_data['is_active'] = True
    ban = data_manager.create('bans', ban_data)
    
    if ban:
        # Update user ban status
        user = get_user_by_id(ban_data['user_id'])
        if user:
            update_user(user['id'], {
                'is_banned': True,
                'ban_reason': ban_data.get('reason'),
                'ban_until': ban_data.get('expires_at'),
                'read_only_mode': ban_data.get('ban_type') == 'read_only'
            })
    
    return ban


def remove_ban(user_id: int) -> bool:
    """Remove a ban from a user."""
    ban = get_active_ban(user_id)
    if ban:
        data_manager.update('bans', ban['id'], {'is_active': False})
        
        user = get_user_by_id(user_id)
        if user:
            update_user(user['id'], {
                'is_banned': False,
                'ban_reason': None,
                'ban_until': None,
                'read_only_mode': False
            })
        return True
    return False


# Report methods
def create_report(report_data: Dict) -> Optional[Dict]:
    """Create a report."""
    report_data['status'] = 'pending'
    return data_manager.create('reports', report_data)


def get_reports(status: Optional[str] = None) -> List[Dict]:
    """Get reports by status."""
    if status:
        return data_manager.get_all_by_field('reports', 'status', status)
    return data_manager.get_all('reports')


# Statistics methods
def get_statistics() -> Dict:
    """Get overall statistics."""
    users = data_manager.get_all('users')
    posts = data_manager.get_all('posts')
    comments = data_manager.get_all('comments')
    reactions = data_manager.get_all('reactions')
    
    # Count active (non-deleted) items
    active_posts = len([p for p in posts if not p.get('is_deleted', False)])
    active_comments = len([c for c in comments if not c.get('is_deleted', False)])
    
    # Count banned users
    banned_users = len([u for u in users if u.get('is_banned', False)])
    
    # Count verified users
    verified_users = len([u for u in users if u.get('is_verified', False)])
    
    return {
        'total_users': len(users),
        'active_users': len([u for u in users if not u.get('is_banned', False)]),
        'banned_users': banned_users,
        'verified_users': verified_users,
        'total_posts': active_posts,
        'total_comments': active_comments,
        'total_reactions': len(reactions),
        'admin_count': len([u for u in users if u.get('role') in config.ADMIN_ROLES])
    }


def get_top_users(limit: int = 10) -> List[Dict]:
    """Get top users by activity."""
    users = data_manager.get_all('users')
    users = [u for u in users if not u.get('is_banned', False)]
    
    # Calculate activity score
    for user in users:
        user['activity_score'] = (user.get('post_count', 0) * 2 + 
                                   user.get('comment_count', 0))
    
    users.sort(key=lambda x: x.get('activity_score', 0), reverse=True)
    return users[:limit]


# Notification methods
def create_notification(notification_data: Dict) -> Optional[Dict]:
    """Create a notification."""
    notification_data['is_read'] = False
    notification_data['link'] = notification_data.get('link', '')
    return data_manager.create('notifications', notification_data)


def get_notifications_by_user(user_id: int, limit: int = 50) -> List[Dict]:
    """Get notifications for a user."""
    notifications = data_manager.get_all_by_field('notifications', 'user_id', user_id)
    notifications.sort(key=lambda x: x.get('created_at', ''), reverse=True)
    return notifications[:limit]


def mark_notification_read(notification_id: int) -> bool:
    """Mark a notification as read."""
    return data_manager.update('notifications', notification_id, {'is_read': True}) is not None


def mark_all_notifications_read(user_id: int) -> int:
    """Mark all notifications for a user as read."""
    notifications = data_manager.get_all_by_field('notifications', 'user_id', user_id)
    count = 0
    for notification in notifications:
        if not notification.get('is_read', False):
            if data_manager.update('notifications', notification['id'], {'is_read': True}):
                count += 1
    return count


# Subscription methods
def create_subscription(follower_id: int, following_id: int) -> Optional[Dict]:
    """Create a subscription/follow relationship."""
    if follower_id == following_id:
        return None
    
    # Check if subscription already exists
    subscriptions = data_manager.get_all('subscriptions')
    for sub in subscriptions:
        if sub.get('follower_id') == follower_id and sub.get('following_id') == following_id:
            return None
    
    subscription_data = {
        'follower_id': follower_id,
        'following_id': following_id
    }
    return data_manager.create('subscriptions', subscription_data)


def remove_subscription(follower_id: int, following_id: int) -> bool:
    """Remove a subscription/follow relationship."""
    subscriptions = data_manager.get_all('subscriptions')
    for sub in subscriptions:
        if sub.get('follower_id') == follower_id and sub.get('following_id') == following_id:
            return data_manager.delete('subscriptions', sub['id'])
    return False


def get_subscriptions(user_id: int) -> List[Dict]:
    """Get all users that a user is following."""
    subscriptions = data_manager.get_all('subscriptions')
    return [sub for sub in subscriptions if sub.get('follower_id') == user_id]


def get_subscribers(user_id: int) -> List[Dict]:
    """Get all users that follow a user."""
    subscriptions = data_manager.get_all('subscriptions')
    return [sub for sub in subscriptions if sub.get('following_id') == user_id]


def is_subscribed(follower_id: int, following_id: int) -> bool:
    """Check if a user is following another user."""
    subscriptions = data_manager.get_all('subscriptions')
    for sub in subscriptions:
        if sub.get('follower_id') == follower_id and sub.get('following_id') == following_id:
            return True
    return False


# Admin action logging
def create_admin_log(log_data: Dict) -> Optional[Dict]:
    """Create an admin action log entry."""
    log_data['admin_id'] = log_data.get('admin_id')
    return data_manager.create('admin_logs', log_data)


def get_admin_logs(limit: int = 100) -> List[Dict]:
    """Get admin action logs."""
    logs = data_manager.get_all('admin_logs')
    logs.sort(key=lambda x: x.get('created_at', ''), reverse=True)
    return logs[:limit]


def get_admin_logs_by_admin(admin_id: int, limit: int = 50) -> List[Dict]:
    """Get admin action logs by a specific admin."""
    logs = data_manager.get_all_by_field('admin_logs', 'admin_id', admin_id)
    logs.sort(key=lambda x: x.get('created_at', ''), reverse=True)
    return logs[:limit]
