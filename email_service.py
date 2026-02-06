"""
Email service using Resend API for sending verification and notification emails.
"""
import logging
from typing import Optional
import config

logger = logging.getLogger(__name__)

try:
    import resend
    resend.api_key = None
except ImportError:
    resend = None

def get_verification_html(username: str, code: str) -> str:
    return f"""
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Подтверждение email - {config.SITE_NAME}</title>
</head>
<body style="margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f5f5f5;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width: 600px; margin: 0 auto; padding: 20px;">
        <tr>
            <td style="background-color: #ffffff; border-radius: 12px; padding: 40px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                <div style="text-align: center; margin-bottom: 30px;">
                    <h1 style="color: #18181b; margin: 0 0 10px; font-size: 28px;">{config.SITE_NAME}</h1>
                    <p style="color: #71717a; margin: 0; font-size: 16px;">Подтверждение email адреса</p>
                </div>
                
                <p style="color: #3f3f46; font-size: 16px; line-height: 1.6; margin-bottom: 25px;">
                    Привет, <strong>@{username}</strong>! Рады видеть вас в нашем сообществе.
                </p>
                
                <p style="color: #3f3f46; font-size: 16px; line-height: 1.6; margin-bottom: 30px;">
                    Пожалуйста, введите этот код на сайте для подтверждения вашего email:
                </p>
                
                <div style="text-align: center; margin-bottom: 30px; padding: 25px; background-color: #f5f5f5; border-radius: 12px;">
                    <span style="font-size: 36px; font-weight: 600; color: #18181b; letter-spacing: 8px;">{code}</span>
                </div>
                
                <p style="color: #a1a1aa; font-size: 14px; line-height: 1.6; margin-bottom: 30px;">
                    Если вы не регистрировались на {config.SITE_NAME}, просто проигнорируйте это письмо.
                </p>
                
                <p style="color: #a1a1aa; font-size: 13px; margin-top: 25px;">
                    С уважением,<br>
                    Команда <strong>{config.SITE_NAME}</strong>
                </p>
            </td>
        </tr>
        <tr>
            <td style="text-align: center; padding: 20px; color: #a1a1aa; font-size: 12px;">
                <p>&copy; 2026 {config.SITE_NAME}. Все права защищены.</p>
            </td>
        </tr>
    </table>
</body>
</html>
"""

def send_verification_email(email: str, username: str, code: str) -> bool:
    if resend is None:
        logger.warning("Resend library not installed, email not sent")
        return False
    
    try:
        resend.api_key = config.RESEND_API_KEY
        
        html_content = get_verification_html(username, code)
        
        r = resend.Emails.send({
            "from": f"noreply@{config.SITE_URL.replace('https://', '')}",
            "to": email,
            "subject": f"Подтверждение email - {config.SITE_NAME}",
            "html": html_content
        })
        
        logger.info(f"Verification email sent to {email}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send verification email: {e}")
        return False

def send_notification_email(email: str, subject: str, message: str) -> bool:
    if resend is None:
        logger.warning("Resend library not installed, email not sent")
        return False
    
    try:
        resend.api_key = config.RESEND_API_KEY
        
        html_content = f"""
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{subject}</title>
</head>
<body style="margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f5f5f5;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width: 600px; margin: 0 auto; padding: 20px;">
        <tr>
            <td style="background-color: #ffffff; border-radius: 12px; padding: 40px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                <div style="text-align: center; margin-bottom: 30px;">
                    <h1 style="color: #18181b; margin: 0 0 10px; font-size: 28px;">{config.SITE_NAME}</h1>
                </div>
                <p style="color: #3f3f46; font-size: 16px; line-height: 1.6;">{message}</p>
            </td>
        </tr>
        <tr>
            <td style="text-align: center; padding: 20px; color: #a1a1aa; font-size: 12px;">
                <p>&copy; 2026 {config.SITE_NAME}. Все права защищены.</p>
            </td>
        </tr>
    </table>
</body>
</html>
"""
        
        r = resend.Emails.send({
            "from": f"noreply@{config.SITE_URL.replace('https://', '')}",
            "to": email,
            "subject": subject,
            "html": html_content
        })
        
        logger.info(f"Notification email sent to {email}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send notification email: {e}")
        return False
