import smtplib
import secrets
import string
import logging
import asyncio
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from icecream import ic
from core.configs.settings_config import SETTINGS

logger = logging.getLogger("auth.email_helper")

def generate_secure_random_password(length: int = 12) -> str:
    """
    Generate a cryptographically secure, high-entropy password that includes
    uppercase, lowercase, digits, and special characters.
    """
    letters_lower = string.ascii_lowercase
    letters_upper = string.ascii_uppercase
    digits = string.digits
    symbols = "!@#$%^&*"
    all_chars = letters_lower + letters_upper + digits + symbols

    while True:
        pwd = [
            secrets.choice(letters_lower),
            secrets.choice(letters_upper),
            secrets.choice(digits),
            secrets.choice(symbols)
        ] + [secrets.choice(all_chars) for _ in range(length - 4)]
        secrets.SystemRandom().shuffle(pwd)
        generated = "".join(pwd)
        # Ensure it has all required character classes
        if (any(c.islower() for c in generated) and
            any(c.isupper() for c in generated) and
            any(c.isdigit() for c in generated) and
            any(c in symbols for c in generated)):
            return generated


def _send_credentials_sync(email: str, name: str, password: str, login_url: str) -> bool:
    """Synchronous worker that connects to SMTP server and sends credentials email."""
    smtp_host = SETTINGS.SMTP_HOST
    smtp_port = SETTINGS.SMTP_PORT
    smtp_user = SETTINGS.SMTP_USER
    smtp_pass = SETTINGS.SMTP_PASS
    from_email = SETTINGS.SMTP_FROM_EMAIL or smtp_user or "no-reply@inventq.in"

    subject = "Welcome to inventQ — Your Account Credentials"

    plain_body = f"""Hello {name or 'User'},

Welcome to inventQ! Your account has been successfully created.

Here are your account credentials to log in:
---------------------------------------------
Email: {email}
Temporary Password: {password}
---------------------------------------------

You can sign in directly at:
{login_url}

Please change your password after your first login for security.

Best regards,
The inventQ Team
"""

    html_body = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Your Account Credentials</title>
</head>
<body style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f8fafc; margin: 0; padding: 24px;">
  <div style="max-width: 540px; margin: 0 auto; background: #ffffff; border-radius: 16px; border: 1px solid #e2e8f0; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.05);">
    <div style="background: linear-gradient(135deg, #184227 0%, #0d2616 100%); padding: 32px 28px; text-align: center;">
      <h1 style="color: #ffffff; margin: 0; font-size: 24px; font-weight: 700; letter-spacing: -0.5px;">inventQ</h1>
      <p style="color: #a8c898; margin: 6px 0 0; font-size: 13px;">Retail, POS & Inventory Management Platform</p>
    </div>
    <div style="padding: 32px 28px;">
      <h2 style="color: #0f172a; margin-top: 0; font-size: 18px; font-weight: 600;">Welcome to inventQ, {name or 'User'}!</h2>
      <p style="color: #475569; font-size: 14px; line-height: 1.6; margin: 0 0 20px;">
        Your account has been created. A secure, randomly generated password has been assigned so you can log in directly using your email and password.
      </p>

      <div style="background: #f1f5f9; border-left: 4px solid #184227; padding: 16px 20px; border-radius: 8px; margin-bottom: 24px;">
        <div style="font-size: 12px; color: #64748b; text-transform: uppercase; font-weight: 600; letter-spacing: 0.5px; margin-bottom: 4px;">Login Email</div>
        <div style="font-size: 15px; font-weight: 600; color: #0f172a; font-family: monospace; margin-bottom: 12px;">{email}</div>

        <div style="font-size: 12px; color: #64748b; text-transform: uppercase; font-weight: 600; letter-spacing: 0.5px; margin-bottom: 4px;">Generated Password</div>
        <div style="font-size: 17px; font-weight: 700; color: #184227; font-family: monospace; letter-spacing: 1px; background: #ffffff; padding: 8px 12px; border-radius: 6px; border: 1px solid #cbd5e1; display: inline-block;">{password}</div>
      </div>

      <div style="text-align: center; margin: 28px 0;">
        <a href="{login_url}" style="background: #184227; color: #ffffff; text-decoration: none; padding: 12px 32px; border-radius: 10px; font-weight: 600; font-size: 14px; display: inline-block; box-shadow: 0 4px 8px rgba(24,66,39,0.25);">
          Sign In Now &rarr;
        </a>
      </div>

      <p style="color: #64748b; font-size: 12px; line-height: 1.5; margin: 20px 0 0; text-align: center;">
        For security, we recommend updating your password in your Profile Settings after signing in.
      </p>
    </div>
    <div style="background: #f8fafc; border-top: 1px solid #e2e8f0; padding: 16px 28px; text-align: center; font-size: 11px; color: #94a3b8;">
      &copy; 2026 inventQ by Antaris Software Pvt Ltd. All rights reserved.
    </div>
  </div>
</body>
</html>"""

    # Check if SMTP configuration is active
    if not smtp_user or not smtp_pass or SETTINGS.ENVIRONMENT.lower() == "development" and not smtp_pass:
        ic("--- [DEV/FALLBACK] Account Credentials Generated ---")
        ic(f"To: {email}")
        ic(f"Name: {name}")
        ic(f"Password: {password}")
        ic(f"Login URL: {login_url}")
        ic("--------------------------------------------------")
        logger.info(f"[DEV/FALLBACK] Generated Password for {email} is: {password}")
        if not smtp_user or not smtp_pass:
            return True

    try:
        msg = MIMEMultipart("alternative")
        msg["From"] = from_email
        msg["To"] = email
        msg["Subject"] = subject
        msg.attach(MIMEText(plain_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        server = smtplib.SMTP(smtp_host, smtp_port, timeout=15)
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)
        server.quit()
        logger.info(f"Account credentials email successfully sent to {email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send credentials email to {email}: {e}")
        ic(f"Failed to send email to {email}: {e}")
        return False


async def send_account_credentials_email(email: str, name: str, password: str, login_url: str = None) -> bool:
    """Asynchronously sends the account credentials email with random password to the user."""
    target_login_url = login_url or f"{SETTINGS.FRONTEND_URL}/login"
    try:
        return await asyncio.to_thread(_send_credentials_sync, email, name, password, target_login_url)
    except Exception as e:
        logger.error(f"Error in send_account_credentials_email: {e}")
        return False
