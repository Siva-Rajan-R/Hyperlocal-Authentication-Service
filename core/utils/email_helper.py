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


def _send_account_deletion_otp_sync(email: str, name: str, otp: str) -> bool:
    """Synchronous worker that connects to SMTP server and sends account deletion verification code."""
    smtp_host = SETTINGS.SMTP_HOST
    smtp_port = SETTINGS.SMTP_PORT
    smtp_user = SETTINGS.SMTP_USER
    smtp_pass = SETTINGS.SMTP_PASS
    from_email = SETTINGS.SMTP_FROM_EMAIL or smtp_user or "debuggerstechs@gmail.com"

    subject = f"ShopiQ Security: Account Deletion Code [{otp}]"

    plain_body = f"""Hello {name or 'ShopiQ Customer'},

A request has been initiated to permanently delete your ShopiQ customer account for email: {email}.

Your one-time 6-digit verification code is:
=============================================
{otp}
=============================================

SECURITY NOTICE & COMPLIANCE:
- This verification code is valid for 10 minutes.
- Confirming this code will immediately soft-delete your customer account, addresses, and session access.
- In accordance with commercial, taxation, and accounting regulations, past order records will be retained securely on the merchant/retailer platform (InventQ) for bookkeeping and compliance.
- If you did NOT request account deletion, please do NOT share this code with anyone and change your password immediately.

Best regards,
ShopiQ & inventQ Security Team
"""

    html_body = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Account Deletion Code</title>
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f8fafc; margin: 0; padding: 24px; color: #1e293b;">
  <div style="max-width: 540px; margin: 0 auto; background: #ffffff; border-radius: 16px; border: 1px solid #e2e8f0; overflow: hidden; box-shadow: 0 4px 14px rgba(0,0,0,0.06);">
    <!-- Header -->
    <div style="background: linear-gradient(135deg, #ea580c 0%, #c2410c 100%); padding: 30px 24px; text-align: center;">
      <h1 style="color: #ffffff; margin: 0; font-size: 24px; font-weight: 800; letter-spacing: -0.5px;">ShopiQ</h1>
      <p style="color: #fed7aa; margin: 6px 0 0; font-size: 13px; font-weight: 500;">Account Security & Privacy Verification</p>
    </div>

    <!-- Body Content -->
    <div style="padding: 28px 24px;">
      <h2 style="color: #0f172a; margin-top: 0; font-size: 18px; font-weight: 700;">Account Deletion Request</h2>
      <p style="color: #475569; font-size: 14px; line-height: 1.6; margin: 0 0 20px;">
        Hello <strong>{name or 'Customer'}</strong>,<br/>
        We received a request to permanently delete your ShopiQ customer account associated with <strong>{email}</strong>.
      </p>

      <!-- OTP Box -->
      <div style="background: #fff7ed; border: 1.5px dashed #f97316; border-radius: 12px; padding: 20px; text-align: center; margin-bottom: 24px;">
        <div style="font-size: 12px; color: #9a3412; text-transform: uppercase; font-weight: 700; letter-spacing: 0.8px; margin-bottom: 6px;">Your One-Time Verification Code</div>
        <div style="font-size: 34px; font-weight: 900; color: #ea580c; font-family: monospace; letter-spacing: 8px;">{otp}</div>
        <div style="font-size: 12px; color: #7c2d12; margin-top: 6px;">Valid for 10 minutes &bull; Do not share with anyone</div>
      </div>

      <!-- Information box -->
      <div style="background: #f1f5f9; border-radius: 10px; padding: 14px 16px; margin-bottom: 20px; font-size: 13px; color: #475569; line-height: 1.55;">
        <div style="font-weight: 700; color: #0f172a; margin-bottom: 4px;">Important Note on Scope:</div>
        This action applies exclusively to your ShopiQ customer shopping account, saved addresses, and favorites. Your <strong>inventQ merchant stores, business dashboard, and retailer account</strong> remain completely unaffected and active.
      </div>

      <p style="color: #dc2626; font-size: 12.5px; line-height: 1.5; margin: 0; font-weight: 600;">
        If you did NOT request this code, please disregard this email. Your account remains completely secure.
      </p>
    </div>

    <!-- Footer -->
    <div style="background: #f8fafc; border-top: 1px solid #e2e8f0; padding: 16px 24px; text-align: center; font-size: 11px; color: #94a3b8;">
      &copy; 2026 ShopiQ & inventQ. All rights reserved.
    </div>
  </div>
</body>
</html>"""

    if not smtp_user or not smtp_pass:
        ic("--- [DEV/FALLBACK] Deletion OTP Generated ---")
        ic(f"To: {email}")
        ic(f"OTP: {otp}")
        ic("--------------------------------------------")
        logger.info(f"[DEV/FALLBACK] Deletion OTP for {email} is: {otp}")
        return True

    try:
        msg = MIMEMultipart("alternative")
        msg["From"] = f"ShopiQ Security <{from_email}>"
        msg["To"] = email
        msg["Subject"] = subject
        msg.attach(MIMEText(plain_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        server = smtplib.SMTP(smtp_host, smtp_port, timeout=15)
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)
        server.quit()
        logger.info(f"Account deletion OTP email successfully sent to {email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send deletion OTP email to {email}: {e}")
        ic(f"Failed to send deletion OTP email to {email}: {e}")
        return False


async def send_account_deletion_otp_email(email: str, name: str, otp: str) -> bool:
    """Asynchronously sends the account deletion verification OTP email."""
    try:
        return await asyncio.to_thread(_send_account_deletion_otp_sync, email, name, otp)
    except Exception as e:
        logger.error(f"Error in send_account_deletion_otp_email: {e}")
        return False


def _send_shopiq_welcome_sync(email: str, name: str) -> bool:
    """Synchronous worker that connects to SMTP server and sends a ShopiQ customer welcome email."""
    smtp_host = SETTINGS.SMTP_HOST
    smtp_port = SETTINGS.SMTP_PORT
    smtp_user = SETTINGS.SMTP_USER
    smtp_pass = SETTINGS.SMTP_PASS
    from_email = SETTINGS.SMTP_FROM_EMAIL or smtp_user or "debuggerstechs@gmail.com"

    subject = "Welcome to ShopiQ! 🎉"

    plain_body = f"""Hello {name or 'Valued Customer'},

Welcome to ShopiQ! We are thrilled to have you with us.

With ShopiQ, you can:
• Discover hidden local shops and stores in your neighborhood
• Check real-time product prices and in-store availability
• Browse, shop online, and place orders with fast doorstep delivery or pickup

Open the ShopiQ app anytime to explore what's around you.

If you ever need help, feel free to contact our support team at supportshopiq@gmail.com.

Happy shopping!
Warm regards,
The ShopiQ Team
https://shopiq.inventq.in
"""

    html_body = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Welcome to ShopiQ</title>
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #fdfbf7; margin: 0; padding: 24px; color: #1c1917;">
  <div style="max-width: 540px; margin: 0 auto; background: #ffffff; border-radius: 20px; border: 1px solid #f1f5f9; overflow: hidden; box-shadow: 0 4px 18px rgba(0,0,0,0.06);">
    <!-- Header banner with ShopiQ orange theme -->
    <div style="background: linear-gradient(135deg, #f97316 0%, #ea580c 100%); padding: 36px 24px; text-align: center;">
      <h1 style="color: #ffffff; margin: 0; font-size: 28px; font-weight: 800; letter-spacing: -0.5px;">ShopiQ</h1>
      <p style="color: #ffedd5; margin: 8px 0 0; font-size: 14px; font-weight: 500;">Discover Local Shops &amp; Shop with Ease</p>
    </div>

    <!-- Body Content -->
    <div style="padding: 32px 28px;">
      <h2 style="color: #1c1917; margin-top: 0; font-size: 20px; font-weight: 700;">Welcome, {name or 'Friend'}! 👋</h2>
      <p style="color: #57534e; font-size: 14.5px; line-height: 1.6; margin: 0 0 24px;">
        Thank you for joining <strong>ShopiQ</strong>. Your customer account is all set up and ready to go. You can now explore neighborhood shops, view real-time catalog items, and order directly from local retailers.
      </p>

      <!-- Key features highlights -->
      <div style="background: #fff7ed; border: 1px solid #fed7aa; border-radius: 14px; padding: 20px; margin-bottom: 26px;">
        <div style="font-size: 13px; font-weight: 700; color: #9a3412; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 12px;">What you can do with ShopiQ:</div>
        
        <table role="presentation" style="width: 100%; border-collapse: collapse;">
          <tr>
            <td style="vertical-align: top; width: 32px; font-size: 20px; padding: 6px 0;">📍</td>
            <td style="padding: 6px 0 12px 10px;">
              <div style="font-size: 14px; font-weight: 600; color: #1c1917;">Discover Local Stores</div>
              <div style="font-size: 12.5px; color: #78716c; line-height: 1.4;">Find hidden gems and trusted neighborhood shops around you.</div>
            </td>
          </tr>
          <tr>
            <td style="vertical-align: top; width: 32px; font-size: 20px; padding: 6px 0;">⚡</td>
            <td style="padding: 6px 0 12px 10px;">
              <div style="font-size: 14px; font-weight: 600; color: #1c1917;">Live Catalog &amp; Stock</div>
              <div style="font-size: 12.5px; color: #78716c; line-height: 1.4;">Browse product prices and check store availability before ordering.</div>
            </td>
          </tr>
          <tr>
            <td style="vertical-align: top; width: 32px; font-size: 20px; padding: 6px 0;">🛍️</td>
            <td style="padding: 6px 0 4px 10px;">
              <div style="font-size: 14px; font-weight: 600; color: #1c1917;">Seamless Ordering</div>
              <div style="font-size: 12.5px; color: #78716c; line-height: 1.4;">Place orders effortlessly and track status right from your phone.</div>
            </td>
          </tr>
        </table>
      </div>

      <!-- Call to Action -->
      <div style="text-align: center; margin: 30px 0 10px;">
        <a href="https://shopiq.inventq.in" style="background: #f97316; color: #ffffff; text-decoration: none; padding: 13px 36px; border-radius: 12px; font-weight: 700; font-size: 14px; display: inline-block; box-shadow: 0 4px 12px rgba(249,115,22,0.3);">
          Explore ShopiQ &rarr;
        </a>
      </div>

      <p style="color: #a8a29e; font-size: 12px; line-height: 1.5; margin: 24px 0 0; text-align: center;">
        Need assistance or have feedback? Reach us at <a href="mailto:supportshopiq@gmail.com" style="color: #f97316; text-decoration: none; font-weight: 600;">supportshopiq@gmail.com</a>.
      </p>
    </div>

    <!-- Footer -->
    <div style="background: #fdfbf7; border-top: 1px solid #f1f5f9; padding: 18px 24px; text-align: center; font-size: 11px; color: #a8a29e;">
      &copy; 2026 ShopiQ by InventQ. All rights reserved.
    </div>
  </div>
</body>
</html>"""

    if not smtp_user or not smtp_pass:
        ic("--- [DEV/FALLBACK] ShopiQ Welcome Email ---")
        ic(f"To: {email}")
        ic(f"Name: {name}")
        ic("------------------------------------------")
        logger.info(f"[DEV/FALLBACK] Welcome email for ShopiQ customer {email}")
        return True

    try:
        msg = MIMEMultipart("alternative")
        msg["From"] = f"ShopiQ <{from_email}>"
        msg["To"] = email
        msg["Subject"] = subject
        msg.attach(MIMEText(plain_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        server = smtplib.SMTP(smtp_host, smtp_port, timeout=15)
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)
        server.quit()
        logger.info(f"ShopiQ welcome email successfully sent to {email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send ShopiQ welcome email to {email}: {e}")
        ic(f"Failed to send ShopiQ welcome email to {email}: {e}")
        return False


async def send_shopiq_welcome_email(email: str, name: str) -> bool:
    """Asynchronously sends the ShopiQ customer welcome email."""
    try:
        return await asyncio.to_thread(_send_shopiq_welcome_sync, email, name)
    except Exception as e:
        logger.error(f"Error in send_shopiq_welcome_email: {e}")
        return False
