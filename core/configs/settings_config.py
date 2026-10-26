import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PORT: int = 8010
    MONGO_URL: str = "mongodb://localhost:27017"
    MONGO_DB_NAME: str = "AuthenticationServiceDb"
    ENVIRONMENT: str = "development"
    DEB_APIKEY: str
    DEB_SECRETS: str
    FRONTEND_URL: str = "http://localhost:5173"
    HYPERLOCAL_WEBSITE_URL: str = "http://localhost:5173/auth/callback"
    APP_DEEP_LINK: str = "hyperlocal://auth/callback"
    BACKEND_URL: str = os.getenv("BACKEND_URL") or os.getenv("AUTH_SERVICE_PUBLIC_URL") or "http://127.0.0.1:8010"
    GATEWAY_URL: str = os.getenv("GATEWAY_URL") or "http://127.0.0.1:8000"

    def get_public_base_url(self) -> str:
        # Returns public gateway base URL (with /api) or direct auth service base URL
        if self.GATEWAY_URL:
            g_url = self.GATEWAY_URL.rstrip('/')
            if not g_url.endswith("/api"):
                return f"{g_url}/api"
            return g_url
        url = (self.BACKEND_URL or f"http://127.0.0.1:{self.PORT}").rstrip("/")
        return url

    def get_verify_url(self, custom_url: str = None) -> str:
        if custom_url:
            return custom_url
        return f"{self.get_public_base_url()}/auth/verify"

    def get_signin_verify_url(self, custom_url: str = None) -> str:
        if custom_url:
            return custom_url
        return f"{self.get_public_base_url()}/auth/signin/verify"

    def get_signin_redirect_url(self, custom_url: str = None) -> str:
        if custom_url:
            return custom_url
        return f"{self.get_public_base_url()}/auth/signin/redirect"

    def get_signup_verify_url(self, custom_url: str = None) -> str:
        if custom_url:
            return custom_url
        return f"{self.get_public_base_url()}/auth/signup/verify"

    def get_signup_redirect_url(self, custom_url: str = None) -> str:
        if custom_url:
            return custom_url
        return f"{self.get_public_base_url()}/auth/signup/redirect"

    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASS: str = ""
    SMTP_FROM_EMAIL: str = ""

    # In non-production environments (ENVIRONMENT != 'production'), only users in DEV_ALLOWED_USERS can access
    RESTRICT_DEV_USERS: bool = os.getenv("RESTRICT_DEV_USERS", "true").lower() in ("true", "1", "yes")
    DEV_ALLOWED_USERS: str = '[{"email": "siva9670763@gmail.com", "password": "password123"}, {"email": "admin@inventq.in", "password": "AdminPassword123!"}]'

    def get_dev_allowed_users(self) -> list:
        import json
        if not self.DEV_ALLOWED_USERS:
            return []
        try:
            val = json.loads(self.DEV_ALLOWED_USERS)
            if isinstance(val, list):
                return val
            return []
        except Exception:
            return []

    def is_dev_allowed(self, email: str = None, password: str = None, mobilenumber: str = None) -> tuple[bool, str]:
        """
        Validates development environment user access.
        If in production, always returns (True, "").
        If in non-production and RESTRICT_DEV_USERS is True (default: True),
        ONLY users listed in DEV_ALLOWED_USERS are permitted.
        """
        if self.ENVIRONMENT.lower() == "production" or not self.RESTRICT_DEV_USERS:
            return True, ""
            
        allowed_list = self.get_dev_allowed_users()
        if not allowed_list:
            return True, ""
            
        clean_email = email.strip().lower() if email else None
        clean_phone = mobilenumber.strip() if mobilenumber else None

        if not clean_email and not clean_phone:
            return False, "Access restricted. Email or mobile number is required in this development environment."
            
        matched = None
        for item in allowed_list:
            if not isinstance(item, dict):
                continue
            item_email = item.get("email", "").strip().lower()
            item_phone = str(item.get("phone") or item.get("mobilenumber") or "").strip()
            
            if clean_email and item_email and item_email == clean_email:
                matched = item
                break
            if clean_phone and item_phone and item_phone == clean_phone:
                matched = item
                break
                
        if not matched:
            account_ident = clean_email or clean_phone
            return False, f"Access restricted. Account '{account_ident}' is not permitted in this non-production development environment."
            
        if password is not None and matched.get("password"):
            if str(matched.get("password")) != str(password):
                return False, "Incorrect credentials for this development account."
                
        return True, ""

    class Config:
        env_file = ".env"
        extra = "ignore"

SETTINGS = Settings()
