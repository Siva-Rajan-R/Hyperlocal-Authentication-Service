import datetime
import uuid
import httpx
import jwt
from fastapi import APIRouter, HTTPException, Depends, Query, Request, Response
from fastapi.responses import RedirectResponse, JSONResponse
import json
import re
from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional, List, Any
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from icecream import ic

# Cryptography imports for RSA key generation
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from core.configs.settings_config import SETTINGS
from infras.db.mongo import get_collection
from dotenv import load_dotenv
load_dotenv()
from hyperlocal_platform.infras.redis.main import redis_client
from core.utils.email_helper import generate_secure_random_password, send_account_credentials_email, send_account_deletion_otp_email, send_shopiq_welcome_email

# Account Deletion Schemas
class RequestAccountDeletionOtpSchema(BaseModel):
    user_id: Optional[str] = None
    email: Optional[str] = None
    scope: Optional[str] = "shopiq"

class VerifyAccountDeletionOtpSchema(BaseModel):
    user_id: Optional[str] = None
    email: Optional[str] = None
    otp: str
    scope: Optional[str] = "shopiq"

router = APIRouter(prefix="/auth", tags=["Authentication"])
ph = PasswordHasher()

# JWT Config
ACCESS_TOKEN_EXPIRE_MINUTES = 60
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Pydantic Schemas
class GenerateKeySchema(BaseModel):
    version: str

class CallbackSchema(BaseModel):
    token_id: str
    service: str
    version: Optional[str] = "1"

class RefreshSchema(BaseModel):
    refresh_token: str
    version: Optional[str] = None

class RevokeSchema(BaseModel):
    token: str

class UserCreateManualSchema(BaseModel):
    user_id: Optional[str] = None
    email: EmailStr
    mobilenumber: str
    password: str
    two_factor: bool = False

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v):
        if isinstance(v, str):
            return v.strip().lower()
        return v

class SignupRequestSchema(BaseModel):
    email: EmailStr
    name: Optional[str] = None
    mobilenumber: Optional[str] = None
    password: Optional[str] = None
    custom_fields: Optional[dict] = None
    additional_infos: Optional[dict] = None

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v):
        if isinstance(v, str) and v.strip():
            return v.strip().lower()
        return v

class SignupVerifySchema(BaseModel):
    email: Optional[str] = None
    mobilenumber: Optional[str] = None

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v):
        if isinstance(v, str) and v.strip():
            return v.strip().lower()
        return v

class UserVerifySchema(BaseModel):
    email: Optional[str] = None
    mobilenumber: Optional[str] = None

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v):
        if isinstance(v, str) and v.strip():
            return v.strip().lower()
        return v

class LoginRequestSchema(BaseModel):
    email: Optional[str] = None
    mobilenumber: Optional[str] = None
    password: str
    service: Optional[str] = "HYPERLOCAL"
    version: Optional[str] = "1"
    entity_name: Optional[str] = None
    entity_type: Optional[str] = None

class UserResponseSchema(BaseModel):
    user_id: str
    email: Optional[str] = None
    mobilenumber: Optional[str] = None
    name: Optional[str] = None
    custom_fields: Optional[dict] = None
    additional_infos: Optional[dict] = None
    two_factor: bool = False

class ForgotPasswordSchema(BaseModel):
    email: Optional[str] = None
    mobilenumber: Optional[str] = None

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v):
        if isinstance(v, str) and v.strip():
            return v.strip().lower()
        return v

class ResetPasswordSchema(BaseModel):
    reset_token: Optional[str] = None
    email: Optional[str] = None
    mobilenumber: Optional[str] = None
    user_id: Optional[str] = None
    new_password: str

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v):
        if isinstance(v, str) and v.strip():
            return v.strip().lower()
        return v

class ChangePasswordSchema(BaseModel):
    email: Optional[str] = None
    mobilenumber: Optional[str] = None
    user_id: Optional[str] = None
    old_password: str
    new_password: str

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v):
        if isinstance(v, str) and v.strip():
            return v.strip().lower()
        return v



DAUTH_BASE_URL="https://api.dauth.debuggerstechnologies.com"
# DAUTH_BASE_URL="http://127.0.0.1:8100"

# Helpers
def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return private_pem, public_pem

async def get_keys_for_version(version: str):
    keys_coll = get_collection("keys")
    key_doc = await keys_coll.find_one({"version": version})
    if not key_doc:
        raise HTTPException(status_code=404, detail=f"RSA keys version '{version}' not found.")
    return key_doc["private_key"], key_doc["public_key"]


# Auth Endpoints

@router.post("/keys/generate")
async def generate_keys(data: GenerateKeySchema):
    keys_coll = get_collection("keys")
    existing = await keys_coll.find_one({"version": data.version})
    if existing:
        raise HTTPException(status_code=400, detail=f"Key version '{data.version}' already exists.")
    
    private_pem, public_pem = generate_rsa_keypair()
    await keys_coll.insert_one({
        "version": data.version,
        "private_key": private_pem,
        "public_key": public_pem,
        "created_at": datetime.datetime.utcnow()
    })
    return {"message": f"Successfully generated key pair version '{data.version}'."}

@router.get("/keys/{version}")
async def get_public_key(version: str):
    _, public_key = await get_keys_for_version(version)
    return {"version": version, "public_key": public_key}

def is_valid_frontend_redirect_url(url: Optional[str]) -> bool:
    if not url or not isinstance(url, str):
        return False
    trimmed = str(url).strip()
    # App deep links and shopiq URLs are always valid frontend targets
    if "shopiq.inventq.in" in trimmed or trimmed.startswith("hyperlocal://") or trimmed.startswith("hyperlocal-app://") or trimmed.startswith("shopiq://"):
        return True
    # If the URL points to backend/gateway auth redirect/verify endpoints, it is NOT a valid frontend URL
    blocked_endpoints = [
        "/auth/signin/redirect",
        "/auth/signup/redirect",
        "/auth/signin/verify",
        "/auth/signup/verify",
        "/auth/callback",
        "/api/auth/signin/redirect",
        "/api/auth/signup/redirect",
        "/api/auth/signin/verify",
        "/api/auth/signup/verify",
        "/api/auth/callback",
    ]
    for ep in blocked_endpoints:
        if ep in url:
            return False
    return True

KNOWN_APP_DEB_APIKEYS = {
    "DAuth-P-4RzbzRX7pO_oyhX4jypZMbkfN6qDdR8FZUkAhXkQM",
    "DAuth-2A9WNniXklWJ2fdFRhlRnyh8x9y829F52mmY55F67AM"
}

def is_app_login_request(
    entity_type: Optional[str] = None,
    client_type: Optional[str] = None,
    platform: Optional[str] = None,
    redirect_url: Optional[str] = None,
    app: Optional[Any] = None,
    service: Optional[str] = None,
    api_key: Optional[str] = None
) -> bool:
    """Helper to detect if login or signup was requested by mobile app."""
    if api_key and (api_key == SETTINGS.APP_DEB_APIKEY or api_key in KNOWN_APP_DEB_APIKEYS):
        return True
    if entity_type and str(entity_type).strip().lower() in ("app", "mobile", "application", "android", "ios"):
        return True
    if client_type and str(client_type).strip().lower() in ("app", "mobile", "application"):
        return True
    if platform and str(platform).strip().lower() in ("app", "mobile", "android", "ios"):
        return True
    if app is not None:
        if isinstance(app, bool) and app:
            return True
        if str(app).strip().lower() in ("true", "1", "yes"):
            return True
    if service and "APP" in str(service).upper():
        return True
    if redirect_url:
        trimmed = str(redirect_url).strip()
        if trimmed.startswith("hyperlocal://") or trimmed.startswith("hyperlocal-app://") or trimmed.startswith("shopiq://"):
            return True
        if "shopiq.inventq.in" in trimmed:
            return True
        if "://" in trimmed and not (trimmed.startswith("http://") or trimmed.startswith("https://")):
            return True
    return False

def check_is_app(request: Optional[Request] = None, body: Optional[dict] = None) -> bool:
    """
    Comprehensive detector to verify if an incoming request originated from the ShopiQ mobile app.
    Checks:
    - Route URL path (/app/)
    - Request Query parameters (is_app, entity_type, client_type, platform, service, redirect_url)
    - Request Headers (x-api-key, apikey, client-id, x-client-type, x-entity-type, referer, origin)
    - Cookie oauth_state (is_app, entity_type)
    - Body fields & nested additional_infos/custom_fields
    - Known App DAuth API keys
    """
    app_keys = {
        SETTINGS.APP_DEB_APIKEY,
        *KNOWN_APP_DEB_APIKEYS
    }
    
    if request:
        try:
            path = request.url.path.lower()
            if "/app/" in path or path.endswith("/app"):
                return True
        except Exception:
            pass

        # Check query parameters
        try:
            for k, v in request.query_params.items():
                k_low = k.lower()
                v_str = str(v).strip().lower()
                if k_low in ("is_app", "app") and v_str in ("true", "1", "yes"):
                    return True
                if k_low in ("entity_type", "client_type", "platform") and v_str in ("app", "mobile", "application", "android", "ios"):
                    return True
                if k_low == "service" and "APP" in str(v).upper():
                    return True
                if k_low in ("redirect_url", "url") and ("shopiq" in v_str or "hyperlocal://" in v_str or "hyperlocal-app://" in v_str):
                    return True
                if k_low in ("apikey", "client_id", "api_key") and v in app_keys:
                    return True
        except Exception:
            pass

        # Check headers
        try:
            for hdr_name in ("x-api-key", "apikey", "client-id", "x-dauth-apikey"):
                hdr_val = request.headers.get(hdr_name)
                if hdr_val and hdr_val in app_keys:
                    return True
            if request.headers.get("x-client-type", "").lower() in ("app", "mobile"):
                return True
            if request.headers.get("x-entity-type", "").lower() in ("app", "mobile"):
                return True
            referer = request.headers.get("referer", "").lower()
            if "shopiq" in referer or "hyperlocal" in referer:
                return True
        except Exception:
            pass

        # Check oauth_state cookie
        try:
            cookie_state = request.cookies.get("oauth_state")
            if cookie_state:
                st = json.loads(cookie_state)
                if bool(st.get("is_app")) or str(st.get("entity_type") or "").lower() == "app" or str(st.get("client_type") or "").lower() == "app" or "APP" in str(st.get("service") or "").upper():
                    return True
        except Exception:
            pass

    if body and isinstance(body, dict):
        if body.get("is_app") is True or str(body.get("is_app")).lower() in ("true", "1", "yes"):
            return True
        b_key = body.get("apikey") or body.get("client_id") or body.get("api_key")
        if b_key and b_key in app_keys:
            return True
            
        additional = body.get("additional_infos") if isinstance(body.get("additional_infos"), dict) else {}
        if additional.get("is_app") is True or str(additional.get("is_app")).lower() in ("true", "1", "yes"):
            return True
        add_key = additional.get("apikey") or additional.get("client_id")
        if add_key and add_key in app_keys:
            return True

        custom = body.get("custom_fields") if isinstance(body.get("custom_fields"), dict) else {}

        for source in (body, additional, custom):
            if not isinstance(source, dict):
                continue
            ent = str(source.get("entity_type") or "").strip().lower()
            cli = str(source.get("client_type") or "").strip().lower()
            plt = str(source.get("platform") or "").strip().lower()
            app_val = source.get("app")
            srv = str(source.get("service") or "").upper()
            red = str(source.get("redirect_url") or "")
            b_key_src = source.get("apikey") or source.get("client_id")
            if is_app_login_request(entity_type=ent, client_type=cli, platform=plt, redirect_url=red, app=app_val, service=srv, api_key=b_key_src):
                return True

    return False

@router.get("/login-url")
@router.get("/signin-url")
@router.get("/signin/url")
async def get_login_url(
    response: Response,
    service: str = Query("HYPERLOCAL-INVENTORY"),
    version: Optional[str] = Query("1"),
    entity_name: Optional[str] = Query(None),
    entity_type: Optional[str] = Query(None),
    client_type: Optional[str] = Query(None),
    platform: Optional[str] = Query(None),
    app: Optional[str] = Query(None),
    redirect_url: Optional[str] = Query(None),
    verify_url: Optional[str] = Query(None),
    flow_type: Optional[str] = Query("signin"),
    temp_id: Optional[str] = Query(None)
):
    # Determine if app login was requested
    is_app = is_app_login_request(
        entity_type=entity_type,
        client_type=client_type,
        platform=platform,
        redirect_url=redirect_url,
        app=app,
        service=service
    )
    api_key, _ = SETTINGS.get_dauth_credentials(is_app=is_app)
    effective_entity_type = entity_type or ("app" if is_app else None)

    # Generate unique temporary polling ticket ID if not provided (5 minutes expiry)
    effective_temp_id = (temp_id or str(uuid.uuid4())).strip()
    poll_redis_key = f"auth_poll:{effective_temp_id}"
    try:
        await redis_client.set(
            poll_redis_key,
            json.dumps({
                "status": "pending",
                "temp_id": effective_temp_id,
                "service": service,
                "version": version,
                "is_app": is_app,
                "flow_type": flow_type or "signin",
                "created_at": datetime.datetime.utcnow().isoformat()
            }),
            ex=300
        )
    except Exception as redis_err:
        ic(f"Failed to record auth_poll pending status in Redis: {redis_err}")

    # Determine unified verify and redirect URLs for signin
    effective_verify_url = SETTINGS.get_app_verify_url(verify_url) if is_app else SETTINGS.get_verify_url(verify_url)
    backend_redirect_url = SETTINGS.get_signin_redirect_url()
    if is_app:
        sep_v = "&" if "?" in effective_verify_url else "?"
        effective_verify_url = f"{effective_verify_url}{sep_v}is_app=true&client_type=app&entity_type=app&service={service or 'HYPERLOCAL_APP'}"
        sep_r = "&" if "?" in backend_redirect_url else "?"
        backend_redirect_url = f"{backend_redirect_url}{sep_r}is_app=true&client_type=app&entity_type=app&service={service or 'HYPERLOCAL_APP'}"

    # Append temp_id to backend redirect URL so callback can map tokens
    sep_t = "&" if "?" in backend_redirect_url else "?"
    backend_redirect_url = f"{backend_redirect_url}{sep_t}temp_id={effective_temp_id}"

    frontend_target_url = redirect_url if (redirect_url and ("://" in redirect_url or is_valid_frontend_redirect_url(redirect_url))) else None
    if not frontend_target_url and is_app:
        frontend_target_url = SETTINGS.APP_DEEP_LINK

    # Connects to Debugger Auth for signin
    constructed_url = f"{DAUTH_BASE_URL}/auth"
    payload = {
        "apikey": api_key,
        "flow_type": flow_type or "signin",
        "verify_url": effective_verify_url,
        "redirect_url": backend_redirect_url,
        "callback_url": backend_redirect_url,
        "additional_infos": {
            "entity_name": entity_name,
            "entity_type": effective_entity_type,
            "client_type": "app" if is_app else "web",
            "is_app": is_app,
            "redirect_url": frontend_target_url,
            "service": service,
            "version": version,
            "flow_type": flow_type or "signin",
            "verify_url": effective_verify_url,
            "backend_redirect_url": backend_redirect_url,
            "temp_id": effective_temp_id
        }
    }
    async with httpx.AsyncClient(timeout=30) as client:
        response_data = await client.post(
            constructed_url,
            json=payload
        )
        ic(response_data.text)
    
    if response_data.status_code != 200:
        raise HTTPException(
            status_code=response_data.status_code,
            detail="Failed to fetch login URLs from Debugger Auth"
        )
    
    res = response_data.json()
    state_val = json.dumps({
        "service": service,
        "version": version,
        "entity_name": entity_name,
        "entity_type": effective_entity_type,
        "is_app": is_app,
        "redirect_url": frontend_target_url,
        "verify_url": effective_verify_url,
        "flow_type": flow_type or "signin",
        "temp_id": effective_temp_id
    })
    response.set_cookie(key="oauth_state", value=state_val, max_age=900, samesite="lax")
    signin_url = res.get("signin_url") or res.get("url")
    return {
        "signin_url": signin_url,
        "signup_url": res.get("signup_url"),
        "url": signin_url,
        "verify_url": effective_verify_url,
        "redirect_url": backend_redirect_url,
        "is_app": is_app,
        "temp_id": effective_temp_id,
        "expires_in": 300
    }

@router.get("/signup-url")
@router.get("/signup/url")
async def get_signup_url(
    response: Response,
    service: str = Query("HYPERLOCAL-INVENTORY"),
    version: Optional[str] = Query("1"),
    entity_name: Optional[str] = Query(None),
    entity_type: Optional[str] = Query(None),
    client_type: Optional[str] = Query(None),
    platform: Optional[str] = Query(None),
    app: Optional[str] = Query(None),
    redirect_url: Optional[str] = Query(None),
    verify_url: Optional[str] = Query(None),
    temp_id: Optional[str] = Query(None)
):
    # Determine if app login was requested
    is_app = is_app_login_request(
        entity_type=entity_type,
        client_type=client_type,
        platform=platform,
        redirect_url=redirect_url,
        app=app,
        service=service
    )
    api_key, _ = SETTINGS.get_dauth_credentials(is_app=is_app)
    effective_entity_type = entity_type or ("app" if is_app else None)

    # Generate unique temporary polling ticket ID if not provided (5 minutes expiry)
    effective_temp_id = (temp_id or str(uuid.uuid4())).strip()
    poll_redis_key = f"auth_poll:{effective_temp_id}"
    try:
        await redis_client.set(
            poll_redis_key,
            json.dumps({
                "status": "pending",
                "temp_id": effective_temp_id,
                "service": service,
                "version": version,
                "is_app": is_app,
                "flow_type": "signup",
                "created_at": datetime.datetime.utcnow().isoformat()
            }),
            ex=300
        )
    except Exception as redis_err:
        ic(f"Failed to record auth_poll pending status in Redis: {redis_err}")

    # Determine unified verify and redirect URLs for signup
    effective_verify_url = SETTINGS.get_app_verify_url(verify_url) if is_app else SETTINGS.get_verify_url(verify_url)
    backend_redirect_url = SETTINGS.get_signup_redirect_url()
    if is_app:
        sep_v = "&" if "?" in effective_verify_url else "?"
        effective_verify_url = f"{effective_verify_url}{sep_v}is_app=true&client_type=app&entity_type=app&service={service or 'HYPERLOCAL_APP'}"
        sep_r = "&" if "?" in backend_redirect_url else "?"
        backend_redirect_url = f"{backend_redirect_url}{sep_r}is_app=true&client_type=app&entity_type=app&service={service or 'HYPERLOCAL_APP'}"

    # Append temp_id to backend redirect URL so callback can map tokens
    sep_t = "&" if "?" in backend_redirect_url else "?"
    backend_redirect_url = f"{backend_redirect_url}{sep_t}temp_id={effective_temp_id}"

    frontend_target_url = redirect_url if (redirect_url and ("://" in redirect_url or is_valid_frontend_redirect_url(redirect_url))) else None
    if not frontend_target_url and is_app:
        frontend_target_url = SETTINGS.APP_DEEP_LINK

    # Connects to Debugger Auth specifically for signup
    constructed_url = f"{DAUTH_BASE_URL}/auth"
    payload = {
        "apikey": api_key,
        "flow_type": "signup",
        "verify_url": effective_verify_url,
        "redirect_url": backend_redirect_url,
        "callback_url": backend_redirect_url,
        "additional_infos": {
            "entity_name": entity_name,
            "entity_type": effective_entity_type,
            "client_type": "app" if is_app else "web",
            "is_app": is_app,
            "redirect_url": frontend_target_url,
            "service": service,
            "version": version,
            "flow_type": "signup",
            "verify_url": effective_verify_url,
            "backend_redirect_url": backend_redirect_url,
            "temp_id": effective_temp_id
        }
    }
    async with httpx.AsyncClient(timeout=30) as client:
        response_data = await client.post(
            constructed_url,
            json=payload
        )
        ic(response_data.text)
    
    if response_data.status_code != 200:
        raise HTTPException(
            status_code=response_data.status_code,
            detail="Failed to fetch signup URLs from Debugger Auth"
        )
    
    res = response_data.json()
    state_val = json.dumps({
        "service": service,
        "version": version,
        "entity_name": entity_name,
        "entity_type": effective_entity_type,
        "is_app": is_app,
        "redirect_url": frontend_target_url,
        "verify_url": effective_verify_url,
        "flow_type": "signup",
        "temp_id": effective_temp_id
    })
    response.set_cookie(key="oauth_state", value=state_val, max_age=900, samesite="lax")
    signup_url = res.get("signup_url") or res.get("signin_url") or res.get("url")
    return {
        "signup_url": signup_url,
        "signin_url": res.get("signin_url"),
        "url": signup_url,
        "verify_url": effective_verify_url,
        "redirect_url": backend_redirect_url,
        "is_app": is_app,
        "temp_id": effective_temp_id,
        "expires_in": 300
    }

@router.post("/signup")
async def signup_direct(data: SignupRequestSchema):
    """
    Direct user signup endpoint:
    - Verifies account does not already exist.
    - Generates a random secure password (or uses provided password).
    - Stores all custom_fields (e.g. fullname) and additional_infos for future extensibility.
    - Sends the generated password to user's email.
    """
    users_coll = get_collection("users")
    clean_email = data.email.strip().lower()
    
    query_or = [
        {"email": clean_email},
        {"email": {"$regex": f"^{re.escape(clean_email)}$", "$options": "i"}}
    ]
    if data.mobilenumber:
        query_or.append({"mobilenumber": data.mobilenumber.strip()})
        
    existing = await users_coll.find_one({"$or": query_or})
    if existing:
        raise HTTPException(
            status_code=409,
            detail="An account with this email or mobile number already exists. Please sign in."
        )
        
    raw_password = data.password or generate_secure_random_password(12)
    hashed_password = ph.hash(raw_password)
    user_id = str(uuid.uuid4())
    
    custom_fields = data.custom_fields or {}
    name = data.name or custom_fields.get("fullname") or custom_fields.get("name") or clean_email.split("@")[0]
    if not custom_fields.get("fullname") and name:
        custom_fields["fullname"] = name
        
    user_doc = {
        "user_id": user_id,
        "email": clean_email,
        "mobilenumber": data.mobilenumber.strip() if data.mobilenumber else None,
        "name": name,
        "password": hashed_password,
        "has_custom_password": True,
        "is_temporary_password": True if not data.password else False,
        "two_factor": False,
        "custom_fields": custom_fields,
        "additional_infos": data.additional_infos or {},
        "auth_provider": "password",
        "created_at": datetime.datetime.utcnow(),
        "updated_at": datetime.datetime.utcnow()
    }
    await users_coll.insert_one(user_doc)
    
    is_shopiq = bool(
        data.additional_infos and (
            data.additional_infos.get("is_app")
            or str(data.additional_infos.get("client_type") or "").lower() in ("app", "mobile")
            or str(data.additional_infos.get("service") or "").upper() in ("HYPERLOCAL_APP", "DIGITAL_STORE", "SHOPIQ")
        )
    )
    if is_shopiq:
        email_sent = await send_shopiq_welcome_email(email=clean_email, name=name)
        ret_msg = "Welcome to ShopiQ! Your account has been created successfully."
    else:
        email_sent = await send_account_credentials_email(
            email=clean_email,
            name=name,
            password=raw_password,
            login_url=f"{SETTINGS.FRONTEND_URL}/login"
        )
        ret_msg = "Account created successfully! Your login password has been sent to your email."
    
    return {
        "success": True,
        "message": ret_msg,
        "user_id": user_id,
        "email": clean_email,
        "email_sent": email_sent
    }

async def _extract_verify_payload(request: Request) -> dict:
    """Helper to extract verify payload from JSON body, form, or query params, including nested data."""
    body = {}
    try:
        body = await request.json()
    except Exception:
        pass
    if not body:
        try:
            form = await request.form()
            body = dict(form)
        except Exception:
            pass
    if not body:
        body = dict(request.query_params)
    else:
        # Merge query params as fallbacks
        for k, v in request.query_params.items():
            if k not in body:
                body[k] = v

    # Check if payload is wrapped inside a data/user/payload dict
    if isinstance(body.get("data"), dict):
        unwrapped = body["data"].copy()
        unwrapped.update(body)
        body = unwrapped
    elif isinstance(body.get("user"), dict):
        unwrapped = body["user"].copy()
        unwrapped.update(body)
        body = unwrapped
    elif isinstance(body.get("payload"), dict):
        unwrapped = body["payload"].copy()
        unwrapped.update(body)
        body = unwrapped

    return body

def _parse_identifiers(body: dict):
    raw_ident = (
        body.get("email")
        or body.get("identifier")
        or body.get("username")
        or body.get("user")
        or body.get("login")
        or body.get("account")
    )
    raw_mobile = (
        body.get("mobile_number")
        or body.get("mobilenumber")
        or body.get("phone")
        or body.get("mobile")
        or body.get("phone_number")
    )
    password = body.get("password") or body.get("pass")
    auth_provider = body.get("auth_provider", "password")

    email = None
    mobilenumber = None

    if isinstance(raw_ident, str) and raw_ident.strip():
        ident = raw_ident.strip()
        if "@" in ident:
            email = ident.lower()
        elif any(c.isdigit() for c in ident):
            mobilenumber = ident
        else:
            email = ident.lower()

    if isinstance(raw_mobile, str) and raw_mobile.strip():
        mobilenumber = raw_mobile.strip()

    return email, mobilenumber, password, auth_provider

@router.api_route("/signin/verify", methods=["GET", "POST", "OPTIONS", "HEAD"])
@router.api_route("/signin/callback/verify", methods=["GET", "POST", "OPTIONS", "HEAD"])
@router.api_route("/login/verify", methods=["GET", "POST", "OPTIONS", "HEAD"])
@router.api_route("/app/verify", methods=["GET", "POST", "OPTIONS", "HEAD"])
@router.api_route("/app/signin/verify", methods=["GET", "POST", "OPTIONS", "HEAD"])
@router.api_route("/app/login/verify", methods=["GET", "POST", "OPTIONS", "HEAD"])
async def signin_verify(request: Request):
    """
    Dedicated Sign-In Verification route with Sign-In specific validation:
    - Supports GET, POST, OPTIONS, HEAD.
    - If ping or healthcheck: returns 200 OK.
    - For ShopiQ Mobile App users (is_app is True): Auto-provisioning is enabled!
      New users are allowed to authenticate without 404 rejection.
    - For Web users: Verifies user MUST exist in DB. Rejects with 404 if not registered.
    - Validates password (Argon2) if provided. Rejects with 401 if invalid.
    """
    if request.method == "OPTIONS":
        return Response(status_code=200)

    body = await _extract_verify_payload(request)
    ic("signin/verify request received:", request.method, body)
    
    is_app = check_is_app(request=request, body=body)
    email, mobilenumber, password, auth_provider = _parse_identifiers(body)

    # Healthcheck / ping handler
    if not email and not mobilenumber:
        is_ping = bool(
            request.method in ("GET", "HEAD")
            or not body
            or body.get("ping")
            or body.get("event") == "ping"
            or body.get("type") == "ping"
        )
        if is_ping:
            return JSONResponse(
                status_code=200,
                content={
                    "success": True,
                    "status": "success",
                    "status_code": 200,
                    "verified": True,
                    "service": "Authentication-Service",
                    "endpoint": "signin/verify",
                    "message": "Sign-in verification endpoint is active and healthy."
                }
            )
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "status": "error",
                "status_code": 400,
                "verified": False,
                "message": "Email or mobile number is required for sign in."
            }
        )
    
    # Dev environment access check (enforced when ENVIRONMENT != 'production' and NOT an app request)
    if SETTINGS.ENVIRONMENT.lower() != "production" and not is_app:
        is_allowed, dev_err = SETTINGS.is_dev_allowed(email=email, password=password if auth_provider == "password" else None, mobilenumber=mobilenumber, is_app=is_app)
        if not is_allowed:
            return JSONResponse(
                status_code=403,
                content={
                    "success": False,
                    "status": "error",
                    "status_code": 403,
                    "verified": False,
                    "message": dev_err
                }
            )

    users_coll = get_collection("users")
    query_or = []
    if email:
        query_or.append({"email": email})
        query_or.append({"email": {"$regex": f"^{re.escape(email)}$", "$options": "i"}})
    if mobilenumber:
        query_or.append({"mobilenumber": mobilenumber})
        
    user_doc = await users_coll.find_one({"$or": query_or, "is_deleted": {"$ne": True}})
    
    # Sign-in validation:
    if not user_doc:
        if is_app:
            # ShopiQ mobile app: auto-provisioning is enabled!
            # Allow new users to proceed with OTP verification without failing "Account not found"!
            ic(f"ShopiQ app user {email or mobilenumber} not found in DB - approving sign-in for auto-provisioning.")
            return JSONResponse(
                status_code=200,
                content={
                    "success": True,
                    "status": "success",
                    "status_code": 200,
                    "verified": True,
                    "is_app": True,
                    "is_new_user": True,
                    "message": "ShopiQ app user verified. Account will be auto-provisioned upon login.",
                    "email": email,
                    "mobilenumber": mobilenumber
                }
            )
        return JSONResponse(
            status_code=404,
            content={
                "success": False,
                "status": "error",
                "status_code": 404,
                "verified": False,
                "message": "Account not found with this email/mobile number. Please sign up to create an account."
            }
        )
        
    # Verify password if password authentication is requested
    if (auth_provider == "password" or password) and password:
        stored_pwd = user_doc.get("password")
        has_custom_pwd = user_doc.get("has_custom_password", False)
        
        if stored_pwd and has_custom_pwd:
            try:
                ph.verify(stored_pwd, password)
            except Exception:
                return JSONResponse(
                    status_code=401,
                    content={
                        "success": False,
                        "status": "error",
                        "status_code": 401,
                        "verified": False,
                        "message": "Incorrect password. Please check your credentials."
                    }
                )

    return JSONResponse(
        status_code=200,
        content={
            "success": True,
            "status": "success",
            "status_code": 200,
            "verified": True,
            "message": "Sign-in verification successful.",
            "user_id": user_doc.get("user_id"),
            "email": user_doc.get("email"),
            "mobilenumber": user_doc.get("mobilenumber"),
            "name": user_doc.get("name")
        }
    )

@router.api_route("/signup/verify", methods=["GET", "POST", "OPTIONS", "HEAD"])
@router.api_route("/callback/signup/verify", methods=["GET", "POST", "OPTIONS", "HEAD"])
@router.api_route("/app/signup/verify", methods=["GET", "POST", "OPTIONS", "HEAD"])
async def signup_verify(request: Request):
    """
    Dedicated Sign-Up Verification route with Sign-Up specific validation:
    - Supports GET, POST, OPTIONS, HEAD.
    - If ping or healthcheck: returns 200 OK.
    - Verifies user MUST NOT exist in DB. Rejects with 409 if already registered (unless is_app).
    - Allows new registrations to proceed.
    """
    if request.method == "OPTIONS":
        return Response(status_code=200)

    body = await _extract_verify_payload(request)
    ic("signup/verify request received:", request.method, body)
    
    is_app = check_is_app(request=request, body=body)
    email, mobilenumber, _, _ = _parse_identifiers(body)

    # Healthcheck / ping handler
    if not email and not mobilenumber:
        is_ping = bool(
            request.method in ("GET", "HEAD")
            or not body
            or body.get("ping")
            or body.get("event") == "ping"
            or body.get("type") == "ping"
        )
        if is_ping:
            return JSONResponse(
                status_code=200,
                content={
                    "success": True,
                    "status": "success",
                    "status_code": 200,
                    "verified": True,
                    "service": "Authentication-Service",
                    "endpoint": "signup/verify",
                    "message": "Sign-up verification endpoint is active and healthy."
                }
            )
        if body.get("request_id") or body.get("custom_fields"):
            return JSONResponse(
                status_code=200,
                content={
                    "success": True,
                    "status": "success",
                    "status_code": 200,
                    "verified": True,
                    "message": "Custom fields validated. New user allowed to register."
                }
            )
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "status": "error",
                "status_code": 400,
                "verified": False,
                "message": "Email or mobile number is required for sign up."
            }
        )

    # Dev environment access check (enforced when ENVIRONMENT != 'production' and NOT an app request)
    if SETTINGS.ENVIRONMENT.lower() != "production" and not is_app:
        is_allowed, dev_err = SETTINGS.is_dev_allowed(email=email, mobilenumber=mobilenumber, is_app=is_app)
        if not is_allowed:
            return JSONResponse(
                status_code=403,
                content={
                    "success": False,
                    "status": "error",
                    "status_code": 403,
                    "verified": False,
                    "message": dev_err
                }
            )

    users_coll = get_collection("users")
    query_or = []
    if email:
        query_or.append({"email": email})
        query_or.append({"email": {"$regex": f"^{re.escape(email)}$", "$options": "i"}})
    if mobilenumber:
        query_or.append({"mobilenumber": mobilenumber})
        
    user_doc = await users_coll.find_one({"$or": query_or, "is_deleted": {"$ne": True}})
    
    # Sign-up validation: Account MUST NOT exist! (Except for ShopiQ app where existing users are allowed)
    if user_doc:
        if is_app:
            return JSONResponse(
                status_code=200,
                content={
                    "success": True,
                    "status": "success",
                    "status_code": 200,
                    "verified": True,
                    "is_app": True,
                    "message": "ShopiQ app user already registered, allowed to proceed.",
                    "user_id": user_doc.get("user_id"),
                    "email": user_doc.get("email"),
                    "mobilenumber": user_doc.get("mobilenumber")
                }
            )
        return JSONResponse(
            status_code=409,
            content={
                "success": False,
                "status": "error",
                "status_code": 409,
                "verified": False,
                "message": "An account with this email or mobile number already exists. Please sign in."
            }
        )
        
    return JSONResponse(
        status_code=200,
        content={
            "success": True,
            "status": "success",
            "status_code": 200,
            "verified": True,
            "message": "Verification successful. New user allowed to register."
        }
    )

@router.api_route("/verify", methods=["GET", "POST", "OPTIONS", "HEAD"])
@router.api_route("/callback/verify", methods=["GET", "POST", "OPTIONS", "HEAD"])
@router.api_route("/verify-signin", methods=["GET", "POST", "OPTIONS", "HEAD"])
async def callback_verify(request: Request):
    """
    Single universal verification endpoint for both Sign In and Sign Up:
    - Supports GET, POST, OPTIONS, HEAD.
    - If ping/healthcheck: returns 200 OK.
    - If flow_type == 'signup' (or action/event == 'signup'): runs Sign-Up validation (409 if exists, 200 if new).
    - Otherwise (flow_type == 'signin'): runs Sign-In validation (404 if not found, 401 if wrong password, 200 if valid).
    """
    body = await _extract_verify_payload(request)
    flow_type = (
        body.get("flow_type")
        or body.get("action")
        or body.get("event")
        or request.query_params.get("flow_type")
        or "signin"
    )
    if str(flow_type).lower() == "signup":
        return await signup_verify(request)
    return await signin_verify(request)


        
@router.get("/callback")
@router.get("/signin/redirect")
@router.get("/signin/callback")
@router.get("/signup/redirect")
@router.get("/signup/callback")
async def callback(
    request: Request,
    token_id: Optional[str] = Query(None),
    temp_id: Optional[str] = Query(None),
    error: Optional[str] = Query(None),
    status_code: Optional[int] = Query(None),
    service: Optional[str] = Query(None),
    version: Optional[str] = Query(None)
):
    if not isinstance(error, str):
        error = None
    if not isinstance(status_code, int):
        status_code = None
    if not isinstance(service, str):
        service = None
    if not isinstance(version, str):
        version = None
    if not isinstance(token_id, str):
        token_id = None

    path = request.url.path
    detected_flow = "signup" if ("signup" in path) else "signin"

    # If error parameter is present from DAuth failure redirect
    if error:
        cookie_state = request.cookies.get("oauth_state")
        redirect_url_param = None
        flow_type = None
        if cookie_state:
            try:
                state_data = json.loads(cookie_state)
                redirect_url_param = state_data.get("redirect_url")
                flow_type = state_data.get("flow_type")
            except Exception:
                pass
        if not flow_type:
            flow_type = detected_flow
        
        # When redirecting to frontend on error, send to /signup if signup flow, or /login if signin flow
        if is_valid_frontend_redirect_url(redirect_url_param):
            base_redirect_url = redirect_url_param
        else:
            base_redirect_url = f"{SETTINGS.FRONTEND_URL}/signup" if flow_type == "signup" else f"{SETTINGS.FRONTEND_URL}/login"
            
        from urllib.parse import quote
        sep = "&" if "?" in base_redirect_url else "?"
        status_part = f"&status_code={status_code}" if status_code else ""
        flow_part = f"&flow={flow_type}" if flow_type else ""
        return RedirectResponse(url=f"{base_redirect_url}{sep}error={quote(str(error))}{status_part}{flow_part}")

    if not token_id:
        target_path = "/signup" if detected_flow == "signup" else "/login"
        return RedirectResponse(url=f"{SETTINGS.FRONTEND_URL}{target_path}")

    # 1. Check if token_id is a login_id stored in Redis
    redis_key = f"login_id:{token_id}"
    stored_payload_json = await redis_client.get(redis_key)
    if not stored_payload_json:
        # Check if token_id is actually a temp_id in auth_poll
        poll_check_key = f"auth_poll:{token_id}"
        poll_check_json = await redis_client.get(poll_check_key)
        if poll_check_json:
            try:
                poll_check_data = json.loads(poll_check_json)
                if poll_check_data.get("status") == "authenticated":
                    return {
                        "access_token": poll_check_data.get("access_token"),
                        "refresh_token": poll_check_data.get("refresh_token"),
                        "token_type": poll_check_data.get("token_type", "bearer"),
                        "expires_in": poll_check_data.get("expires_in", 3600)
                    }
            except Exception:
                pass

    if stored_payload_json:
        # This is a frontend exchange request!
        payload = json.loads(stored_payload_json)
        await redis_client.delete(redis_key)
        
        user_id = payload["user_id"]
        email = payload.get("email")
        mobilenumber = payload.get("mobilenumber")
        service = payload.get("service", "HYPERLOCAL")
        version = payload.get("version", "1")
        entity_name = payload.get("entity_name")
        entity_type = payload.get("entity_type")
        
        # Generate versioned tokens
        private_key_pem, _ = await get_keys_for_version(version)
        
        now = datetime.datetime.now(datetime.timezone.utc)
        access_jti = str(uuid.uuid4())
        access_exp = now + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_payload = {
            "sub": user_id,
            "user_id": user_id,
            "service_name": service,
            "type": "access",
            "version": version,
            "exp": int(access_exp.timestamp()),
            "jti": access_jti,
            "email": email,
            "mobilenumber": mobilenumber
        }
        if entity_name:
            access_payload["entity_name"] = entity_name
        if entity_type:
            access_payload["entity_type"] = entity_type
        
        refresh_jti = str(uuid.uuid4())
        refresh_exp = now + datetime.timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        refresh_payload = {
            "sub": user_id,
            "user_id": user_id,
            "service_name": service,
            "type": "refresh",
            "version": version,
            "exp": int(refresh_exp.timestamp()),
            "jti": refresh_jti,
            "email": email,
            "mobilenumber": mobilenumber
        }
        if entity_name:
            refresh_payload["entity_name"] = entity_name
        if entity_type:
            refresh_payload["entity_type"] = entity_type
        
        access_token = jwt.encode(access_payload, private_key_pem, algorithm="RS256")
        refresh_token = jwt.encode(refresh_payload, private_key_pem, algorithm="RS256")
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }

    # 2. Otherwise, treat it as the OAuth callback from Debugger Auth
    cookie_state = request.cookies.get("oauth_state")
    entity_name = None
    entity_type = None
    redirect_url_param = None
    flow_type = None
    cookie_temp_id = None
    if cookie_state:
        try:
            state_data = json.loads(cookie_state)
            if not service:
                service = state_data.get("service")
            if not version:
                version = state_data.get("version")
            entity_name = state_data.get("entity_name")
            entity_type = state_data.get("entity_type")
            redirect_url_param = state_data.get("redirect_url")
            flow_type = state_data.get("flow_type")
            cookie_temp_id = state_data.get("temp_id")
        except Exception:
            pass
            
    if not service:
        service = "HYPERLOCAL"
    if not version:
        version = "1"
        
    # Check if app flow from state, query params, or entity_type
    is_app_flow = check_is_app(request=request)
    if not is_app_flow and cookie_state:
        try:
            state_dict = json.loads(cookie_state)
            is_app_flow = bool(state_dict.get("is_app")) or (str(state_dict.get("entity_type") or "").lower() == "app")
        except Exception:
            pass
    if not is_app_flow:
        is_app_flow = is_app_login_request(
            entity_type=entity_type or request.query_params.get("entity_type"),
            client_type=request.query_params.get("client_type"),
            platform=request.query_params.get("platform"),
            app=request.query_params.get("app"),
            service=service or request.query_params.get("service")
        )

    primary_key, primary_secret = SETTINGS.get_dauth_credentials(is_app=is_app_flow)
    fallback_key, fallback_secret = SETTINGS.get_dauth_credentials(is_app=not is_app_flow)

    # Connects to Debugger Auth to get loggedin user
    constructed_url = f"{DAUTH_BASE_URL}/auth/authenticated-user"
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(
            constructed_url,
            json={
                "token_id": token_id,
                "client_id": primary_key,
                "client_secret": primary_secret
            }
        )
        if response.status_code != 200 and fallback_key and fallback_key != primary_key:
            ic("Primary DAuth credentials failed, attempting fallback credentials...")
            fallback_response = await client.post(
                constructed_url,
                json={
                    "token_id": token_id,
                    "client_id": fallback_key,
                    "client_secret": fallback_secret
                }
            )
            if fallback_response.status_code == 200:
                response = fallback_response
    
    if response.status_code != 200:
        raise HTTPException(
            status_code=response.status_code,
            detail="Failed to fetch authenticated user from Debugger Auth"
        )
    
    deb_data = response.json()
    ic(deb_data["token"])
    deb_user_info = jwt.decode(
        deb_data["token"],
        options={"verify_signature": False}
    )
    ic(deb_user_info)
    
    additional_infos = deb_user_info.get("additional_infos") or {}
    custom_fields = deb_user_info.get("custom_fields") or {}
    if "entity_name" in additional_infos:
        entity_name = additional_infos.get("entity_name")
    if "entity_type" in additional_infos:
        entity_type = additional_infos.get("entity_type")
    if "redirect_url" in additional_infos and additional_infos.get("redirect_url"):
        redirect_url_param = additional_infos.get("redirect_url")
    if not is_valid_frontend_redirect_url(redirect_url_param):
        redirect_url_param = None
    if additional_infos.get("service"):
        service = additional_infos.get("service")
    if additional_infos.get("version"):
        version = additional_infos.get("version")
    if not is_app_flow:
        is_app_flow = check_is_app(
            request=request,
            body={"additional_infos": additional_infos, "custom_fields": custom_fields}
        )
    if not flow_type:
        flow_type = (
            additional_infos.get("flow_type")
            or deb_user_info.get("flow_type")
            or request.query_params.get("flow_type")
            or detected_flow
            or "signin"
        )
    
    # Store user if not exists
    raw_email = deb_user_info.get("email")
    email = raw_email.strip().lower() if isinstance(raw_email, str) and raw_email.strip() else None
    mobilenumber = deb_user_info.get("mobilenumber") or deb_user_info.get("mobile_number")
    if isinstance(mobilenumber, str):
        mobilenumber = mobilenumber.strip()
    
    users_coll = get_collection("users")
    user_query = {"is_deleted": {"$ne": True}}
    if email:
        user_query["$or"] = [
            {"email": email},
            {"email": {"$regex": f"^{re.escape(email)}$", "$options": "i"}}
        ]
    elif mobilenumber:
        user_query["mobilenumber"] = mobilenumber
        
    user_doc = None
    if user_query:
        user_doc = await users_coll.find_one(user_query)
        
    # Dev environment access check (only pre-configured dev users can access when not production)
    # Mobile app users are exempt from dev restriction check
    if SETTINGS.ENVIRONMENT.lower() != "production" and not is_app_flow:
        is_allowed, dev_err = SETTINGS.is_dev_allowed(email=email, mobilenumber=mobilenumber, is_app=is_app_flow)
        if not is_allowed:
            from urllib.parse import quote
            base_redirect_url = redirect_url_param or f"{SETTINGS.FRONTEND_URL}/login"
            sep = "&" if "?" in base_redirect_url else "?"
            return RedirectResponse(url=f"{base_redirect_url}{sep}error={quote(dev_err)}&status_code=403")

        # Auto-provision allowed dev user with pre-configured password if not present in DB
        if not user_doc:
            dev_pwd = None
            for u in SETTINGS.get_dev_allowed_users():
                if isinstance(u, dict) and u.get("email", "").strip().lower() == email:
                    dev_pwd = u.get("password")
                    break
            if dev_pwd:
                user_id = deb_user_info.get("user_id") or deb_user_info.get("id") or str(uuid.uuid4())
                name = deb_user_info.get("name") or custom_fields.get("fullname") or custom_fields.get("name") or email.split("@")[0]
                if not custom_fields.get("fullname") and name:
                    custom_fields["fullname"] = name
                user_doc = {
                    "user_id": user_id,
                    "email": email,
                    "mobilenumber": mobilenumber,
                    "name": name,
                    "password": ph.hash(dev_pwd),
                    "has_custom_password": True,
                    "is_temporary_password": False,
                    "two_factor": False,
                    "custom_fields": custom_fields,
                    "additional_infos": additional_infos,
                    "auth_provider": deb_user_info.get("auth_provider") or "otp-email",
                    "profile_picture": deb_user_info.get("profile_picture"),
                    "ip": deb_user_info.get("ip"),
                    "browser": deb_user_info.get("browser"),
                    "location": deb_user_info.get("location"),
                    "created_at": datetime.datetime.utcnow(),
                    "updated_at": datetime.datetime.utcnow()
                }
                await users_coll.insert_one(user_doc)

    is_signup_flow = bool(flow_type == "signup" or deb_user_info.get("action") == "signup" or deb_user_info.get("event") == "signup")

    # If Signin flow and user NOT present: reject and redirect to signup EXCEPT for ShopiQ app users!
    if not is_signup_flow and not user_doc:
        if not is_app_flow:
            from urllib.parse import quote
            base_redirect_url = redirect_url_param or f"{SETTINGS.FRONTEND_URL}/login"
            sep = "&" if "?" in base_redirect_url else "?"
            err_msg = "Account not found. Please sign up to create an account."
            return RedirectResponse(url=f"{base_redirect_url}{sep}error={quote(err_msg)}&status_code=404&flow=signup")
        else:
            ic("Auto-provisioning new account for ShopiQ mobile app user:", email or mobilenumber)

    # If user NOT present in DB (Signup flow OR ShopiQ app auto-provisioning):
    # create new account, generate password, email it!
    if not user_doc:
        user_id = deb_user_info.get("user_id") or deb_user_info.get("id") or str(uuid.uuid4())
        
        # Generate secure random password
        generated_password = generate_secure_random_password(12)
        hashed_password = ph.hash(generated_password)
        
        name = deb_user_info.get("name") or custom_fields.get("fullname") or custom_fields.get("name") or (email.split("@")[0] if email else "User")
        if not custom_fields.get("fullname") and name:
            custom_fields["fullname"] = name
            
        user_doc = {
            "user_id": user_id,
            "password": hashed_password,
            "has_custom_password": True,
            "is_temporary_password": True,
            "two_factor": False,
            "name": name,
            "custom_fields": custom_fields,
            "additional_infos": additional_infos,
            "auth_provider": deb_user_info.get("auth_provider") or "otp-email",
            "profile_picture": deb_user_info.get("profile_picture"),
            "ip": deb_user_info.get("ip"),
            "browser": deb_user_info.get("browser"),
            "location": deb_user_info.get("location"),
            "created_at": datetime.datetime.utcnow(),
            "updated_at": datetime.datetime.utcnow()
        }
        if email:
            user_doc["email"] = email
        if mobilenumber:
            user_doc["mobilenumber"] = mobilenumber
            
        await users_coll.insert_one(user_doc)
        
        # Send welcome email based on client type (ShopiQ customer vs inventQ retailer)
        if email:
            is_shopiq_customer = bool(
                is_app_flow
                or str(entity_type or "").lower() in ("app", "mobile")
                or str(service or "").upper() in ("HYPERLOCAL_APP", "DIGITAL_STORE", "SHOPIQ")
                or (additional_infos and (
                    additional_infos.get("is_app")
                    or str(additional_infos.get("client_type") or "").lower() in ("app", "mobile")
                    or str(additional_infos.get("entity_type") or "").lower() in ("app", "mobile")
                    or str(additional_infos.get("service") or "").upper() in ("HYPERLOCAL_APP", "DIGITAL_STORE", "SHOPIQ")
                ))
                or (effective_temp_id)
            )

            try:
                if is_shopiq_customer:
                    # ShopiQ customer: send friendly welcome message ONLY (no temporary password or inventQ credentials)
                    await send_shopiq_welcome_email(
                        email=email,
                        name=name
                    )
                else:
                    # inventQ retail/staff platform user: send credentials email
                    await send_account_credentials_email(
                        email=email,
                        name=name,
                        password=generated_password,
                        login_url=f"{SETTINGS.FRONTEND_URL}/login"
                    )
            except Exception as mail_err:
                ic(f"Failed to send welcome email: {mail_err}")
    else:
        user_id = user_doc["user_id"]
        email = user_doc.get("email") or email
        mobilenumber = user_doc.get("mobilenumber") or mobilenumber
        
        # Update user with latest custom_fields & additional_infos
        update_fields = {"updated_at": datetime.datetime.utcnow()}
        if custom_fields:
            merged_custom = user_doc.get("custom_fields") or {}
            merged_custom.update(custom_fields)
            update_fields["custom_fields"] = merged_custom
            if not user_doc.get("name"):
                name_cand = custom_fields.get("fullname") or custom_fields.get("name")
                if name_cand:
                    update_fields["name"] = name_cand
        if additional_infos:
            merged_add = user_doc.get("additional_infos") or {}
            merged_add.update(additional_infos)
            update_fields["additional_infos"] = merged_add
        if deb_user_info.get("ip"):
            update_fields["ip"] = deb_user_info.get("ip")
        if deb_user_info.get("browser"):
            update_fields["browser"] = deb_user_info.get("browser")
        if deb_user_info.get("profile_picture"):
            update_fields["profile_picture"] = deb_user_info.get("profile_picture")
            
        auth_provider = deb_user_info.get("auth_provider") or deb_user_info.get("provider") or deb_user_info.get("login_type")
        incoming_password = deb_user_info.get("password")
        new_password_field = deb_user_info.get("new_password")
        
        is_reset_event = bool(
            auth_provider in ("forgot-password", "forgot_password", "reset_password", "password_reset")
            or deb_user_info.get("flow_type") == "password_reset"
            or deb_user_info.get("is_reset")
            or deb_user_info.get("is_password_reset")
            or deb_user_info.get("action") in ("reset_password", "forgot_password", "change_password", "reset", "update_password")
            or deb_user_info.get("event") in ("reset_password", "forgot_password", "change_password", "reset")
            or new_password_field
        )
        effective_new_pwd = new_password_field or incoming_password

        # If it's a reset / forgot password event, directly update with new password
        if is_reset_event and effective_new_pwd:
            new_hash = ph.hash(effective_new_pwd)
            update_fields["password"] = new_hash
            update_fields["has_custom_password"] = True
            await users_coll.update_one(
                {"_id": user_doc["_id"]},
                {"$set": update_fields}
            )
        # If user logged in via password, verify with stored password
        elif auth_provider == "password" or incoming_password:
            if incoming_password:
                stored_pwd_hash = user_doc.get("password")
                has_custom_pwd = user_doc.get("has_custom_password", False)
                if stored_pwd_hash and has_custom_pwd:
                    try:
                        ph.verify(stored_pwd_hash, incoming_password)
                    except VerifyMismatchError:
                        from urllib.parse import quote
                        base_redirect_url = redirect_url_param or f"{SETTINGS.FRONTEND_URL}/login"
                        sep = "&" if "?" in base_redirect_url else "?"
                        err_msg = "Invalid password. Please check your credentials."
                        return RedirectResponse(url=f"{base_redirect_url}{sep}error={quote(err_msg)}&status_code=401")
                    except Exception as e:
                        from urllib.parse import quote
                        base_redirect_url = redirect_url_param or f"{SETTINGS.FRONTEND_URL}/login"
                        sep = "&" if "?" in base_redirect_url else "?"
                        err_msg = f"Password verification failed: {str(e)}"
                        return RedirectResponse(url=f"{base_redirect_url}{sep}error={quote(err_msg)}&status_code=401")
                    
                    if ph.check_needs_rehash(stored_pwd_hash):
                        new_hash = ph.hash(incoming_password)
                        update_fields["password"] = new_hash
                        
                    await users_coll.update_one(
                        {"_id": user_doc["_id"]},
                        {"$set": update_fields}
                    )
                else:
                    new_hash = ph.hash(incoming_password)
                    update_fields["password"] = new_hash
                    update_fields["has_custom_password"] = True
                    await users_coll.update_one(
                        {"_id": user_doc["_id"]},
                        {"$set": update_fields}
                    )
            else:
                await users_coll.update_one(
                    {"_id": user_doc["_id"]},
                    {"$set": update_fields}
                )
        else:
            await users_coll.update_one(
                {"_id": user_doc["_id"]},
                {"$set": update_fields}
            )

    # Generate a temporary login_id and store user payload in Redis
    login_id = str(uuid.uuid4())
    new_redis_key = f"login_id:{login_id}"
    
    user_context = {
        "user_id": user_id,
        "email": email,
        "mobilenumber": mobilenumber,
        "service": service,
        "version": version,
        "entity_name": entity_name,
        "entity_type": entity_type
    }
    
    await redis_client.set(new_redis_key, json.dumps(user_context), ex=120)

    # Resolve effective_temp_id for polling mapping
    effective_temp_id = (
        temp_id
        or request.query_params.get("temp_id")
        or (additional_infos.get("temp_id") if isinstance(additional_infos, dict) else None)
        or cookie_temp_id
    )

    # Pre-generate JWT access & refresh tokens for polling clients (ShopiQ) and store in Redis
    try:
        private_key_pem, _ = await get_keys_for_version(version)
        now = datetime.datetime.now(datetime.timezone.utc)
        access_jti = str(uuid.uuid4())
        access_exp = now + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_payload = {
            "sub": user_id,
            "user_id": user_id,
            "service_name": service,
            "type": "access",
            "version": version,
            "exp": int(access_exp.timestamp()),
            "jti": access_jti,
            "email": email,
            "mobilenumber": mobilenumber
        }
        if entity_name:
            access_payload["entity_name"] = entity_name
        if entity_type:
            access_payload["entity_type"] = entity_type

        refresh_jti = str(uuid.uuid4())
        refresh_exp = now + datetime.timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        refresh_payload = {
            "sub": user_id,
            "user_id": user_id,
            "service_name": service,
            "type": "refresh",
            "version": version,
            "exp": int(refresh_exp.timestamp()),
            "jti": refresh_jti,
            "email": email,
            "mobilenumber": mobilenumber
        }
        if entity_name:
            refresh_payload["entity_name"] = entity_name
        if entity_type:
            refresh_payload["entity_type"] = entity_type

        access_token = jwt.encode(access_payload, private_key_pem, algorithm="RS256")
        refresh_token = jwt.encode(refresh_payload, private_key_pem, algorithm="RS256")

        if effective_temp_id:
            poll_redis_key = f"auth_poll:{effective_temp_id}"
            poll_payload = {
                "status": "authenticated",
                "temp_id": effective_temp_id,
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "bearer",
                "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                "user_id": user_id,
                "email": email,
                "mobilenumber": mobilenumber,
                "service": service,
                "version": version,
                "authenticated_at": datetime.datetime.utcnow().isoformat()
            }
            await redis_client.set(poll_redis_key, json.dumps(poll_payload), ex=300)
            ic(f"Successfully mapped tokens to temp_id {effective_temp_id} in Redis for polling")
    except Exception as token_err:
        ic(f"Error pre-generating tokens for auth_poll: {token_err}")
    
    def append_query_param(url: str, key: str, value: str) -> str:
        from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
        parsed = urlparse(url)
        params = parse_qsl(parsed.query)
        params.append((key, value))
        new_query = urlencode(params)
        return urlunparse(parsed._replace(query=new_query))

    base_redirect_url = None
    if is_valid_frontend_redirect_url(redirect_url_param):
        base_redirect_url = redirect_url_param
    else:
        srv_upper = service.upper() if service else ""
        ent_lower = entity_type.lower() if entity_type else ""
        is_app_redirect = bool(
            is_app_flow
            or ent_lower in ("app", "mobile")
            or (additional_infos and (additional_infos.get("is_app") or str(additional_infos.get("client_type") or "").lower() in ("app", "mobile") or str(additional_infos.get("entity_type") or "").lower() in ("app", "mobile")))
        )
        if is_app_redirect:
            base_redirect_url = SETTINGS.APP_DEEP_LINK
        elif (srv_upper == "HYPERLOCAL" or srv_upper == "HYPERLOCAL-INVENTORY") and ent_lower == "website":
            base_redirect_url = SETTINGS.HYPERLOCAL_WEBSITE_URL
        else:
            base_redirect_url = f"{SETTINGS.FRONTEND_URL}/auth/callback"

    redirect_url = append_query_param(base_redirect_url, "token_id", login_id)
    if effective_temp_id:
        redirect_url = append_query_param(redirect_url, "temp_id", effective_temp_id)
    if is_signup_flow:
        redirect_url = append_query_param(redirect_url, "flow", "signup")
    else:
        redirect_url = append_query_param(redirect_url, "flow", "signin")
    return RedirectResponse(url=redirect_url)


@router.get("/poll-status")
@router.get("/session-status")
@router.get("/poll")
async def poll_auth_status(temp_id: str = Query(...)):
    """
    Polling endpoint for ShopiQ mobile app:
    Polls the backend by temp_id every 5 seconds until auth verification completes.
    - 'pending': User hasn't finished browser authentication yet.
    - 'authenticated': Returns access_token, refresh_token, and user info.
    - 'expired': Session expired (>5 mins) or invalid.
    """
    if not temp_id or not temp_id.strip():
        raise HTTPException(status_code=400, detail="temp_id is required")

    clean_temp_id = temp_id.strip()
    poll_key = f"auth_poll:{clean_temp_id}"
    data_str = await redis_client.get(poll_key)

    if not data_str:
        return JSONResponse(
            status_code=200,
            content={
                "status": "expired",
                "temp_id": clean_temp_id,
                "message": "Authentication session expired or not found."
            }
        )

    try:
        data = json.loads(data_str)
    except Exception:
        return JSONResponse(
            status_code=200,
            content={
                "status": "expired",
                "temp_id": clean_temp_id,
                "message": "Corrupted auth session."
            }
        )

    if data.get("status") == "authenticated":
        return JSONResponse(
            status_code=200,
            content={
                "status": "authenticated",
                "temp_id": clean_temp_id,
                "access_token": data.get("access_token"),
                "refresh_token": data.get("refresh_token"),
                "token_type": data.get("token_type", "bearer"),
                "expires_in": data.get("expires_in", 3600),
                "user_id": data.get("user_id"),
                "email": data.get("email"),
                "mobilenumber": data.get("mobilenumber")
            }
        )

    return JSONResponse(
        status_code=200,
        content={
            "status": "pending",
            "temp_id": clean_temp_id,
            "message": "Waiting for user authentication in browser."
        }
    )

@router.post("/refresh")
async def refresh_token(data: RefreshSchema):
    version = data.version
    if not version:
        try:
            unv = jwt.decode(data.refresh_token, options={"verify_signature": False})
            version = unv.get("version", "1")
        except Exception:
            version = "1"

    # Verify signature using public key matching version
    _, public_key_pem = await get_keys_for_version(version)
    
    try:
        payload = jwt.decode(data.refresh_token, public_key_pem, algorithms=["RS256"])
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid refresh token: {str(e)}")
        
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=400, detail="Token type must be refresh")
        
    # Check if revoked
    revoked_coll = get_collection("revoked_tokens")
    is_revoked = await revoked_coll.find_one({"jti": payload.get("jti")})
    if is_revoked:
        raise HTTPException(status_code=401, detail="Refresh token has been revoked")
        
    # Issue new access token & fresh refresh token
    private_key_pem, _ = await get_keys_for_version(version)
    
    user_id = payload.get("user_id") or payload["sub"]
    email = payload.get("email")
    mobilenumber = payload.get("mobilenumber")
    service = payload.get("service_name")
    entity_name = payload.get("entity_name")
    entity_type = payload.get("entity_type")
    role = payload.get("role")
    shop_id = payload.get("shop_id")
    
    now = datetime.datetime.now(datetime.timezone.utc)
    access_jti = str(uuid.uuid4())
    access_exp = now + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_payload = {
        "sub": user_id,
        "user_id": user_id,
        "service_name": service,
        "type": "access",
        "version": version,
        "exp": int(access_exp.timestamp()),
        "jti": access_jti,
        "email": email,
        "mobilenumber": mobilenumber
    }
    if entity_name:
        access_payload["entity_name"] = entity_name
    if entity_type:
        access_payload["entity_type"] = entity_type
    if role:
        access_payload["role"] = role
    if shop_id:
        access_payload["shop_id"] = shop_id
    
    new_access_token = jwt.encode(access_payload, private_key_pem, algorithm="RS256")

    refresh_jti = str(uuid.uuid4())
    refresh_exp = now + datetime.timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    refresh_payload = {
        "sub": user_id,
        "user_id": user_id,
        "service_name": service,
        "type": "refresh",
        "version": version,
        "exp": int(refresh_exp.timestamp()),
        "jti": refresh_jti,
        "email": email,
        "mobilenumber": mobilenumber
    }
    if entity_name:
        refresh_payload["entity_name"] = entity_name
    if entity_type:
        refresh_payload["entity_type"] = entity_type
    if role:
        refresh_payload["role"] = role
    if shop_id:
        refresh_payload["shop_id"] = shop_id

    new_refresh_token = jwt.encode(refresh_payload, private_key_pem, algorithm="RS256")
    
    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60
    }

@router.post("/revoke")
async def revoke_token(data: RevokeSchema):
    # Decode token without verification to get version and jti
    try:
        unverified_payload = jwt.decode(data.token, options={"verify_signature": False})
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=400, detail="Invalid token format")
        
    version = unverified_payload.get("version")
    if not version:
        raise HTTPException(status_code=400, detail="Token version metadata missing")
        
    # Verify token fully
    _, public_key_pem = await get_keys_for_version(version)
    try:
        payload = jwt.decode(data.token, public_key_pem, algorithms=["RS256"])
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=401, detail="Invalid token signature or expired")
        
    jti = payload.get("jti")
    if not jti:
        raise HTTPException(status_code=400, detail="Token identifier (jti) missing")
        
    revoked_coll = get_collection("revoked_tokens")
    await revoked_coll.update_one(
        {"jti": jti},
        {"$set": {"jti": jti, "revoked_at": datetime.datetime.utcnow()}},
        upsert=True
    )
    return {"message": "Token revoked successfully"}


# Manual User Creation & CRUD Endpoints

@router.post("/users", response_model=UserResponseSchema)
async def create_user_manual(data: UserCreateManualSchema):
    users_coll = get_collection("users")
    normalized_email = data.email.strip().lower() if data.email else None
    
    # Check if exists (case-insensitive email matching)
    query_or = []
    if normalized_email:
        query_or.append({"email": normalized_email})
        query_or.append({"email": {"$regex": f"^{re.escape(normalized_email)}$", "$options": "i"}})
    if data.mobilenumber:
        query_or.append({"mobilenumber": data.mobilenumber.strip()})
        
    existing = await users_coll.find_one({"$or": query_or}) if query_or else None
    if existing:
        raise HTTPException(status_code=400, detail="User with this email or mobile number already exists.")
        
    user_id = data.user_id if data.user_id else str(uuid.uuid4())
    hashed_password = ph.hash(data.password)
    
    user_doc = {
        "user_id": user_id,
        "email": normalized_email,
        "mobilenumber": data.mobilenumber.strip() if data.mobilenumber else None,
        "password": hashed_password,
        "has_custom_password": True,
        "two_factor": data.two_factor,
        "created_at": datetime.datetime.utcnow(),
        "updated_at": datetime.datetime.utcnow()
    }
    await users_coll.insert_one(user_doc)
    return user_doc

@router.post("/login")
async def login_with_password(data: LoginRequestSchema):
    if not data.email and not data.mobilenumber:
        raise HTTPException(status_code=400, detail="Email or mobile number is required")
    
    users_coll = get_collection("users")
    query_or = []
    if data.email:
        clean_email = data.email.strip().lower()
        query_or.append({"email": clean_email})
        query_or.append({"email": {"$regex": f"^{re.escape(clean_email)}$", "$options": "i"}})
    # Dev environment access check
    if SETTINGS.ENVIRONMENT.lower() != "production":
        is_allowed, dev_err = SETTINGS.is_dev_allowed(email=data.email, password=data.password, mobilenumber=data.mobilenumber)
        if not is_allowed:
            raise HTTPException(status_code=403, detail=dev_err)

    if data.mobilenumber:
        query_or.append({"mobilenumber": data.mobilenumber.strip()})
        
    user_doc = await users_coll.find_one({"$or": query_or, "is_deleted": {"$ne": True}}) if query_or else None
    if not user_doc:
        raise HTTPException(status_code=401, detail="Invalid email/mobile or password.")
        
    stored_pwd = user_doc.get("password")
    if not stored_pwd:
        raise HTTPException(status_code=401, detail="No password set for this account. Please login via OTP or OAuth.")
        
    try:
        ph.verify(stored_pwd, data.password)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid email/mobile or password.")
        
    if ph.check_needs_rehash(stored_pwd):
        new_hash = ph.hash(data.password)
        await users_coll.update_one(
            {"_id": user_doc["_id"]},
            {"$set": {"password": new_hash, "updated_at": datetime.datetime.utcnow()}}
        )
        
    version = data.version or "1"
    private_key_pem, _ = await get_keys_for_version(version)
    
    user_id = user_doc["user_id"]
    email = user_doc.get("email")
    mobilenumber = user_doc.get("mobilenumber")
    
    now = datetime.datetime.now(datetime.timezone.utc)
    access_jti = str(uuid.uuid4())
    access_exp = now + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_payload = {
        "sub": user_id,
        "user_id": user_id,
        "service_name": data.service or "HYPERLOCAL",
        "type": "access",
        "version": version,
        "exp": int(access_exp.timestamp()),
        "jti": access_jti,
        "email": email,
        "mobilenumber": mobilenumber
    }
    if data.entity_name:
        access_payload["entity_name"] = data.entity_name
    if data.entity_type:
        access_payload["entity_type"] = data.entity_type
        
    refresh_jti = str(uuid.uuid4())
    refresh_exp = now + datetime.timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    refresh_payload = {
        "sub": user_id,
        "user_id": user_id,
        "service_name": data.service or "HYPERLOCAL",
        "type": "refresh",
        "version": version,
        "exp": int(refresh_exp.timestamp()),
        "jti": refresh_jti,
        "email": email,
        "mobilenumber": mobilenumber
    }
    if data.entity_name:
        refresh_payload["entity_name"] = data.entity_name
    if data.entity_type:
        refresh_payload["entity_type"] = data.entity_type
        
    access_token = jwt.encode(access_payload, private_key_pem, algorithm="RS256")
    refresh_token = jwt.encode(refresh_payload, private_key_pem, algorithm="RS256")
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "user": {
            "user_id": user_id,
            "email": email,
            "mobilenumber": mobilenumber
        }
    }

@router.get("/users", response_model=List[UserResponseSchema])
async def get_all_users():
    users_coll = get_collection("users")
    cursor = users_coll.find({})
    users = []
    async for doc in cursor:
        users.append(doc)
    return users

@router.get("/users/by-id/{user_id}", response_model=UserResponseSchema)
async def get_user_by_id(user_id: str):
    users_coll = get_collection("users")
    user = await users_coll.find_one({"user_id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@router.get("/users/by-email/{email}", response_model=UserResponseSchema)
async def get_user_by_email(email: str):
    users_coll = get_collection("users")
    clean_email = email.strip().lower()
    user = await users_coll.find_one({
        "$or": [
            {"email": clean_email},
            {"email": {"$regex": f"^{re.escape(clean_email)}$", "$options": "i"}}
        ]
    })
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@router.get("/users/by-mobile/{mobilenumber}", response_model=UserResponseSchema)
async def get_user_by_mobile(mobilenumber: str):
    users_coll = get_collection("users")
    user = await users_coll.find_one({"mobilenumber": mobilenumber})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

def _mask_email(email: str) -> str:
    if not email or "@" not in email:
        return email or ""
    parts = email.split("@")
    name, domain = parts[0], parts[1]
    if len(name) <= 2:
        masked = name[0] + "*"
    else:
        masked = name[0] + "*" * (len(name) - 2) + name[-1]
    return f"{masked}@{domain}"

@router.post("/account-deletion/request-otp")
@router.post("/delete-account/request-otp")
async def request_account_deletion_otp(data: RequestAccountDeletionOtpSchema):
    if not data.user_id and not data.email:
        raise HTTPException(status_code=400, detail="User ID or email is required.")

    users_coll = get_collection("users")
    query_or = []
    if data.user_id:
        query_or.append({"user_id": data.user_id})
    if data.email:
        clean_email = data.email.strip().lower()
        query_or.append({"email": clean_email})
        query_or.append({"email": {"$regex": f"^{re.escape(clean_email)}$", "$options": "i"}})

    user_doc = await users_coll.find_one({"$or": query_or, "is_deleted": {"$ne": True}}) if query_or else None
    if not user_doc:
        raise HTTPException(status_code=404, detail="User account not found.")

    if user_doc.get("is_deleted") is True:
        raise HTTPException(status_code=400, detail="This account has already been deleted.")

    user_email = user_doc.get("email")
    if not user_email:
        raise HTTPException(status_code=400, detail="No registered Gmail address found for this account to receive verification code.")

    user_id = user_doc["user_id"]
    user_name = user_doc.get("name") or user_doc.get("first_name") or "ShopiQ Customer"

    # Generate 6-digit numeric OTP
    import secrets
    otp = f"{secrets.randbelow(900000) + 100000}"

    # Store OTP in Redis for 10 minutes (600 seconds) under all identifier keys
    redis_keys_to_set = [f"del_account_otp:{user_id}"]
    if user_email:
        clean_uemail = user_email.split("__deleted")[0].strip().lower()
        redis_keys_to_set.append(f"del_account_otp:email:{clean_uemail}")
    if data.user_id and data.user_id != user_id:
        redis_keys_to_set.append(f"del_account_otp:{data.user_id}")
    if data.email:
        redis_keys_to_set.append(f"del_account_otp:email:{data.email.strip().lower()}")

    for k in set(redis_keys_to_set):
        await redis_client.set(k, otp, ex=600)

    # Dispatch verification email to user's Gmail
    email_sent = await send_account_deletion_otp_email(email=user_email, name=user_name, otp=otp)
    if not email_sent:
        ic(f"[SoftDelete] Warning: Email dispatch returned false for {user_email}")

    return {
        "success": True,
        "message": f"A 6-digit verification code has been sent to your registered Gmail address: {_mask_email(user_email)}.",
        "email": _mask_email(user_email),
        "user_id": user_id
    }

@router.post("/account-deletion/verify-otp")
@router.post("/delete-account/verify-otp")
async def verify_account_deletion_otp(data: VerifyAccountDeletionOtpSchema):
    raw_user_id = (data.user_id or "").strip()
    raw_email = (data.email or "").strip().lower()
    otp_entered = data.otp.strip()

    if (not raw_user_id and not raw_email) or not otp_entered:
        raise HTTPException(status_code=400, detail="User ID or email, and verification code are required.")

    # Collect candidate Redis keys
    candidate_keys = []
    if raw_user_id:
        candidate_keys.append(f"del_account_otp:{raw_user_id}")
    if raw_email:
        candidate_keys.append(f"del_account_otp:email:{raw_email}")

    users_coll = get_collection("users")
    user_doc = None
    if raw_user_id:
        user_doc = await users_coll.find_one({"user_id": raw_user_id})
    if not user_doc and raw_email:
        user_doc = await users_coll.find_one({"email": raw_email, "is_deleted": {"$ne": True}})
    if not user_doc and raw_email:
        user_doc = await users_coll.find_one({"email": {"$regex": f"^{re.escape(raw_email)}$", "$options": "i"}, "is_deleted": {"$ne": True}})

    if user_doc:
        doc_uid = user_doc.get("user_id")
        doc_email = (user_doc.get("email") or "").split("__deleted")[0].strip().lower()
        if doc_uid and f"del_account_otp:{doc_uid}" not in candidate_keys:
            candidate_keys.append(f"del_account_otp:{doc_uid}")
        if doc_email and f"del_account_otp:email:{doc_email}" not in candidate_keys:
            candidate_keys.append(f"del_account_otp:email:{doc_email}")

    # Check Redis for any matching OTP key
    stored_otp = None
    for k in candidate_keys:
        val = await redis_client.get(k)
        if val:
            stored_otp = val
            break

    if not stored_otp:
        raise HTTPException(status_code=400, detail="Verification code has expired or is invalid. Please request a new code.")

    if stored_otp != otp_entered:
        raise HTTPException(status_code=400, detail="Invalid verification code. Please check your Gmail and try again.")

    # Invalidate OTP from Redis immediately across candidate keys
    for k in candidate_keys:
        try:
            await redis_client.delete(k)
        except Exception:
            pass

    # Resolve target user document to soft-delete
    target_user_doc = user_doc
    if not target_user_doc or target_user_doc.get("is_deleted") is True:
        email_to_find = raw_email or (user_doc.get("original_email") if user_doc else None) or (user_doc.get("email") if user_doc else None)
        if email_to_find:
            clean_email_to_find = email_to_find.split("__deleted")[0].strip().lower()
            active_doc = await users_coll.find_one({
                "$or": [
                    {"email": clean_email_to_find},
                    {"email": {"$regex": f"^{re.escape(clean_email_to_find)}$", "$options": "i"}}
                ],
                "is_deleted": {"$ne": True}
            })
            if active_doc:
                target_user_doc = active_doc

    if not target_user_doc:
        raise HTTPException(status_code=404, detail="User account not found.")

    target_user_id = target_user_doc["user_id"]
    now_utc = datetime.datetime.utcnow()

    scope = (data.scope or "shopiq").lower()

    if scope == "shopiq":
        # ─────────────────────────────────────────────────────────────
        # SHOPIQ CUSTOMER DELETION ONLY
        # Only deletes consumer shopping profile, addresses, and favorites.
        # DOES NOT touch inventQ retailer account, stores, or merchant data.
        # ─────────────────────────────────────────────────────────────
        from infras.db.mongo import MongoDBManager
        if MongoDBManager.client:
            # 1. SOFT DELETE customer profile in DigitalStoreUserServiceDb
            try:
                for ds_name in ["DigitalStoreUserServiceDb", "DigitalStoreUserDb"]:
                    ds_db = MongoDBManager.client[ds_name]
                    await ds_db["users"].update_one(
                        {"user_id": target_user_id},
                        {
                            "$set": {
                                "is_deleted": True,
                                "deleted_at": now_utc,
                                "updated_at": now_utc,
                                "addresses": []
                            }
                        }
                    )
                    await ds_db["search_histories"].delete_many({"user_id": target_user_id})
                    await ds_db["favourite_products"].delete_many({"user_id": target_user_id})
                    await ds_db["favourite_shops"].delete_many({"user_id": target_user_id})
            except Exception as e:
                ic(f"[SoftDelete:ShopiQ] Error updating DigitalStoreUserServiceDb: {e}")

            # 2. Mark online customer orders as user_deleted in OrdersDb (hidden from customer app, kept for retailer on inventQ)
            try:
                orders_db = MongoDBManager.client["OrdersDb"]
                await orders_db["OrdersCollection"].update_many(
                    {"online_details.user_id": target_user_id},
                    {
                        "$set": {
                            "online_details.user_deleted": True,
                            "user_deleted": True
                        }
                    }
                )
            except Exception as e:
                ic(f"[SoftDelete:ShopiQ] Error updating OrdersDb: {e}")

        # 3. Clean up active mobile app polling tokens in Redis
        try:
            user_tokens_pattern = f"auth_poll:{target_user_id}*"
            keys = await redis_client.keys(user_tokens_pattern)
            if keys:
                await redis_client.delete(*keys)
        except Exception as e:
            ic(f"[SoftDelete:ShopiQ] Redis token cleanup: {e}")

        return {
            "success": True,
            "scope": "shopiq",
            "message": "Your ShopiQ customer account, saved addresses, and shopping history have been deleted successfully. Your inventQ retail stores and merchant account remain completely active."
        }

    # ─────────────────────────────────────────────────────────────
    # INVENTQ / FULL ACCOUNT DELETION
    # ─────────────────────────────────────────────────────────────
    orig_email = target_user_doc.get("email")
    orig_mobile = target_user_doc.get("mobilenumber")
    del_suffix = f"__deleted_{int(now_utc.timestamp())}_{target_user_id[:8]}"

    update_fields = {
        "is_deleted": True,
        "deleted_at": now_utc,
        "status": "deleted",
        "original_email": orig_email,
        "original_mobilenumber": orig_mobile,
        "updated_at": now_utc
    }
    if orig_email and not orig_email.endswith("__deleted"):
        update_fields["email"] = f"{orig_email}{del_suffix}"
    if orig_mobile and "__deleted" not in orig_mobile:
        update_fields["mobilenumber"] = f"{orig_mobile}{del_suffix}"

    await users_coll.update_one(
        {"user_id": target_user_id},
        {"$set": update_fields}
    )

    from infras.db.mongo import MongoDBManager
    if MongoDBManager.client:
        try:
            for ds_name in ["DigitalStoreUserServiceDb", "DigitalStoreUserDb"]:
                ds_db = MongoDBManager.client[ds_name]
                ds_update = {
                    "is_deleted": True,
                    "deleted_at": now_utc,
                    "original_email": orig_email,
                    "original_mobilenumber": orig_mobile,
                    "updated_at": now_utc
                }
                if orig_email and not orig_email.endswith("__deleted"):
                    ds_update["email"] = f"{orig_email}{del_suffix}"
                if orig_mobile and "__deleted" not in orig_mobile:
                    ds_update["mobilenumber"] = f"{orig_mobile}{del_suffix}"

                await ds_db["users"].update_one(
                    {"user_id": target_user_id},
                    {"$set": ds_update}
                )
                await ds_db["search_histories"].delete_many({"user_id": target_user_id})
                await ds_db["favourite_products"].delete_many({"user_id": target_user_id})
                await ds_db["favourite_shops"].delete_many({"user_id": target_user_id})
        except Exception as e:
            ic(f"[SoftDelete:Full] Error updating DigitalStoreUserServiceDb: {e}")

        try:
            orders_db = MongoDBManager.client["OrdersDb"]
            await orders_db["OrdersCollection"].update_many(
                {"online_details.user_id": target_user_id},
                {
                    "$set": {
                        "online_details.user_deleted": True,
                        "user_deleted": True
                    }
                }
            )
        except Exception as e:
            ic(f"[SoftDelete:Full] Error updating OrdersDb: {e}")

    try:
        user_tokens_pattern = f"auth_poll:{target_user_id}*"
        keys = await redis_client.keys(user_tokens_pattern)
        if keys:
            await redis_client.delete(*keys)
    except Exception as e:
        ic(f"[SoftDelete:Full] Redis token cleanup: {e}")

    return {
        "success": True,
        "scope": scope,
        "message": "Your account has been deleted successfully."
    }

@router.delete("/users/{user_id}")
async def delete_user(user_id: str):
    """Soft delete user account across services while preserving order records."""
    users_coll = get_collection("users")
    user = await users_coll.find_one({"user_id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    now_utc = datetime.datetime.utcnow()
    await users_coll.update_one(
        {"user_id": user_id},
        {
            "$set": {
                "is_deleted": True,
                "deleted_at": now_utc,
                "status": "deleted",
                "updated_at": now_utc
            }
        }
    )

    from infras.db.mongo import MongoDBManager
    if MongoDBManager.client:
        try:
            ds_db = MongoDBManager.client["DigitalStoreUserDb"]
            await ds_db["users"].update_one(
                {"user_id": user_id},
                {"$set": {"is_deleted": True, "deleted_at": now_utc, "updated_at": now_utc}}
            )
            await ds_db["search_histories"].delete_many({"user_id": user_id})
            await ds_db["favourite_products"].delete_many({"user_id": user_id})
            await ds_db["favourite_shops"].delete_many({"user_id": user_id})
        except Exception as e:
            ic(f"[SoftDelete] Error updating DigitalStoreUserDb: {e}")

        try:
            orders_db = MongoDBManager.client["OrdersDb"]
            await orders_db["OrdersCollection"].update_many(
                {"online_details.user_id": user_id},
                {"$set": {"online_details.user_deleted": True, "user_deleted": True}}
            )
        except Exception as e:
            ic(f"[SoftDelete] Error updating OrdersDb: {e}")

    return {"message": "User soft-deleted successfully"}


# Password Reset & Management Endpoints

@router.post("/forgot-password")
async def forgot_password(data: ForgotPasswordSchema):
    if not data.email and not data.mobilenumber:
        raise HTTPException(status_code=400, detail="Email or mobile number is required.")
    
    users_coll = get_collection("users")
    query_or = []
    if data.email:
        clean_email = data.email.strip().lower()
        query_or.append({"email": clean_email})
        query_or.append({"email": {"$regex": f"^{re.escape(clean_email)}$", "$options": "i"}})
    if data.mobilenumber:
        query_or.append({"mobilenumber": data.mobilenumber.strip()})
        
    user_doc = await users_coll.find_one({"$or": query_or, "is_deleted": {"$ne": True}}) if query_or else None
    if not user_doc:
        raise HTTPException(status_code=404, detail="User with this email/mobile number not found.")
        
    reset_token = str(uuid.uuid4())
    redis_key = f"pwd_reset:{reset_token}"
    token_payload = {
        "user_id": user_doc["user_id"],
        "email": user_doc.get("email"),
        "mobilenumber": user_doc.get("mobilenumber")
    }
    # Store token in Redis for 15 minutes (900 seconds)
    await redis_client.set(redis_key, json.dumps(token_payload), ex=900)
    
    return {
        "message": "Password reset token generated successfully.",
        "reset_token": reset_token,
        "user_id": user_doc["user_id"],
        "email": user_doc.get("email"),
        "mobilenumber": user_doc.get("mobilenumber"),
        "expires_in_seconds": 900
    }

@router.post("/reset-password")
async def reset_password(data: ResetPasswordSchema):
    if not data.new_password:
        raise HTTPException(status_code=400, detail="New password is required.")
    
    users_coll = get_collection("users")
    user_id = data.user_id
    
    if data.reset_token:
        redis_key = f"pwd_reset:{data.reset_token}"
        stored_payload_json = await redis_client.get(redis_key)
        if not stored_payload_json:
            raise HTTPException(status_code=400, detail="Invalid or expired reset token.")
        
        token_data = json.loads(stored_payload_json)
        user_id = token_data.get("user_id") or user_id
        await redis_client.delete(redis_key)
        
    query_or = []
    if user_id:
        query_or.append({"user_id": user_id})
    if data.email:
        clean_email = data.email.strip().lower()
        query_or.append({"email": clean_email})
        query_or.append({"email": {"$regex": f"^{re.escape(clean_email)}$", "$options": "i"}})
    if data.mobilenumber:
        query_or.append({"mobilenumber": data.mobilenumber.strip()})
        
    if not query_or:
        raise HTTPException(status_code=400, detail="Reset token, user_id, email, or mobile number is required.")
        
    user_doc = await users_coll.find_one({"$or": query_or, "is_deleted": {"$ne": True}})
    if not user_doc:
        raise HTTPException(status_code=404, detail="User not found.")
        
    new_hash = ph.hash(data.new_password)
    await users_coll.update_one(
        {"_id": user_doc["_id"]},
        {"$set": {
            "password": new_hash,
            "has_custom_password": True,
            "updated_at": datetime.datetime.utcnow()
        }}
    )
    
    return {"message": "Password has been successfully updated. You can now login with your new password."}

@router.post("/change-password")
async def change_password(data: ChangePasswordSchema):
    if not data.old_password or not data.new_password:
        raise HTTPException(status_code=400, detail="Both old and new passwords are required.")
        
    users_coll = get_collection("users")
    query_or = []
    if data.user_id:
        query_or.append({"user_id": data.user_id})
    if data.email:
        clean_email = data.email.strip().lower()
        query_or.append({"email": clean_email})
        query_or.append({"email": {"$regex": f"^{re.escape(clean_email)}$", "$options": "i"}})
    if data.mobilenumber:
        query_or.append({"mobilenumber": data.mobilenumber.strip()})
        
    if not query_or:
        raise HTTPException(status_code=400, detail="User identifier (user_id, email, or mobile number) is required.")
        
    user_doc = await users_coll.find_one({"$or": query_or, "is_deleted": {"$ne": True}})
    if not user_doc:
        raise HTTPException(status_code=404, detail="User not found.")
        
    stored_pwd = user_doc.get("password")
    has_custom_pwd = user_doc.get("has_custom_password", False)
    
    if stored_pwd and has_custom_pwd:
        try:
            ph.verify(stored_pwd, data.old_password)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid current password.")
            
    new_hash = ph.hash(data.new_password)
    await users_coll.update_one(
        {"_id": user_doc["_id"]},
        {"$set": {
            "password": new_hash,
            "has_custom_password": True,
            "updated_at": datetime.datetime.utcnow()
        }}
    )
    
    return {"message": "Password changed successfully."}

