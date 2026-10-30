import datetime
import uuid
import httpx
import jwt
from fastapi import APIRouter, HTTPException, Depends, Query, Request, Response
from fastapi.responses import RedirectResponse, JSONResponse
import json
import re
from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional, List
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
from core.utils.email_helper import generate_secure_random_password, send_account_credentials_email

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
    version: Optional[str] = "1"

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

@router.get("/login-url")
@router.get("/signin-url")
@router.get("/signin/url")
async def get_login_url(
    response: Response,
    service: str = Query("HYPERLOCAL-INVENTORY"),
    version: Optional[str] = Query("1"),
    entity_name: Optional[str] = Query(None),
    entity_type: Optional[str] = Query(None),
    redirect_url: Optional[str] = Query(None),
    verify_url: Optional[str] = Query(None),
    flow_type: Optional[str] = Query("signin")
):
    # Determine unified verify and redirect URLs for signin
    effective_verify_url = SETTINGS.get_verify_url(verify_url)
    backend_redirect_url = SETTINGS.get_signin_redirect_url()
    frontend_target_url = redirect_url if is_valid_frontend_redirect_url(redirect_url) else None

    # Connects to Debugger Auth for signin
    constructed_url = f"{DAUTH_BASE_URL}/auth"
    payload = {
        "apikey": SETTINGS.DEB_APIKEY,
        "flow_type": "signin",
        "additional_infos": {
            "entity_name": entity_name,
            "entity_type": entity_type,
            "redirect_url": frontend_target_url,
            "service": service,
            "version": version,
            "flow_type": "signin"
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
        "entity_type": entity_type,
        "redirect_url": frontend_target_url,
        "verify_url": effective_verify_url,
        "flow_type": "signin"
    })
    response.set_cookie(key="oauth_state", value=state_val, max_age=900, samesite="lax")
    signin_url = res.get("signin_url") or res.get("url")
    return {
        "signin_url": signin_url,
        "signup_url": res.get("signup_url"),
        "url": signin_url,
        "verify_url": effective_verify_url,
        "redirect_url": backend_redirect_url
    }

@router.get("/signup-url")
@router.get("/signup/url")
async def get_signup_url(
    response: Response,
    service: str = Query("HYPERLOCAL-INVENTORY"),
    version: Optional[str] = Query("1"),
    entity_name: Optional[str] = Query(None),
    entity_type: Optional[str] = Query(None),
    redirect_url: Optional[str] = Query(None),
    verify_url: Optional[str] = Query(None)
):
    # Determine unified verify and redirect URLs for signup
    effective_verify_url = SETTINGS.get_verify_url(verify_url)
    backend_redirect_url = SETTINGS.get_signup_redirect_url()
    frontend_target_url = redirect_url if is_valid_frontend_redirect_url(redirect_url) else None

    # Connects to Debugger Auth specifically for signup
    constructed_url = f"{DAUTH_BASE_URL}/auth"
    payload = {
        "apikey": SETTINGS.DEB_APIKEY,
        "flow_type": "signup",
        "additional_infos": {
            "entity_name": entity_name,
            "entity_type": entity_type,
            "redirect_url": frontend_target_url,
            "service": service,
            "version": version,
            "flow_type": "signup"
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
        "entity_type": entity_type,
        "redirect_url": frontend_target_url,
        "verify_url": effective_verify_url,
        "flow_type": "signup"
    })
    response.set_cookie(key="oauth_state", value=state_val, max_age=900, samesite="lax")
    signup_url = res.get("signup_url") or res.get("signin_url") or res.get("url")
    return {
        "signup_url": signup_url,
        "signin_url": res.get("signin_url"),
        "url": signup_url,
        "verify_url": effective_verify_url,
        "redirect_url": backend_redirect_url
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
    
    email_sent = await send_account_credentials_email(
        email=clean_email,
        name=name,
        password=raw_password,
        login_url=f"{SETTINGS.FRONTEND_URL}/login"
    )
    
    return {
        "success": True,
        "message": "Account created successfully! Your login password has been sent to your email.",
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
async def signin_verify(request: Request):
    """
    Dedicated Sign-In Verification route with Sign-In specific validation:
    - Supports GET, POST, OPTIONS, HEAD.
    - If ping or healthcheck: returns 200 OK.
    - Verifies user MUST exist in DB. Rejects with 404 if not registered.
    - Validates password (Argon2) if provided. Rejects with 401 if invalid.
    """
    if request.method == "OPTIONS":
        return Response(status_code=200)

    body = await _extract_verify_payload(request)
    ic("signin/verify request received:", request.method, body)
    
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
    
    # Dev environment access check (enforced when ENVIRONMENT != 'production')
    if SETTINGS.ENVIRONMENT.lower() != "production":
        is_allowed, dev_err = SETTINGS.is_dev_allowed(email=email, password=password if auth_provider == "password" else None, mobilenumber=mobilenumber)
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
        
    user_doc = await users_coll.find_one({"$or": query_or})
    
    # Sign-in validation: Account MUST exist!
    if not user_doc:
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
async def signup_verify(request: Request):
    """
    Dedicated Sign-Up Verification route with Sign-Up specific validation:
    - Supports GET, POST, OPTIONS, HEAD.
    - If ping or healthcheck: returns 200 OK.
    - Verifies user MUST NOT exist in DB. Rejects with 409 if already registered.
    - Allows new registrations to proceed.
    """
    if request.method == "OPTIONS":
        return Response(status_code=200)

    body = await _extract_verify_payload(request)
    ic("signup/verify request received:", request.method, body)
    
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

    # Dev environment access check (enforced when ENVIRONMENT != 'production')
    if SETTINGS.ENVIRONMENT.lower() != "production":
        is_allowed, dev_err = SETTINGS.is_dev_allowed(email=email, mobilenumber=mobilenumber)
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
        
    user_doc = await users_coll.find_one({"$or": query_or})
    
    # Sign-up validation: Account MUST NOT exist!
    if user_doc:
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
    error: Optional[str] = Query(None),
    status_code: Optional[int] = Query(None),
    service: Optional[str] = Query(None),
    version: Optional[str] = Query(None)
):
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
        except Exception:
            pass
            
    if not service:
        service = "HYPERLOCAL"
    if not version:
        version = "1"
        
    # Connects to Debugger Auth to get loggedin user
    constructed_url = f"{DAUTH_BASE_URL}/auth/authenticated-user"
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(
            constructed_url,
            json={
                "token_id": token_id,
                "client_id": SETTINGS.DEB_APIKEY,
                "client_secret": SETTINGS.DEB_SECRETS
            }
        )
    
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
    user_query = {}
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
    if SETTINGS.ENVIRONMENT.lower() != "production":
        is_allowed, dev_err = SETTINGS.is_dev_allowed(email=email, mobilenumber=mobilenumber)
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

    # If Signin flow and user NOT present: reject and redirect to signup!
    if not is_signup_flow and not user_doc:
        from urllib.parse import quote
        base_redirect_url = redirect_url_param or f"{SETTINGS.FRONTEND_URL}/login"
        sep = "&" if "?" in base_redirect_url else "?"
        err_msg = "Account not found. Please sign up to create an account."
        return RedirectResponse(url=f"{base_redirect_url}{sep}error={quote(err_msg)}&status_code=404&flow=signup")

    # If Signup flow and user NOT present: create new account, generate password, email it!
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
        
        # Send generated credentials via email
        if email:
            await send_account_credentials_email(
                email=email,
                name=name,
                password=generated_password,
                login_url=f"{SETTINGS.FRONTEND_URL}/login"
            )
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
        if (srv_upper == "HYPERLOCAL" or srv_upper == "HYPERLOCAL-INVENTORY") and ent_lower == "website":
            base_redirect_url = SETTINGS.HYPERLOCAL_WEBSITE_URL
        elif ent_lower == "app":
            base_redirect_url = SETTINGS.APP_DEEP_LINK
        else:
            base_redirect_url = f"{SETTINGS.FRONTEND_URL}/auth/callback"

    redirect_url = append_query_param(base_redirect_url, "token_id", login_id)
    if is_signup_flow:
        redirect_url = append_query_param(redirect_url, "flow", "signup")
    else:
        redirect_url = append_query_param(redirect_url, "flow", "signin")
    return RedirectResponse(url=redirect_url)

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
        
    user_doc = await users_coll.find_one({"$or": query_or}) if query_or else None
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

@router.delete("/users/{user_id}")
async def delete_user(user_id: str):
    users_coll = get_collection("users")
    res = await users_coll.delete_one({"user_id": user_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": "User deleted successfully"}


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
        
    user_doc = await users_coll.find_one({"$or": query_or}) if query_or else None
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
        
    user_doc = await users_coll.find_one({"$or": query_or})
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
        
    user_doc = await users_coll.find_one({"$or": query_or})
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

